//! SFTP subsystem protocol decode → per-operation file-transfer audit (Design
//! §12.1, Part B; FR-AUD-1).
//!
//! The SFTP wire protocol (v3, what OpenSSH speaks) is a stream of
//! `[uint32 length][byte type][payload]` packets: requests on the **input**
//! (client→node) direction, responses on the **output** (node→client). This
//! decoder reassembles packets across SSH chunk boundaries and correlates them to
//! emit one [`FileTransferAudit`] per operation — path, direction, size, and a
//! **streaming SHA-256 of the transferred content** (the content itself is never
//! captured; metadata only, §12). Uploads are `WRITE`s on a handle; downloads are
//! `READ`→`DATA` pairs; `CLOSE` flushes the per-handle audit. `RENAME`/`REMOVE`/
//! `MKDIR`/`RMDIR`/`SETSTAT` emit a metadata audit immediately.
//!
//! Decoding is **best-effort**: a malformed/unknown packet stops decode on that
//! channel (the recording is not failed — only the crypto/spool path fails a
//! session, §7.1). Bounded buffers guard against a hostile client.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::pb::FileTransferAudit;
use crate::ssh::bridge::TapDirection;
use crate::ssh::recorder::chain;

// SFTP packet types (subset we correlate; RFC draft-ietf-secsh-filexfer-02).
const FXP_OPEN: u8 = 3;
const FXP_CLOSE: u8 = 4;
const FXP_READ: u8 = 5;
const FXP_WRITE: u8 = 6;
const FXP_SETSTAT: u8 = 9;
const FXP_OPENDIR: u8 = 11;
const FXP_REMOVE: u8 = 13;
const FXP_MKDIR: u8 = 14;
const FXP_RMDIR: u8 = 15;
const FXP_RENAME: u8 = 18;
const FXP_HANDLE: u8 = 102;
const FXP_DATA: u8 = 103;

/// The largest single SFTP packet we will buffer (guards against a hostile length
/// prefix); real SFTP packets are far smaller than this.
const MAX_PACKET: usize = 512 * 1024;
/// Bound on tracked handles / in-flight correlations (hostile-client guard).
const MAX_TRACKED: usize = 4096;

/// A per-handle transfer accumulator (streaming size + SHA-256, no content).
struct HandleState {
    path: Vec<u8>,
    is_dir: bool,
    write_size: u64,
    read_size: u64,
    sha_write: Sha256,
    sha_read: Sha256,
}

/// Stateful SFTP decoder for one bridged channel. The reassembly buffers
/// transiently hold file-transfer plaintext (WRITE/DATA payloads, which are
/// hashed but never captured), so they are scrubbed on drop (Tier-0, §15).
pub struct SftpDecoder {
    in_buf: Zeroizing<Vec<u8>>,
    out_buf: Zeroizing<Vec<u8>>,
    handles: HashMap<Vec<u8>, HandleState>,
    /// OPEN/OPENDIR request-id → (path, is_dir), awaiting the HANDLE reply.
    pending_open: HashMap<u32, (Vec<u8>, bool)>,
    /// READ request-id → handle, awaiting the DATA reply (download correlation).
    pending_read: HashMap<u32, Vec<u8>>,
    broken: bool,
}

impl Default for SftpDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpDecoder {
    /// A fresh decoder.
    pub fn new() -> Self {
        Self {
            in_buf: Zeroizing::new(Vec::new()),
            out_buf: Zeroizing::new(Vec::new()),
            handles: HashMap::new(),
            pending_open: HashMap::new(),
            pending_read: HashMap::new(),
            broken: false,
        }
    }

    /// Feed a plaintext chunk in `dir`; returns any audits completed by it.
    pub fn feed(&mut self, dir: TapDirection, data: &[u8]) -> Vec<FileTransferAudit> {
        if self.broken {
            return Vec::new();
        }
        let mut audits = Vec::new();
        // Reassemble into the per-direction buffer, then drain whole packets.
        let buf = match dir {
            TapDirection::Input => &mut self.in_buf,
            TapDirection::Output => &mut self.out_buf,
        };
        buf.extend_from_slice(data);
        loop {
            let buf = match dir {
                TapDirection::Input => &self.in_buf,
                TapDirection::Output => &self.out_buf,
            };
            if buf.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if len == 0 || len > MAX_PACKET {
                self.broken = true; // implausible framing: stop decoding this channel
                break;
            }
            if buf.len() < 4 + len {
                break; // packet not fully arrived yet
            }
            // Extract the packet body (type + payload) and advance the buffer.
            let packet: Vec<u8> = {
                let buf = match dir {
                    TapDirection::Input => &mut self.in_buf,
                    TapDirection::Output => &mut self.out_buf,
                };
                let p = buf[4..4 + len].to_vec();
                buf.drain(..4 + len);
                p
            };
            let ptype = packet[0];
            let payload = &packet[1..];
            match dir {
                TapDirection::Input => self.on_request(ptype, payload, &mut audits),
                TapDirection::Output => self.on_response(ptype, payload),
            }
            if self.tracking_overflow() {
                self.broken = true;
                break;
            }
        }
        audits
    }

    /// Flush any still-open handles at channel close (a transfer without a clean
    /// CLOSE still yields its audit).
    pub fn finish(&mut self) -> Vec<FileTransferAudit> {
        let mut audits = Vec::new();
        let handles = std::mem::take(&mut self.handles);
        for (_h, st) in handles {
            emit_handle_audit(st, &mut audits);
        }
        audits
    }

    fn tracking_overflow(&self) -> bool {
        self.handles.len() > MAX_TRACKED
            || self.pending_open.len() > MAX_TRACKED
            || self.pending_read.len() > MAX_TRACKED
    }

    fn on_request(&mut self, ptype: u8, payload: &[u8], audits: &mut Vec<FileTransferAudit>) {
        let mut c = Reader::new(payload);
        match ptype {
            FXP_OPEN | FXP_OPENDIR => {
                let is_dir = ptype == FXP_OPENDIR;
                if let (Some(id), Some(path)) = (c.u32(), c.string()) {
                    self.pending_open.insert(id, (path.to_vec(), is_dir));
                }
            }
            FXP_WRITE => {
                // id, string handle, uint64 offset, string data.
                if let (Some(_id), Some(handle), Some(_off), Some(chunk)) =
                    (c.u32(), c.string(), c.u64(), c.string())
                {
                    if let Some(st) = self.handles.get_mut(handle) {
                        st.write_size += chunk.len() as u64;
                        st.sha_write.update(chunk);
                    }
                }
            }
            FXP_READ => {
                // id, string handle, uint64 offset, uint32 len → await DATA.
                if let (Some(id), Some(handle)) = (c.u32(), c.string()) {
                    self.pending_read.insert(id, handle.to_vec());
                }
            }
            FXP_CLOSE => {
                if let (Some(_id), Some(handle)) = (c.u32(), c.string()) {
                    if let Some(st) = self.handles.remove(handle) {
                        emit_handle_audit(st, audits);
                    }
                }
            }
            FXP_REMOVE => self.metadata(&mut c, "remove", audits),
            FXP_MKDIR => self.metadata(&mut c, "mkdir", audits),
            FXP_RMDIR => self.metadata(&mut c, "rmdir", audits),
            FXP_SETSTAT => self.metadata(&mut c, "setstat", audits),
            FXP_RENAME => {
                // id, string oldpath, string newpath.
                if let (Some(_id), Some(old), Some(new)) = (c.u32(), c.string(), c.string()) {
                    let path = format!(
                        "{} -> {}",
                        String::from_utf8_lossy(old),
                        String::from_utf8_lossy(new)
                    );
                    audits.push(metadata_audit("rename", path.into_bytes()));
                }
            }
            _ => {}
        }
    }

    fn metadata(&mut self, c: &mut Reader<'_>, op: &str, audits: &mut Vec<FileTransferAudit>) {
        if let (Some(_id), Some(path)) = (c.u32(), c.string()) {
            audits.push(metadata_audit(op, path.to_vec()));
        }
    }

    fn on_response(&mut self, ptype: u8, payload: &[u8]) {
        let mut c = Reader::new(payload);
        match ptype {
            FXP_HANDLE => {
                // id, string handle → bind the handle to the pending OPEN/OPENDIR.
                if let (Some(id), Some(handle)) = (c.u32(), c.string()) {
                    if let Some((path, is_dir)) = self.pending_open.remove(&id) {
                        self.handles.insert(
                            handle.to_vec(),
                            HandleState {
                                path,
                                is_dir,
                                write_size: 0,
                                read_size: 0,
                                sha_write: Sha256::new(),
                                sha_read: Sha256::new(),
                            },
                        );
                    }
                }
            }
            FXP_DATA => {
                // id, string data → download bytes for the correlated READ handle.
                if let (Some(id), Some(chunk)) = (c.u32(), c.string()) {
                    if let Some(handle) = self.pending_read.remove(&id) {
                        if let Some(st) = self.handles.get_mut(&handle) {
                            st.read_size += chunk.len() as u64;
                            st.sha_read.update(chunk);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Emit the audit(s) for a handle being closed (upload and/or download; else an
/// open record for a handle that transferred nothing, e.g. a stat/opendir).
fn emit_handle_audit(st: HandleState, audits: &mut Vec<FileTransferAudit>) {
    let mut emitted = false;
    if st.write_size > 0 {
        audits.push(FileTransferAudit {
            operation: "write".to_string(),
            path: String::from_utf8_lossy(&st.path).into_owned(),
            direction: "upload".to_string(),
            size: st.write_size as i64,
            sha256: chain::format_sha256(&st.sha_write.finalize()),
        });
        emitted = true;
    }
    if st.read_size > 0 {
        audits.push(FileTransferAudit {
            operation: "read".to_string(),
            path: String::from_utf8_lossy(&st.path).into_owned(),
            direction: "download".to_string(),
            size: st.read_size as i64,
            sha256: chain::format_sha256(&st.sha_read.finalize()),
        });
        emitted = true;
    }
    if !emitted {
        audits.push(FileTransferAudit {
            operation: if st.is_dir { "opendir" } else { "open" }.to_string(),
            path: String::from_utf8_lossy(&st.path).into_owned(),
            direction: String::new(),
            size: 0,
            sha256: chain::sha256_hex(&[]),
        });
    }
}

fn metadata_audit(op: &str, path: Vec<u8>) -> FileTransferAudit {
    FileTransferAudit {
        operation: op.to_string(),
        path: String::from_utf8_lossy(&path).into_owned(),
        direction: String::new(),
        size: 0,
        sha256: chain::sha256_hex(&[]),
    }
}

/// The canonical byte serialization of a file-transfer audit record for the
/// hash-chain (order-sensitive, NUL-delimited).
pub fn canonical(a: &FileTransferAudit) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(a.operation.as_bytes());
    v.push(0);
    v.extend_from_slice(a.path.as_bytes());
    v.push(0);
    v.extend_from_slice(a.direction.as_bytes());
    v.push(0);
    v.extend_from_slice(&a.size.to_be_bytes());
    v.push(0);
    v.extend_from_slice(a.sha256.as_bytes());
    v
}

/// A fail-closed big-endian reader for SFTP payload fields.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
    /// An SFTP `string`: uint32 length + that many bytes.
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an SFTP packet: [u32 len][type][payload].
    fn packet(ptype: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&((payload.len() as u32) + 1).to_be_bytes());
        p.push(ptype);
        p.extend_from_slice(payload);
        p
    }
    fn sftp_string(s: &[u8]) -> Vec<u8> {
        let mut v = (s.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(s);
        v
    }

    #[test]
    fn decodes_upload_then_download_audit() {
        let mut d = SftpDecoder::new();
        let content = b"the file contents";

        // Upload: OPEN "up.txt" (id 1) → HANDLE "h1" → WRITE content → CLOSE.
        let mut open = 1u32.to_be_bytes().to_vec();
        open.extend_from_slice(&sftp_string(b"up.txt"));
        open.extend_from_slice(&0u32.to_be_bytes()); // pflags (ATTRS omitted; ignored)
        assert!(d
            .feed(TapDirection::Input, &packet(FXP_OPEN, &open))
            .is_empty());

        let mut handle = 1u32.to_be_bytes().to_vec();
        handle.extend_from_slice(&sftp_string(b"h1"));
        assert!(d
            .feed(TapDirection::Output, &packet(FXP_HANDLE, &handle))
            .is_empty());

        let mut write = 2u32.to_be_bytes().to_vec();
        write.extend_from_slice(&sftp_string(b"h1"));
        write.extend_from_slice(&0u64.to_be_bytes());
        write.extend_from_slice(&sftp_string(content));
        assert!(d
            .feed(TapDirection::Input, &packet(FXP_WRITE, &write))
            .is_empty());

        let mut close = 3u32.to_be_bytes().to_vec();
        close.extend_from_slice(&sftp_string(b"h1"));
        let audits = d.feed(TapDirection::Input, &packet(FXP_CLOSE, &close));
        assert_eq!(audits.len(), 1);
        let a = &audits[0];
        assert_eq!(a.direction, "upload");
        assert_eq!(a.size, content.len() as i64);
        assert_eq!(a.sha256, chain::sha256_hex(content));
        assert_eq!(a.path, "up.txt");

        // Download: OPEN "down.txt" (id 4) → HANDLE "h2" → READ → DATA → CLOSE.
        let mut open = 4u32.to_be_bytes().to_vec();
        open.extend_from_slice(&sftp_string(b"down.txt"));
        open.extend_from_slice(&0u32.to_be_bytes());
        d.feed(TapDirection::Input, &packet(FXP_OPEN, &open));
        let mut handle = 4u32.to_be_bytes().to_vec();
        handle.extend_from_slice(&sftp_string(b"h2"));
        d.feed(TapDirection::Output, &packet(FXP_HANDLE, &handle));

        let mut read = 5u32.to_be_bytes().to_vec();
        read.extend_from_slice(&sftp_string(b"h2"));
        read.extend_from_slice(&0u64.to_be_bytes());
        read.extend_from_slice(&4096u32.to_be_bytes());
        d.feed(TapDirection::Input, &packet(FXP_READ, &read));

        let mut data = 5u32.to_be_bytes().to_vec();
        data.extend_from_slice(&sftp_string(content));
        d.feed(TapDirection::Output, &packet(FXP_DATA, &data));

        let mut close = 6u32.to_be_bytes().to_vec();
        close.extend_from_slice(&sftp_string(b"h2"));
        let audits = d.feed(TapDirection::Input, &packet(FXP_CLOSE, &close));
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].direction, "download");
        assert_eq!(audits[0].size, content.len() as i64);
        assert_eq!(audits[0].sha256, chain::sha256_hex(content));
        assert_eq!(audits[0].path, "down.txt");
    }

    #[test]
    fn reassembles_packets_split_across_chunks() {
        let mut d = SftpDecoder::new();
        let mut open = 1u32.to_be_bytes().to_vec();
        open.extend_from_slice(&sftp_string(b"x"));
        open.extend_from_slice(&0u32.to_be_bytes());
        let pkt = packet(FXP_OPEN, &open);
        // Split the packet mid-way across two feeds.
        d.feed(TapDirection::Input, &pkt[..3]);
        d.feed(TapDirection::Input, &pkt[3..]);
        let mut handle = 1u32.to_be_bytes().to_vec();
        handle.extend_from_slice(&sftp_string(b"h"));
        d.feed(TapDirection::Output, &packet(FXP_HANDLE, &handle));
        // The handle was bound despite the split → a CLOSE now yields an audit.
        let mut close = 2u32.to_be_bytes().to_vec();
        close.extend_from_slice(&sftp_string(b"h"));
        let audits = d.feed(TapDirection::Input, &packet(FXP_CLOSE, &close));
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].path, "x");
    }

    #[test]
    fn metadata_ops_emit_immediately() {
        let mut d = SftpDecoder::new();
        let mut rm = 1u32.to_be_bytes().to_vec();
        rm.extend_from_slice(&sftp_string(b"/tmp/gone"));
        let audits = d.feed(TapDirection::Input, &packet(FXP_REMOVE, &rm));
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].operation, "remove");
        assert_eq!(audits[0].path, "/tmp/gone");
    }
}
