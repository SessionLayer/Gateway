//! Legacy SCP-over-exec protocol decode → file-transfer audit (Design §12.1,
//! Part B; FR-AUD-1).
//!
//! `scp -O` (and old clients) run the transfer as an exec of the remote `scp`
//! binary in source/sink mode: control lines `C<mode> <size> <name>\n` introduce
//! a file, followed by exactly `size` raw content bytes and a trailing `\0`;
//! `D`/`E` bracket directories, `T` carries timestamps. The file protocol flows on
//! **one** direction — the client for an upload (`scp -t`), the node for a
//! download (`scp -f`) — with `\0` acks on the other (ignored). This decoder
//! streams the content SHA-256 + size (never the content) and emits one
//! [`FileTransferAudit`] per file. Best-effort: unparseable framing stops decode
//! (the recording is not failed).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::pb::FileTransferAudit;
use crate::ssh::bridge::TapDirection;
use crate::ssh::recorder::chain;

/// Bound on an accumulated control line (hostile / non-scp stream guard).
const MAX_CONTROL_LINE: usize = 8 * 1024;

enum State {
    /// Accumulating a control line until `\n`.
    Control,
    /// Streaming `remaining` content bytes of the current file.
    Data {
        name: Vec<u8>,
        size: u64,
        remaining: u64,
        sha: Sha256,
    },
    /// Consuming the single `\0` that terminates a file's data.
    Trailer {
        name: Vec<u8>,
        size: u64,
        sha: Sha256,
    },
}

/// Stateful legacy-SCP decoder for one bridged exec channel.
pub struct ScpDecoder {
    /// The direction that carries the file protocol (input for upload).
    protocol_dir: TapDirection,
    upload: bool,
    /// The scp target argument (from `scp -t <target>` / `-f <target>`), prepended
    /// to each file's C-message name so the audit path is the destination, not the
    /// bare basename (#20).
    base: Vec<u8>,
    dirs: Vec<Vec<u8>>,
    line: Zeroizing<Vec<u8>>,
    state: State,
    broken: bool,
}

impl ScpDecoder {
    /// A decoder for an `scp -t` (`upload = true`) or `scp -f` transfer against the
    /// given `target` path argument.
    pub fn new(upload: bool, target: Vec<u8>) -> Self {
        Self {
            protocol_dir: if upload {
                TapDirection::Input
            } else {
                TapDirection::Output
            },
            upload,
            base: target,
            dirs: Vec::new(),
            line: Zeroizing::new(Vec::new()),
            state: State::Control,
            broken: false,
        }
    }

    /// Feed a plaintext chunk; returns any file-transfer audits it completes. Only
    /// the protocol-carrying direction is parsed (the ack direction is ignored).
    pub fn feed(&mut self, dir: TapDirection, data: &[u8]) -> Vec<FileTransferAudit> {
        let mut audits = Vec::new();
        if self.broken || dir != self.protocol_dir {
            return audits;
        }
        let mut i = 0;
        while i < data.len() && !self.broken {
            match &mut self.state {
                State::Control => {
                    // Accumulate up to and including the next '\n'.
                    let b = data[i];
                    i += 1;
                    if b == b'\n' {
                        self.dispatch_control(&mut audits);
                        self.line.clear();
                    } else {
                        self.line.push(b);
                        if self.line.len() > MAX_CONTROL_LINE {
                            self.broken = true;
                        }
                    }
                }
                State::Data { remaining, sha, .. } => {
                    let take = (*remaining).min((data.len() - i) as u64) as usize;
                    sha.update(&data[i..i + take]);
                    *remaining -= take as u64;
                    i += take;
                    if *remaining == 0 {
                        // Move to the trailer (\0) state.
                        if let State::Data {
                            name, size, sha, ..
                        } = std::mem::replace(&mut self.state, State::Control)
                        {
                            self.state = State::Trailer { name, size, sha };
                        }
                    }
                }
                State::Trailer { .. } => {
                    // Consume exactly the one terminating byte, then emit the audit.
                    i += 1;
                    if let State::Trailer { name, size, sha } =
                        std::mem::replace(&mut self.state, State::Control)
                    {
                        audits.push(self.file_audit(&name, size, sha));
                    }
                }
            }
        }
        audits
    }

    /// Flush a file whose data ended without a clean trailer (truncated transfer).
    pub fn finish(&mut self) -> Vec<FileTransferAudit> {
        match std::mem::replace(&mut self.state, State::Control) {
            State::Data {
                name, size, sha, ..
            }
            | State::Trailer { name, size, sha } => {
                vec![self.file_audit(&name, size, sha)]
            }
            State::Control => Vec::new(),
        }
    }

    fn dispatch_control(&mut self, audits: &mut Vec<FileTransferAudit>) {
        let line = std::mem::take(&mut self.line);
        match line.first().copied() {
            Some(b'C') => {
                if let Some((size, name)) = parse_file_header(&line[1..]) {
                    let mut path = self.dir_prefix();
                    path.extend_from_slice(&name);
                    if size == 0 {
                        // A zero-length file still has a trailing \0 before the next
                        // control line; capture it via the Trailer state.
                        self.state = State::Trailer {
                            name: path,
                            size: 0,
                            sha: Sha256::new(),
                        };
                    } else {
                        self.state = State::Data {
                            name: path,
                            size,
                            remaining: size,
                            sha: Sha256::new(),
                        };
                    }
                } else {
                    self.broken = true;
                }
            }
            Some(b'D') => {
                if let Some((_size, name)) = parse_file_header(&line[1..]) {
                    self.dirs.push(name);
                }
            }
            Some(b'E') => {
                self.dirs.pop();
            }
            // Timestamps: advisory, ignored. A leading \0 (an ack that leaked onto
            // the protocol direction) is tolerated. `\x01` (warning) / `\x02`
            // (fatal) are in-band scp messages — consume the line, do NOT break the
            // decoder (#15).
            Some(b'T') | Some(0) | Some(1) | Some(2) => {}
            // Anything else on the protocol direction is not scp framing.
            Some(_) => self.broken = true,
            None => {}
        }
        let _ = audits; // audits only produced from the Trailer state
    }

    /// The destination path prefix: the scp `target` argument, then any nested
    /// directory (`D`/`E`) stack.
    fn dir_prefix(&self) -> Vec<u8> {
        let mut p = Vec::new();
        if !self.base.is_empty() {
            p.extend_from_slice(&self.base);
            if p.last() != Some(&b'/') {
                p.push(b'/');
            }
        }
        for d in &self.dirs {
            p.extend_from_slice(d);
            p.push(b'/');
        }
        p
    }

    fn file_audit(&self, name: &[u8], size: u64, sha: Sha256) -> FileTransferAudit {
        FileTransferAudit {
            operation: if self.upload { "put" } else { "get" }.to_string(),
            path: String::from_utf8_lossy(name).into_owned(),
            direction: if self.upload { "upload" } else { "download" }.to_string(),
            // Clamp a hostile / oversized size to a non-negative i64 (#21).
            size: i64::try_from(size).unwrap_or(i64::MAX),
            sha256: chain::format_sha256(&sha.finalize()),
        }
    }
}

/// Classify a bridged exec command as a legacy scp source/sink transfer.
/// Returns `(upload, path)` where `upload` is `true` for `scp -t` (client→node),
/// `false` for `scp -f` (node→client); `None` when the command is not an
/// scp source/sink invocation (it is then recorded as a normal terminal exec).
pub fn parse_scp_command(cmd: &[u8]) -> Option<(bool, Vec<u8>)> {
    let s = std::str::from_utf8(cmd).ok()?;
    let mut tokens = s.split_whitespace();
    let first = tokens.next()?;
    let base = first.rsplit(['/', '\\']).next().unwrap_or(first);
    if base != "scp" {
        return None;
    }
    let mut upload: Option<bool> = None;
    let mut path: Option<&str> = None;
    let mut end_of_flags = false;
    for t in tokens {
        if !end_of_flags && t == "--" {
            end_of_flags = true;
        } else if !end_of_flags && t.starts_with('-') && t.len() > 1 {
            if t.contains('t') {
                upload = Some(true);
            }
            if t.contains('f') {
                upload = Some(false);
            }
        } else {
            path = Some(t); // the target path (last non-flag token)
        }
    }
    // A source/sink invocation must carry -t or -f; anything else is a plain exec.
    let upload = upload?;
    Some((upload, path.unwrap_or("").as_bytes().to_vec()))
}

/// Parse the `<mode> <size> <name>` tail of a `C`/`D` control line.
fn parse_file_header(rest: &[u8]) -> Option<(u64, Vec<u8>)> {
    // mode SP size SP name (name runs to end of line and may contain spaces).
    let s = std::str::from_utf8(rest).ok()?;
    let mut parts = s.splitn(3, ' ');
    let _mode = parts.next()?;
    let size = parts.next()?.parse::<u64>().ok()?;
    let name = parts.next()?;
    Some((size, name.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_scp_upload() {
        let mut d = ScpDecoder::new(true, Vec::new());
        let content = b"hello scp world";
        let mut stream = Vec::new();
        stream.extend_from_slice(format!("C0644 {} greeting.txt\n", content.len()).as_bytes());
        stream.extend_from_slice(content);
        stream.push(0); // trailing NUL

        let audits = d.feed(TapDirection::Input, &stream);
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].operation, "put");
        assert_eq!(audits[0].direction, "upload");
        assert_eq!(audits[0].path, "greeting.txt");
        assert_eq!(audits[0].size, content.len() as i64);
        assert_eq!(audits[0].sha256, chain::sha256_hex(content));
    }

    #[test]
    fn ack_direction_is_ignored() {
        let mut d = ScpDecoder::new(true, Vec::new());
        // Acks arrive on Output for an upload; they must not be parsed.
        assert!(d.feed(TapDirection::Output, &[0, 0, 0]).is_empty());
    }

    #[test]
    fn decodes_download_on_output_direction() {
        let mut d = ScpDecoder::new(false, Vec::new());
        let content = b"downloaded";
        let mut stream = format!("C0600 {} f.bin\n", content.len()).into_bytes();
        stream.extend_from_slice(content);
        stream.push(0);
        let audits = d.feed(TapDirection::Output, &stream);
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].direction, "download");
        assert_eq!(audits[0].operation, "get");
        assert_eq!(audits[0].sha256, chain::sha256_hex(content));
    }

    #[test]
    fn classifies_scp_source_sink_commands() {
        assert_eq!(
            parse_scp_command(b"scp -t /tmp/dest"),
            Some((true, b"/tmp/dest".to_vec()))
        );
        assert_eq!(
            parse_scp_command(b"scp -f /etc/hostname"),
            Some((false, b"/etc/hostname".to_vec()))
        );
        assert_eq!(
            parse_scp_command(b"/usr/bin/scp -v -r -t -- /tmp/d"),
            Some((true, b"/tmp/d".to_vec()))
        );
        // Not a source/sink transfer (no -t/-f) → recorded as a normal exec.
        assert_eq!(parse_scp_command(b"scp --version"), None);
        assert_eq!(parse_scp_command(b"ls -la"), None);
    }

    #[test]
    fn reassembles_content_split_across_chunks() {
        let mut d = ScpDecoder::new(true, Vec::new());
        let content = b"splitcontent";
        let mut header = format!("C0644 {} s.txt\n", content.len()).into_bytes();
        // Feed header, then content in two pieces, then the trailing NUL.
        assert!(d.feed(TapDirection::Input, &header).is_empty());
        header.clear();
        assert!(d.feed(TapDirection::Input, &content[..5]).is_empty());
        assert!(d.feed(TapDirection::Input, &content[5..]).is_empty());
        let audits = d.feed(TapDirection::Input, &[0]);
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].sha256, chain::sha256_hex(content));
    }

    #[test]
    fn audit_path_is_target_prefixed_and_messages_are_tolerated() {
        // Target dir prefixes the C-message basename (#20); an in-band \x01 warning
        // line does not break decoding (#15).
        let mut d = ScpDecoder::new(true, b"/srv/data".to_vec());
        let content = b"x";
        let mut stream = Vec::new();
        stream.extend_from_slice(b"\x01scp: warning: something\n"); // in-band warning
        stream.extend_from_slice(format!("C0644 {} f.txt\n", content.len()).as_bytes());
        stream.extend_from_slice(content);
        stream.push(0);
        let audits = d.feed(TapDirection::Input, &stream);
        assert_eq!(audits.len(), 1, "warning line must not break decoding");
        assert_eq!(audits[0].path, "/srv/data/f.txt");
    }
}
