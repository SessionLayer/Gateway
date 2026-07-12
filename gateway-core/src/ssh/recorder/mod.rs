//! The real session recorder (Session Nine, Design §12/§12A/§15; FR-AUD-1/2/3/9).
//!
//! Replaces `NullRecorder` behind the S8 tap seam. Per SSH session (1:1) it:
//!
//! 1. captures every bridged channel — terminal channels as **asciicast v2**
//!    (output + keystrokes + resize), SFTP/SCP channels as protocol-decoded
//!    **file-transfer audit** ([`asciicast`], [`sftp`], [`scp`]);
//! 2. **encrypts** the asciicast stream on the hot path under a per-recording
//!    AES-256-GCM data key sealed to the **customer** public key ([`seal`]), so no
//!    platform key can read it; only ciphertext is ever spooled;
//! 3. **hash-chains** every record for tamper-evidence ([`chain`]);
//! 4. **uploads** the ciphertext object straight to the WORM store via the
//!    CP-issued presigned PUT ([`upload`]) — bytes never traverse the CP — and
//!    commits the hash-chain head + digest + audit via `FinalizeRecording`.
//!
//! Recording is mandatory: in strict mode a setup failure refuses the session
//! before bytes flow, and a mid-session encrypt/spool failure tears the whole
//! connection down (fail closed, §7.1). The customer key is mandatory (keystroke
//! capture is always on): no key ⇒ the session is refused.

pub mod asciicast;
pub mod chain;
pub mod scp;
pub mod seal;
pub mod sftp;
pub mod upload;

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io::{self, Read, Seek, Write};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use russh::server::Handle;
use russh::ChannelId;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::config::RecorderConfig;
use crate::cpauth::CpAuthClient;
use crate::pb::{
    BeginRecordingRequest, FileTransferAudit, FinalizeRecordingRequest, KeySealAlgorithm,
    RecordingContext, RecordingStatus,
};
use crate::ssh::bridge::{
    RecChannelKind, RecorderError, RecorderFactory, RecorderTap, RecordingParams, SessionRecorder,
    TapDirection,
};
use crate::ssh::outcome::RECORDING_UNAVAILABLE;

use asciicast::{EventCode, Utf8Chunker};
use chain::HashChain;
use scp::ScpDecoder;
use seal::RecordingCipher;
use sftp::SftpDecoder;
use upload::HttpUploader;

/// How a bridged channel's plaintext is being captured.
enum ChannelRec {
    Terminal { out: Utf8Chunker, inp: Utf8Chunker },
    Sftp(SftpDecoder),
    Scp(ScpDecoder),
}

/// The synchronous capture core (all state behind the recorder's mutex). Generic
/// over the channel key so it is unit-testable without a real [`ChannelId`].
struct Capture<K: Eq + std::hash::Hash + Copy> {
    started: Instant,
    chain: HashChain,
    sealer: RecordingCipher,
    spool: CipherSpool,
    frame_index: u64,
    frame_size: usize,
    /// Plaintext (asciicast bytes) staged before the next frame is sealed. Held in
    /// a scrub-on-drop buffer so it never lingers in freed heap (Tier-0, §15); the
    /// data-key cipher schedule is likewise zeroized (aes-gcm `zeroize`). Transient
    /// per-event JSON copies are a documented coredump/swap-only residual (S18).
    pending_pt: Zeroizing<Vec<u8>>,
    channels: HashMap<K, ChannelRec>,
    sftp_audit: Vec<FileTransferAudit>,
    /// The first capture failure (operator reason). Set ⇒ capture stops.
    failed: Option<String>,
    finalized: bool,
}

/// The result of draining + sealing a recording at finalize.
struct FinalizedObject {
    object: io::Result<Vec<u8>>,
    capture_failed: bool,
    chain_head: String,
    content_digest: String,
    byte_len: i64,
    audits: Vec<FileTransferAudit>,
}

impl<K: Eq + std::hash::Hash + Copy> Capture<K> {
    /// Build the capture core: write the (cleartext) seal header + the asciicast v2
    /// header to the ciphertext spool. Fails closed on a spool error.
    fn new(sealer: RecordingCipher, config: &RecorderConfig) -> io::Result<Self> {
        let mut spool = CipherSpool::new(
            config.spool_dir.clone(),
            config.spool_memory_threshold_bytes,
        );
        spool.write_all(sealer.header())?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut cap = Self {
            started: Instant::now(),
            chain: HashChain::new(),
            sealer,
            spool,
            frame_index: 0,
            frame_size: config.frame_plaintext_bytes.max(1),
            pending_pt: Zeroizing::new(Vec::new()),
            channels: HashMap::new(),
            sftp_audit: Vec::new(),
            failed: None,
            finalized: false,
        };
        cap.push_asciicast(asciicast::header_line(80, 24, ts))
            .map_err(io::Error::other)?;
        Ok(cap)
    }

    fn elapsed(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    fn open_channel(&mut self, channel: K, kind: RecChannelKind) -> Result<(), String> {
        match kind {
            RecChannelKind::Terminal { command } => {
                self.channels.insert(
                    channel,
                    ChannelRec::Terminal {
                        out: Utf8Chunker::default(),
                        inp: Utf8Chunker::default(),
                    },
                );
                if let Some(cmd) = command {
                    // A non-PTY exec: record the command line as an input event.
                    let text = String::from_utf8_lossy(&cmd).into_owned();
                    let line = asciicast::event_line(self.elapsed(), EventCode::Input, &text);
                    self.push_asciicast(line)?;
                }
            }
            RecChannelKind::Sftp => {
                self.channels
                    .insert(channel, ChannelRec::Sftp(SftpDecoder::new()));
            }
            RecChannelKind::Scp { upload, .. } => {
                self.channels
                    .insert(channel, ChannelRec::Scp(ScpDecoder::new(upload)));
            }
        }
        Ok(())
    }

    fn tap(&mut self, channel: K, direction: TapDirection, data: &[u8]) -> Result<(), String> {
        let elapsed = self.elapsed();
        // Produce records under a scoped channel borrow, then fold them in.
        let produced = match self.channels.get_mut(&channel) {
            Some(ChannelRec::Terminal { out, inp }) => {
                let (chunker, code) = match direction {
                    TapDirection::Output => (out, EventCode::Output),
                    TapDirection::Input => (inp, EventCode::Input),
                };
                let text = chunker.push(data);
                if text.is_empty() {
                    Produced::Lines(Vec::new())
                } else {
                    Produced::Lines(vec![asciicast::event_line(elapsed, code, &text)])
                }
            }
            Some(ChannelRec::Sftp(d)) => Produced::Audits(d.feed(direction, data)),
            Some(ChannelRec::Scp(d)) => Produced::Audits(d.feed(direction, data)),
            None => Produced::Lines(Vec::new()),
        };
        match produced {
            Produced::Lines(lines) => {
                for l in lines {
                    self.push_asciicast(l)?;
                }
            }
            Produced::Audits(audits) => {
                for a in audits {
                    self.push_audit(a);
                }
            }
        }
        Ok(())
    }

    fn resize(&mut self, channel: K, cols: u16, rows: u16) -> Result<(), String> {
        if matches!(
            self.channels.get(&channel),
            Some(ChannelRec::Terminal { .. })
        ) {
            let data = format!("{cols}x{rows}");
            let line = asciicast::event_line(self.elapsed(), EventCode::Resize, &data);
            self.push_asciicast(line)?;
        }
        Ok(())
    }

    /// Drain one channel's decoder/chunker state (flush pending UTF-8, emit final
    /// file-transfer audits). Push errors are recorded, not propagated (the
    /// channel is already closing).
    fn drain_channel(&mut self, ch: ChannelRec) {
        let elapsed = self.elapsed();
        match ch {
            ChannelRec::Terminal { mut out, mut inp } => {
                if let Some(t) = out.flush() {
                    let r =
                        self.push_asciicast(asciicast::event_line(elapsed, EventCode::Output, &t));
                    self.note_push(r);
                }
                if let Some(t) = inp.flush() {
                    let r =
                        self.push_asciicast(asciicast::event_line(elapsed, EventCode::Input, &t));
                    self.note_push(r);
                }
            }
            ChannelRec::Sftp(mut d) => {
                for a in d.finish() {
                    self.push_audit(a);
                }
            }
            ChannelRec::Scp(mut d) => {
                for a in d.finish() {
                    self.push_audit(a);
                }
            }
        }
    }

    fn close_channel(&mut self, channel: K) {
        if let Some(ch) = self.channels.remove(&channel) {
            self.drain_channel(ch);
        }
    }

    /// Flush all channels, seal the remaining plaintext, and read back the object.
    fn finalize_object(&mut self) -> FinalizedObject {
        self.finalized = true;
        let channels = std::mem::take(&mut self.channels);
        for (_id, ch) in channels {
            self.drain_channel(ch);
        }
        let capture_failed = self.failed.is_some() || self.seal_remaining().is_err();
        FinalizedObject {
            object: self.spool.read_object(),
            capture_failed,
            chain_head: self.chain.head_hex(),
            content_digest: self.spool.content_digest_hex(),
            byte_len: self.spool.len() as i64,
            audits: std::mem::take(&mut self.sftp_audit),
        }
    }

    fn push_asciicast(&mut self, line: Vec<u8>) -> Result<(), String> {
        self.chain.extend(&line);
        self.pending_pt.extend_from_slice(&line);
        self.seal_ready_frames()
    }

    /// Record a push error into `failed` (the closing path never propagates).
    fn note_push(&mut self, r: Result<(), String>) {
        if let Err(e) = r {
            self.failed.get_or_insert(e);
        }
    }

    fn push_audit(&mut self, a: FileTransferAudit) {
        self.chain.extend(&sftp::canonical(&a));
        self.sftp_audit.push(a);
    }

    fn seal_ready_frames(&mut self) -> Result<(), String> {
        while self.pending_pt.len() >= self.frame_size {
            // The drained plaintext is scrubbed on drop of this frame buffer.
            let frame = Zeroizing::new(
                self.pending_pt
                    .drain(..self.frame_size)
                    .collect::<Vec<u8>>(),
            );
            self.seal_and_spool(&frame)?;
        }
        Ok(())
    }

    fn seal_remaining(&mut self) -> Result<(), String> {
        self.seal_ready_frames()?;
        if !self.pending_pt.is_empty() {
            let frame = std::mem::take(&mut self.pending_pt);
            self.seal_and_spool(&frame)?;
        }
        Ok(())
    }

    fn seal_and_spool(&mut self, frame_pt: &[u8]) -> Result<(), String> {
        let framed = self
            .sealer
            .seal_frame(self.frame_index, frame_pt)
            .map_err(|e| e.to_string())?;
        self.frame_index += 1;
        self.spool.write_all(&framed).map_err(|e| e.to_string())?;
        Ok(())
    }
}

enum Produced {
    Lines(Vec<Vec<u8>>),
    Audits(Vec<FileTransferAudit>),
}

/// The per-session recorder handed to the SSH handler and (upcast) to the bridge.
pub struct Recorder {
    cap: Mutex<Capture<ChannelId>>,
    strict: bool,
    teardown: Option<Handle>,
    torn: AtomicBool,
    session_id: String,
    recording_id: String,
    upload_url: String,
    upload_headers: BTreeMap<String, String>,
    cpauth: Arc<CpAuthClient>,
    uploader: Arc<HttpUploader>,
}

impl Recorder {
    /// After a capture failure: strict ⇒ tear the connection down (once);
    /// non-strict ⇒ log loudly and continue unrecorded (never silently drop).
    fn on_capture_failure(&self) {
        tracing::warn!(session_id = %self.session_id, recording_id = %self.recording_id, outcome = "recording_failed", "session recording continuation failed");
        if self.strict {
            self.trigger_teardown();
        } else {
            tracing::warn!(session_id = %self.session_id, "STRICT MODE OFF: session continues UNRECORDED (degraded)");
        }
    }

    fn trigger_teardown(&self) {
        if self.torn.swap(true, Ordering::SeqCst) {
            return; // already tearing down
        }
        if let Some(handle) = self.teardown.clone() {
            tokio::spawn(async move {
                let _ = handle
                    .disconnect(
                        russh::Disconnect::ByApplication,
                        RECORDING_UNAVAILABLE.to_string(),
                        String::new(),
                    )
                    .await;
            });
        }
    }
}

impl RecorderTap for Recorder {
    fn tap(&self, channel: ChannelId, direction: TapDirection, _ext: Option<u32>, data: &[u8]) {
        let failed = {
            let mut cap = self.cap.lock().unwrap();
            if cap.finalized || cap.failed.is_some() {
                return;
            }
            match cap.tap(channel, direction, data) {
                Ok(()) => false,
                Err(e) => {
                    cap.failed = Some(e);
                    true
                }
            }
        };
        if failed {
            self.on_capture_failure();
        }
    }

    fn resize(&self, channel: ChannelId, cols: u16, rows: u16) {
        let failed = {
            let mut cap = self.cap.lock().unwrap();
            if cap.finalized || cap.failed.is_some() {
                return;
            }
            match cap.resize(channel, cols, rows) {
                Ok(()) => false,
                Err(e) => {
                    cap.failed = Some(e);
                    true
                }
            }
        };
        if failed {
            self.on_capture_failure();
        }
    }
}

impl SessionRecorder for Recorder {
    fn open_channel(&self, channel: ChannelId, kind: RecChannelKind) {
        let failed = {
            let mut cap = self.cap.lock().unwrap();
            if cap.finalized || cap.failed.is_some() {
                return;
            }
            match cap.open_channel(channel, kind) {
                Ok(()) => false,
                Err(e) => {
                    cap.failed = Some(e);
                    true
                }
            }
        };
        if failed {
            self.on_capture_failure();
        }
    }

    fn close_channel(&self, channel: ChannelId) {
        let mut cap = self.cap.lock().unwrap();
        if cap.finalized {
            return;
        }
        cap.close_channel(channel);
    }

    fn is_torn_down(&self) -> bool {
        self.torn.load(Ordering::SeqCst)
    }

    fn finalize(self: Arc<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            let prepared = {
                let mut cap = self.cap.lock().unwrap();
                if cap.finalized {
                    return;
                }
                cap.finalize_object()
            };

            // Upload the (possibly partial but hash-chained) ciphertext object, then
            // commit the integrity metadata + audit. Bytes never traverse the CP.
            let upload_ok = match &prepared.object {
                Ok(bytes) => self
                    .uploader
                    .put(&self.upload_url, &self.upload_headers, bytes.clone())
                    .await
                    .is_ok(),
                Err(_) => false,
            };
            let status = match (prepared.capture_failed, upload_ok) {
                (false, true) => RecordingStatus::Finalized,
                (true, true) => RecordingStatus::Truncated,
                (_, false) => RecordingStatus::Failed,
            };

            let req = FinalizeRecordingRequest {
                recording_id: self.recording_id.clone(),
                status: status as i32,
                hash_chain_head: prepared.chain_head,
                content_digest: prepared.content_digest,
                byte_len: prepared.byte_len,
                sftp_audit: prepared.audits,
            };
            match self.cpauth.finalize_recording(req).await {
                Ok(_) => tracing::info!(
                    session_id = %self.session_id,
                    recording_id = %self.recording_id,
                    status = ?status,
                    byte_len = prepared.byte_len,
                    "recording finalized"
                ),
                Err(e) => tracing::warn!(
                    session_id = %self.session_id,
                    recording_id = %self.recording_id,
                    error = %e,
                    "FinalizeRecording failed (recording object was uploaded; metadata not committed)"
                ),
            }
        })
    }
}

/// Builds a real [`Recorder`] per authorized session (holds the CP client + the
/// HTTP uploader + the recorder config). One shared factory per Gateway.
pub struct RecorderFactoryImpl {
    cpauth: Arc<CpAuthClient>,
    uploader: Arc<HttpUploader>,
    config: RecorderConfig,
}

impl RecorderFactoryImpl {
    /// Build the factory. Reads the optional upload-CA PEM (for an https store)
    /// eagerly so a misconfiguration fails at startup (fail closed).
    pub fn new(cpauth: Arc<CpAuthClient>, config: RecorderConfig) -> io::Result<Self> {
        let tls = match &config.upload_ca_pem_path {
            Some(path) => {
                let pem = std::fs::read(path)?;
                Some(upload::build_upload_tls(&pem).map_err(io::Error::other)?)
            }
            None => None,
        };
        let uploader = Arc::new(HttpUploader::new(
            std::time::Duration::from_secs(config.upload_timeout_secs),
            tls,
        ));
        Ok(Self {
            cpauth,
            uploader,
            config,
        })
    }
}

impl RecorderFactory for RecorderFactoryImpl {
    fn begin(&self, params: RecordingParams) -> crate::ssh::bridge::BeginFuture<'_> {
        Box::pin(async move {
            let request = BeginRecordingRequest {
                recording_token: params.recording_token,
                context: Some(RecordingContext {
                    session_id: params.session_id.clone(),
                    node_id: params.node_id,
                    principal: params.principal,
                }),
            };
            let resp = self
                .cpauth
                .begin_recording(request)
                .await
                .map_err(|_| RecorderError::Begin)?;

            // The customer key is MANDATORY (keystroke capture is always on).
            let customer_key = resp.customer_key.ok_or(RecorderError::NoCustomerKey)?;
            if customer_key.public_key.is_empty() {
                return Err(RecorderError::NoCustomerKey);
            }
            let algorithm = KeySealAlgorithm::try_from(customer_key.algorithm)
                .unwrap_or(KeySealAlgorithm::Unspecified);
            let sealer = RecordingCipher::seal_to_customer(algorithm, &customer_key.public_key)
                .map_err(|_| RecorderError::Setup)?;

            let upload = resp.upload.ok_or(RecorderError::Setup)?;
            let cap = Capture::new(sealer, &self.config).map_err(|_| RecorderError::Setup)?;

            Ok(Arc::new(Recorder {
                cap: Mutex::new(cap),
                strict: self.config.strict,
                teardown: params.teardown,
                torn: AtomicBool::new(false),
                session_id: params.session_id,
                recording_id: resp.recording_id,
                upload_url: upload.url,
                upload_headers: upload.required_headers.into_iter().collect(),
                cpauth: self.cpauth.clone(),
                uploader: self.uploader.clone(),
            }) as Arc<dyn SessionRecorder>)
        })
    }
}

/// A ciphertext-only spool: an in-memory buffer that spills to a per-recording
/// temp file once it exceeds a threshold (when a spool dir is configured). It
/// streams the object's SHA-256 content digest + byte length as bytes are
/// written. **Only sealed ciphertext is ever written here** (§3/§15).
struct CipherSpool {
    digest: Sha256,
    len: u64,
    mem: Vec<u8>,
    file: Option<std::fs::File>,
    path: Option<PathBuf>,
    spool_dir: Option<PathBuf>,
    threshold: usize,
}

impl CipherSpool {
    fn new(spool_dir: Option<PathBuf>, threshold: usize) -> Self {
        Self {
            digest: Sha256::new(),
            len: 0,
            mem: Vec::new(),
            file: None,
            path: None,
            spool_dir,
            threshold,
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.digest.update(bytes);
        self.len += bytes.len() as u64;
        if let Some(f) = &mut self.file {
            return f.write_all(bytes);
        }
        self.mem.extend_from_slice(bytes);
        if let Some(dir) = self.spool_dir.clone() {
            if self.mem.len() > self.threshold {
                self.spill(&dir)?;
            }
        }
        Ok(())
    }

    fn spill(&mut self, dir: &std::path::Path) -> io::Result<()> {
        let name = format!("slrec-{}.tmp", random_hex());
        let path = dir.join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.create_new(true).write(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path)?;
        f.write_all(&self.mem)?;
        self.mem = Vec::new();
        self.file = Some(f);
        self.path = Some(path);
        Ok(())
    }

    fn read_object(&mut self) -> io::Result<Vec<u8>> {
        if let Some(f) = &mut self.file {
            f.flush()?;
            f.seek(io::SeekFrom::Start(0))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            Ok(buf)
        } else {
            Ok(self.mem.clone())
        }
    }

    fn content_digest_hex(&self) -> String {
        format!(
            "sha256:{}",
            chain::hex_lower(&self.digest.clone().finalize())
        )
    }

    fn len(&self) -> u64 {
        self.len
    }
}

impl Drop for CipherSpool {
    fn drop(&mut self) {
        if let Some(p) = &self.path {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn random_hex() -> String {
    use rand_core::RngCore;
    let mut b = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut b);
    chain::hex_lower(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePublicKey;

    fn customer_keypair() -> (Vec<u8>, p256::SecretKey) {
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let der = secret.public_key().to_public_key_der().unwrap();
        (der.as_bytes().to_vec(), secret)
    }

    fn capture(config: &RecorderConfig, pub_der: &[u8]) -> Capture<u32> {
        let sealer = RecordingCipher::seal_to_customer(
            KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
            pub_der,
        )
        .unwrap();
        Capture::new(sealer, config).unwrap()
    }

    /// Parse an asciicast v2 object (decrypted) into (header, events) where an
    /// event is (code, data).
    fn parse_asciicast(plaintext: &[u8]) -> (String, Vec<(String, String)>) {
        let text = String::from_utf8(plaintext.to_vec()).unwrap();
        let mut lines = text.lines();
        let header = lines.next().unwrap().to_string();
        let events = lines
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                let arr = v.as_array().unwrap();
                (
                    arr[1].as_str().unwrap().to_string(),
                    arr[2].as_str().unwrap().to_string(),
                )
            })
            .collect();
        (header, events)
    }

    /// Part A + C + D: a scripted terminal session's recording replays to the exact
    /// original output/keystroke bytes, records a resize, seals under the customer
    /// key, and the hash-chain head commits to the content.
    #[test]
    fn terminal_round_trips_through_seal_and_chain() {
        let (pub_der, secret) = customer_keypair();
        let config = RecorderConfig::default();
        let mut cap = capture(&config, &pub_der);

        cap.open_channel(1, RecChannelKind::Terminal { command: None })
            .unwrap();
        cap.resize(1, 132, 43).unwrap();
        cap.tap(1, TapDirection::Input, b"echo hi\r").unwrap();
        cap.tap(1, TapDirection::Output, b"hi\r\n").unwrap();
        cap.tap(1, TapDirection::Output, b"user@node:~$ ").unwrap();
        cap.close_channel(1);
        let head_before = cap.chain.head_hex();

        let fin = cap.finalize_object();
        let object = fin.object.unwrap();
        assert_eq!(fin.chain_head, head_before);
        assert!(fin.byte_len as usize == object.len());
        assert_eq!(fin.content_digest, chain::sha256_hex(&object));

        // Decrypt with the customer private key → the exact asciicast v2 file.
        let header = seal::parse_header(&object).unwrap();
        let key = seal::unseal_data_key(&header, &secret).unwrap();
        let plaintext = seal::decrypt_frames(&object, &header, &key).unwrap();
        let (hdr, events) = parse_asciicast(&plaintext);
        assert!(hdr.contains("\"version\":2"));

        // Output events concatenate to the exact node output; input to the keystrokes.
        let out: String = events
            .iter()
            .filter(|(c, _)| c == "o")
            .map(|(_, d)| d.clone())
            .collect();
        let inp: String = events
            .iter()
            .filter(|(c, _)| c == "i")
            .map(|(_, d)| d.clone())
            .collect();
        assert_eq!(out, "hi\r\nuser@node:~$ ");
        assert_eq!(inp, "echo hi\r");
        assert!(
            events.iter().any(|(c, d)| c == "r" && d == "132x43"),
            "resize recorded"
        );
    }

    /// Part D: altering a recorded record changes the hash-chain head (tamper
    /// detection at the record layer).
    #[test]
    fn altering_a_record_changes_the_chain_head() {
        let (pub_der, _s) = customer_keypair();
        let config = RecorderConfig::default();

        let mut a = capture(&config, &pub_der);
        a.open_channel(1, RecChannelKind::Terminal { command: None })
            .unwrap();
        a.tap(1, TapDirection::Output, b"secret output").unwrap();
        let head_a = a.finalize_object().chain_head;

        let mut b = capture(&config, &pub_der);
        b.open_channel(1, RecChannelKind::Terminal { command: None })
            .unwrap();
        b.tap(1, TapDirection::Output, b"secret 0utput").unwrap();
        let head_b = b.finalize_object().chain_head;

        assert_ne!(head_a, head_b, "a changed record must change the head");
    }

    /// Part B: an SFTP upload+download over the tap yields per-op file-transfer
    /// audit (path/direction/size/SHA-256) folded into the chain, and NO asciicast
    /// events (file-transfer channels do not produce terminal recording).
    #[test]
    fn sftp_channel_produces_file_transfer_audit_only() {
        let (pub_der, secret) = customer_keypair();
        let config = RecorderConfig::default();
        let mut cap = capture(&config, &pub_der);
        cap.open_channel(2, RecChannelKind::Sftp).unwrap();

        let content = b"payload-bytes";
        // OPEN(id1,"f") → HANDLE("h") → WRITE(content) → CLOSE.
        let mut open = 1u32.to_be_bytes().to_vec();
        open.extend_from_slice(&sftp_string(b"f"));
        open.extend_from_slice(&0u32.to_be_bytes());
        cap.tap(2, TapDirection::Input, &sftp_packet(3, &open))
            .unwrap();
        let mut handle = 1u32.to_be_bytes().to_vec();
        handle.extend_from_slice(&sftp_string(b"h"));
        cap.tap(2, TapDirection::Output, &sftp_packet(102, &handle))
            .unwrap();
        let mut write = 2u32.to_be_bytes().to_vec();
        write.extend_from_slice(&sftp_string(b"h"));
        write.extend_from_slice(&0u64.to_be_bytes());
        write.extend_from_slice(&sftp_string(content));
        cap.tap(2, TapDirection::Input, &sftp_packet(6, &write))
            .unwrap();
        let mut close = 3u32.to_be_bytes().to_vec();
        close.extend_from_slice(&sftp_string(b"h"));
        cap.tap(2, TapDirection::Input, &sftp_packet(4, &close))
            .unwrap();
        cap.close_channel(2);

        let fin = cap.finalize_object();
        assert_eq!(fin.audits.len(), 1);
        assert_eq!(fin.audits[0].direction, "upload");
        assert_eq!(fin.audits[0].size, content.len() as i64);
        assert_eq!(fin.audits[0].sha256, chain::sha256_hex(content));

        // The object decrypts to an asciicast with only the header (no events).
        let object = fin.object.unwrap();
        let header = seal::parse_header(&object).unwrap();
        let key = seal::unseal_data_key(&header, &secret).unwrap();
        let plaintext = seal::decrypt_frames(&object, &header, &key).unwrap();
        let (_hdr, events) = parse_asciicast(&plaintext);
        assert!(events.is_empty(), "sftp channel adds no terminal events");
    }

    /// Part F mechanics (detection): a spool write to an unwritable dir makes the
    /// capture surface an error, which the recorder turns into a fail-closed
    /// teardown (the actual SSH disconnect is proven end-to-end).
    #[test]
    fn spool_failure_is_detected_as_a_capture_error() {
        let (pub_der, _s) = customer_keypair();
        // A high threshold so setup (a small header) stays in memory, but a
        // large mid-session tap crosses it and spills to a bad dir → error.
        let config = RecorderConfig {
            strict: true,
            spool_dir: Some(PathBuf::from("/nonexistent/sessionlayer-spill")),
            spool_memory_threshold_bytes: 100_000,
            ..RecorderConfig::default()
        };
        let mut cap = capture(&config, &pub_der);
        cap.open_channel(1, RecChannelKind::Terminal { command: None })
            .unwrap();
        // Enough output that sealing crosses the threshold → spill to the bad dir.
        let err = cap.tap(1, TapDirection::Output, &vec![b'x'; 200_000]);
        assert!(
            err.is_err(),
            "an unwritable spool must surface a capture error"
        );
    }

    /// Part F wiring: a strict recorder flags teardown on a capture failure; a
    /// non-strict one continues (degraded) without tearing the session down.
    #[test]
    fn strict_flag_governs_teardown_on_failure() {
        let strict = recorder_for_test(true);
        strict.on_capture_failure();
        assert!(strict.is_torn_down(), "strict must flag teardown");

        let lax = recorder_for_test(false);
        lax.on_capture_failure();
        assert!(
            !lax.is_torn_down(),
            "non-strict must NOT tear down (degraded)"
        );
    }

    fn recorder_for_test(strict: bool) -> Recorder {
        let (pub_der, _s) = customer_keypair();
        let config = RecorderConfig {
            strict,
            ..RecorderConfig::default()
        };
        let sealer = RecordingCipher::seal_to_customer(
            KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
            &pub_der,
        )
        .unwrap();
        let cap = Capture::new(sealer, &config).unwrap();
        Recorder {
            cap: Mutex::new(cap),
            strict,
            teardown: None,
            torn: AtomicBool::new(false),
            session_id: "s".into(),
            recording_id: "r".into(),
            upload_url: String::new(),
            upload_headers: BTreeMap::new(),
            cpauth: Arc::new(crate::cpauth::CpAuthClient::new(
                Arc::new(crate::cpauth::CpChannelFactory::fixed(
                    crate::mtls::ChannelParams {
                        endpoint: "https://127.0.0.1:1".into(),
                        server_name: "x".into(),
                        connect_timeout: std::time::Duration::from_millis(1),
                        rpc_timeout: std::time::Duration::from_millis(1),
                    },
                    dummy_identity(),
                    Vec::new(),
                )),
                std::time::Duration::from_millis(1),
            )),
            uploader: Arc::new(HttpUploader::new(std::time::Duration::from_secs(1), None)),
        }
    }

    // --- test helpers ---
    fn sftp_packet(ptype: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = ((payload.len() as u32) + 1).to_be_bytes().to_vec();
        p.push(ptype);
        p.extend_from_slice(payload);
        p
    }
    fn sftp_string(s: &[u8]) -> Vec<u8> {
        let mut v = (s.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(s);
        v
    }
    fn dummy_identity() -> crate::mtls::ClientIdentity {
        // A throwaway self-signed identity; the CP is never actually dialed in this
        // test (the recorder's network finalize is not invoked).
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["gw".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        crate::mtls::ClientIdentity {
            cert_pem: cert.pem().into_bytes(),
            key_pem: zeroize::Zeroizing::new(kp.serialize_pem()),
        }
    }
}
