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
use std::io::{self, Write};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// Tracks in-flight end-of-session finalize tasks so a graceful shutdown can wait
/// for live recordings to flush → seal → upload → FinalizeRecording before the
/// process exits, instead of losing them (#3). Connection-preservation drain is
/// still S14 (F-drain, Accepted-Risk); only recordings are drained here.
#[derive(Clone, Default)]
pub struct FinalizeTracker {
    inner: Arc<FinalizeInner>,
}

#[derive(Default)]
struct FinalizeInner {
    count: AtomicUsize,
    notify: tokio::sync::Notify,
}

impl FinalizeTracker {
    /// Spawn a finalize future, tracked so [`Self::drain`] can await it.
    pub fn spawn(&self, fut: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.count.fetch_add(1, Ordering::SeqCst);
        let inner = self.inner.clone();
        tokio::spawn(async move {
            fut.await;
            if inner.count.fetch_sub(1, Ordering::SeqCst) == 1 {
                inner.notify.notify_waiters();
            }
        });
    }

    /// Await all in-flight finalize tasks, or until `grace` elapses (fail-safe: a
    /// hung upload never blocks shutdown forever).
    pub async fn drain(&self, grace: Duration) {
        let deadline = tokio::time::sleep(grace);
        tokio::pin!(deadline);
        loop {
            // Register the waiter BEFORE checking the count (no lost wakeup).
            let notified = self.inner.notify.notified();
            if self.inner.count.load(Ordering::SeqCst) == 0 {
                return;
            }
            tokio::select! {
                _ = &mut deadline => return,
                _ = notified => {}
            }
        }
    }
}

/// How a bridged channel's plaintext is being captured. A terminal channel is
/// ALWAYS asciicast (output + input); a legacy scp-over-exec additionally runs an
/// SCP decoder for file-transfer audit — the command never suppresses capture.
enum ChannelRec {
    Terminal {
        out: Utf8Chunker,
        inp: Utf8Chunker,
        scp: Option<ScpDecoder>,
    },
    Sftp(SftpDecoder),
}

/// The synchronous capture core (all state behind the recorder's mutex). Generic
/// over the channel key so it is unit-testable without a real [`ChannelId`].
struct Capture<K: Eq + std::hash::Hash + Copy> {
    started: Instant,
    /// Unix seconds at recording start (the asciicast header `timestamp`).
    started_unix: u64,
    /// Whether the asciicast v2 header line has been written yet. Deferred to the
    /// first terminal channel so the header carries the real PTY size (#10).
    header_written: bool,
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
    source: io::Result<upload::UploadSource>,
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
            config.max_object_bytes,
        );
        spool.write_all(sealer.header())?;
        let started_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // The asciicast header is written lazily (on the first terminal channel /
        // at finalize) so it can carry the real PTY size (#10).
        Ok(Self {
            started: Instant::now(),
            started_unix,
            header_written: false,
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
        })
    }

    fn elapsed(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// Write the asciicast v2 header exactly once (line 0 of the sealed stream),
    /// carrying `cols`×`rows` (0 ⇒ default 80×24).
    fn ensure_header(&mut self, cols: u16, rows: u16) -> Result<(), String> {
        if self.header_written {
            return Ok(());
        }
        self.header_written = true;
        let w = if cols == 0 { 80 } else { cols };
        let h = if rows == 0 { 24 } else { rows };
        self.push_asciicast(asciicast::header_line(w, h, self.started_unix))
    }

    fn open_channel(&mut self, channel: K, kind: RecChannelKind) -> Result<(), String> {
        match kind {
            RecChannelKind::Terminal {
                command,
                scp,
                cols,
                rows,
            } => {
                self.ensure_header(cols, rows)?;
                self.channels.insert(
                    channel,
                    ChannelRec::Terminal {
                        out: Utf8Chunker::default(),
                        inp: Utf8Chunker::default(),
                        scp: scp.map(|m| ScpDecoder::new(m.upload, m.target)),
                    },
                );
                if let Some(cmd) = command {
                    // Record the exec command line as an input event (ALWAYS — even
                    // for a legacy scp-over-exec, whose content is ALSO captured).
                    let text = String::from_utf8_lossy(&cmd).into_owned();
                    let line = asciicast::event_line(self.elapsed(), EventCode::Input, &text);
                    self.push_asciicast(line)?;
                }
            }
            RecChannelKind::Sftp => {
                self.ensure_header(0, 0)?;
                self.channels
                    .insert(channel, ChannelRec::Sftp(SftpDecoder::new()));
            }
        }
        Ok(())
    }

    fn tap(
        &mut self,
        channel: K,
        direction: TapDirection,
        ext: Option<u32>,
        data: &[u8],
    ) -> Result<(), String> {
        let elapsed = self.elapsed();
        // Produce records under a scoped channel borrow, then fold them in.
        let (lines, audits) = match self.channels.get_mut(&channel) {
            Some(ChannelRec::Terminal { out, inp, scp }) => {
                // ALWAYS asciicast (stderr `ext=Some(1)` still folds into `o`).
                let (chunker, code) = match direction {
                    TapDirection::Output => (out, EventCode::Output),
                    TapDirection::Input => (inp, EventCode::Input),
                };
                let text = chunker.push(data);
                let mut lines = Vec::new();
                if !text.is_empty() {
                    lines.push(asciicast::event_line(elapsed, code, &text));
                }
                // ADDITIVELY decode a legacy scp-over-exec transfer — only the
                // PRIMARY data stream (never stderr; #6) is protocol bytes.
                let audits = match scp {
                    Some(d) if ext.is_none() => d.feed(direction, data),
                    _ => Vec::new(),
                };
                (lines, audits)
            }
            // The sftp subsystem is protocol on the primary stream only (stderr,
            // if any, is not SFTP framing — never feed it to the decoder; #6).
            Some(ChannelRec::Sftp(d)) => {
                let audits = if ext.is_none() {
                    d.feed(direction, data)
                } else {
                    Vec::new()
                };
                (Vec::new(), audits)
            }
            None => (Vec::new(), Vec::new()),
        };
        for l in lines {
            self.push_asciicast(l)?;
        }
        for a in audits {
            self.push_audit(a)?;
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
            ChannelRec::Terminal {
                mut out,
                mut inp,
                scp,
            } => {
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
                if let Some(mut d) = scp {
                    for a in d.finish() {
                        let r = self.push_audit(a);
                        self.note_push(r);
                    }
                }
            }
            ChannelRec::Sftp(mut d) => {
                for a in d.finish() {
                    let r = self.push_audit(a);
                    self.note_push(r);
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
        // A recording with no terminal channel (or none at all) still gets a valid
        // asciicast v2 header so the object is well-formed.
        let r = self.ensure_header(0, 0);
        self.note_push(r);
        let channels = std::mem::take(&mut self.channels);
        for (_id, ch) in channels {
            self.drain_channel(ch);
        }
        let capture_failed = self.failed.is_some() || self.seal_remaining().is_err();
        FinalizedObject {
            source: self.spool.take_source(),
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

    /// Record a file-transfer audit BOTH as an asciicast `m` marker in the sealed
    /// stream (so the hash-chain — computed over the sealed line stream — commits
    /// to it and the object is independently verifiable, #7) AND as a cleartext
    /// convenience copy for the CP's audit correlation (FinalizeRecording).
    fn push_audit(&mut self, a: FileTransferAudit) -> Result<(), String> {
        let label = audit_marker_label(&a);
        let line = asciicast::event_line(self.elapsed(), EventCode::Marker, &label);
        self.push_asciicast(line)?;
        self.sftp_audit.push(a);
        Ok(())
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

/// The canonical marker label for a file-transfer audit (an asciicast `m` event
/// payload). A replay verifier reconstructs the file-transfer records from these,
/// and the hash-chain (over the sealed stream) commits to them.
fn audit_marker_label(a: &FileTransferAudit) -> String {
    serde_json::to_string(&serde_json::json!({
        "type": "file-transfer",
        "operation": a.operation,
        "path": a.path,
        "direction": a.direction,
        "size": a.size,
        "sha256": a.sha256,
    }))
    .expect("audit marker serializes")
}

/// The per-session recorder handed to the SSH handler and (upcast) to the bridge.
/// The WORM upload credential is NOT held here — it is fetched at session end via
/// `RequestUpload` so its TTL covers only the PUT (§12.2; no session-long creds).
pub struct Recorder {
    cap: Mutex<Capture<ChannelId>>,
    strict: bool,
    teardown: Option<Handle>,
    torn: AtomicBool,
    session_id: String,
    recording_id: String,
    cpauth: Arc<CpAuthClient>,
    uploader: Arc<HttpUploader>,
    upload_max_attempts: u32,
}

impl Recorder {
    /// Fetch a fresh credential and PUT the object, retrying transient faults with
    /// exponential backoff up to `upload_max_attempts` (#4). Each attempt mints a
    /// fresh short-lived credential and a fresh streaming body.
    async fn upload_with_retry(&self, source: &upload::UploadSource) -> bool {
        let mut backoff = std::time::Duration::from_millis(200);
        for attempt in 1..=self.upload_max_attempts {
            let cred = match self.cpauth.request_upload(&self.recording_id).await {
                Ok(resp) => resp.upload,
                Err(e) => {
                    tracing::warn!(session_id = %self.session_id, recording_id = %self.recording_id, attempt, error = %e, "RequestUpload failed");
                    None
                }
            };
            if let Some(cred) = cred {
                let headers: BTreeMap<String, String> = cred.required_headers.into_iter().collect();
                match self.uploader.put(&cred.url, &headers, source).await {
                    Ok(()) => return true,
                    Err(e) if e.is_retryable() && attempt < self.upload_max_attempts => {
                        tracing::warn!(session_id = %self.session_id, recording_id = %self.recording_id, attempt, error = %e, "WORM upload failed; retrying");
                    }
                    Err(e) => {
                        tracing::warn!(session_id = %self.session_id, recording_id = %self.recording_id, attempt, error = %e, "WORM upload failed; no more retries");
                        return false;
                    }
                }
            } else if attempt >= self.upload_max_attempts {
                return false;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(std::time::Duration::from_secs(5));
        }
        false
    }

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
    fn tap(&self, channel: ChannelId, direction: TapDirection, ext: Option<u32>, data: &[u8]) {
        let failed = {
            let mut cap = self.cap.lock().unwrap();
            if cap.finalized || cap.failed.is_some() {
                return;
            }
            match cap.tap(channel, direction, ext, data) {
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

    fn should_abort(&self) -> bool {
        self.torn.load(Ordering::SeqCst)
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

            // Upload the (possibly partial but hash-chained) ciphertext object with
            // a FRESH short-lived credential fetched now (at session end) — a
            // session-long begin-time credential would expire before a long
            // session's PUT (§12.2). Bounded retry with backoff (#4). Bytes never
            // traverse the CP.
            let upload_ok = match &prepared.source {
                Ok(source) => self.upload_with_retry(source).await,
                Err(e) => {
                    tracing::warn!(session_id = %self.session_id, recording_id = %self.recording_id, error = %e, outcome = "recording_failed", "recording object unavailable (spool error); not uploaded");
                    false
                }
            };
            let status = match (prepared.capture_failed, upload_ok) {
                (false, true) => RecordingStatus::Finalized,
                (true, true) => RecordingStatus::Truncated,
                (_, false) => RecordingStatus::Failed,
            };
            let outcome = match status {
                RecordingStatus::Finalized => "recording_finalized",
                RecordingStatus::Truncated => "recording_truncated",
                _ if prepared.capture_failed => "recording_failed",
                _ => "recording_upload_failed",
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
                Ok(_) if status == RecordingStatus::Finalized => tracing::info!(
                    session_id = %self.session_id,
                    recording_id = %self.recording_id,
                    outcome,
                    byte_len = prepared.byte_len,
                    "recording finalized"
                ),
                // A non-final status is committed (never silently dropped) but logged
                // loudly at warn so the incomplete recording is visible (#16).
                Ok(_) => tracing::warn!(
                    session_id = %self.session_id,
                    recording_id = %self.recording_id,
                    outcome,
                    status = ?status,
                    "recording committed with a NON-FINAL status"
                ),
                Err(e) => tracing::warn!(
                    session_id = %self.session_id,
                    recording_id = %self.recording_id,
                    outcome,
                    error = %e,
                    "FinalizeRecording failed; recording metadata not committed"
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
            config.require_https,
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

            // The WORM upload credential is NOT issued here — it is fetched at
            // session end via RequestUpload (short-lived, covers only the PUT).
            let cap = Capture::new(sealer, &self.config).map_err(|_| RecorderError::Setup)?;

            Ok(Arc::new(Recorder {
                cap: Mutex::new(cap),
                strict: self.config.strict,
                teardown: params.teardown,
                torn: AtomicBool::new(false),
                session_id: params.session_id,
                recording_id: resp.recording_id,
                cpauth: self.cpauth.clone(),
                uploader: self.uploader.clone(),
                upload_max_attempts: self.config.upload_max_attempts.max(1),
            }) as Arc<dyn SessionRecorder>)
        })
    }
}

/// A ciphertext-only spool. It holds the sealed object in memory up to a
/// threshold, then **always spills** (even with no configured dir — the system
/// temp dir) to a per-recording temp file written by a DEDICATED BLOCKING THREAD,
/// so no file I/O happens on the tokio reactor under the recorder lock (#9). It
/// enforces a hard `max_object_bytes` cap (fail closed, #2) and tracks the object
/// content digest + byte length. **Only sealed ciphertext is ever written here.**
struct CipherSpool {
    digest: Sha256,
    len: u64,
    max_bytes: u64,
    threshold: usize,
    spool_dir: Option<PathBuf>,
    state: SpoolState,
}

enum SpoolState {
    /// Ciphertext buffered in memory (short session). Not secret — sealed frames.
    Mem(Vec<u8>),
    /// Spilled to a temp file, fed by a dedicated blocking writer thread.
    File(FileSink),
}

struct FileSink {
    tx: Option<std::sync::mpsc::Sender<Vec<u8>>>,
    handle: Option<std::thread::JoinHandle<io::Result<()>>>,
    /// Set by the writer thread on an I/O error (surfaced on the next write).
    err: Arc<AtomicBool>,
    path: PathBuf,
}

impl CipherSpool {
    fn new(spool_dir: Option<PathBuf>, threshold: usize, max_bytes: u64) -> Self {
        Self {
            digest: Sha256::new(),
            len: 0,
            max_bytes,
            threshold,
            spool_dir,
            state: SpoolState::Mem(Vec::new()),
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let new_len = self.len + bytes.len() as u64;
        if new_len > self.max_bytes {
            return Err(io::Error::other("recording exceeds max_object_bytes"));
        }
        self.digest.update(bytes);
        self.len = new_len;
        match &mut self.state {
            SpoolState::Mem(buf) => {
                buf.extend_from_slice(bytes);
                if buf.len() > self.threshold {
                    self.spill()?;
                }
                Ok(())
            }
            SpoolState::File(sink) => {
                if sink.err.load(Ordering::Relaxed) {
                    return Err(io::Error::other("recording spool writer failed"));
                }
                sink.tx
                    .as_ref()
                    .expect("sender live before finalize")
                    .send(bytes.to_vec())
                    .map_err(|_| io::Error::other("recording spool writer gone"))
            }
        }
    }

    /// Transition Mem→File: create the temp file + writer thread, hand over the
    /// buffered ciphertext. File writes happen off the reactor on that thread (#9).
    fn spill(&mut self) -> io::Result<()> {
        let dir = self.spool_dir.clone().unwrap_or_else(std::env::temp_dir);
        let path = dir.join(format!("slrec-{}.tmp", random_hex()));
        let mut opts = std::fs::OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let err = Arc::new(AtomicBool::new(false));
        let err_thread = err.clone();
        let handle = std::thread::Builder::new()
            .name("slrec-spool".to_string())
            .spawn(move || -> io::Result<()> {
                let mut w = io::BufWriter::new(file);
                while let Ok(chunk) = rx.recv() {
                    if let Err(e) = w.write_all(&chunk) {
                        err_thread.store(true, Ordering::Relaxed);
                        return Err(e);
                    }
                }
                w.flush()
            })?;
        // Hand over the in-memory ciphertext, then switch to the file sink.
        if let SpoolState::Mem(buf) = &mut self.state {
            let buffered = std::mem::take(buf);
            tx.send(buffered)
                .map_err(|_| io::Error::other("recording spool writer gone"))?;
        }
        self.state = SpoolState::File(FileSink {
            tx: Some(tx),
            handle: Some(handle),
            err,
            path,
        });
        Ok(())
    }

    /// Close the spool and produce the upload source (a fresh body per attempt).
    /// For the file sink this joins the writer thread (flush + surface any error).
    fn take_source(&mut self) -> io::Result<upload::UploadSource> {
        match &mut self.state {
            SpoolState::Mem(buf) => Ok(upload::UploadSource::Mem(bytes::Bytes::from(
                std::mem::take(buf),
            ))),
            SpoolState::File(sink) => {
                drop(sink.tx.take()); // close the channel → writer flushes + exits
                match sink.handle.take() {
                    Some(h) => h
                        .join()
                        .map_err(|_| io::Error::other("recording spool writer panicked"))??,
                    None => return Err(io::Error::other("recording spool already finalized")),
                }
                Ok(upload::UploadSource::File {
                    path: sink.path.clone(),
                    len: self.len,
                })
            }
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
        if let SpoolState::File(sink) = &self.state {
            let _ = std::fs::remove_file(&sink.path);
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

    /// The ciphertext object bytes from a finalized source (in-memory or spilled).
    fn object_bytes(source: io::Result<upload::UploadSource>) -> Vec<u8> {
        match source.unwrap() {
            upload::UploadSource::Mem(b) => b.to_vec(),
            upload::UploadSource::File { path, .. } => std::fs::read(path).unwrap(),
        }
    }

    /// Recompute the hash-chain head from a decrypted asciicast object (each `\n`-
    /// terminated line is one record) — the independent verification of #7.
    fn recompute_chain(plaintext: &[u8]) -> String {
        let mut c = HashChain::new();
        let mut start = 0;
        for i in 0..plaintext.len() {
            if plaintext[i] == b'\n' {
                c.extend(&plaintext[start..=i]);
                start = i + 1;
            }
        }
        if start < plaintext.len() {
            c.extend(&plaintext[start..]);
        }
        c.head_hex()
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

        cap.open_channel(
            1,
            RecChannelKind::Terminal {
                command: None,
                scp: None,
                cols: 0,
                rows: 0,
            },
        )
        .unwrap();
        cap.resize(1, 132, 43).unwrap();
        cap.tap(1, TapDirection::Input, None, b"echo hi\r").unwrap();
        cap.tap(1, TapDirection::Output, None, b"hi\r\n").unwrap();
        cap.tap(1, TapDirection::Output, None, b"user@node:~$ ")
            .unwrap();
        cap.close_channel(1);
        let head_before = cap.chain.head_hex();

        let fin = cap.finalize_object();
        let chain_head = fin.chain_head.clone();
        let content_digest = fin.content_digest.clone();
        let byte_len = fin.byte_len;
        let object = object_bytes(fin.source);
        assert_eq!(chain_head, head_before);
        assert_eq!(byte_len as usize, object.len());
        assert_eq!(content_digest, chain::sha256_hex(&object));

        // Decrypt with the customer private key → the exact asciicast v2 file.
        let header = seal::parse_header(&object).unwrap();
        let key = seal::unseal_data_key(&header, &secret).unwrap();
        let plaintext = seal::decrypt_frames(&object, &header, &key).unwrap();
        // #7: the hash-chain head is recomputable from the decrypted object alone.
        assert_eq!(recompute_chain(&plaintext), chain_head);
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

    /// Red-team #1: an exec whose command LOOKS like a legacy scp still records
    /// asciicast for ALL I/O — the command string can never suppress mandatory
    /// content capture (the SCP decoder runs additively, not instead of).
    #[test]
    fn scp_classified_exec_still_records_asciicast() {
        let (pub_der, secret) = customer_keypair();
        let config = RecorderConfig::default();
        let mut cap = capture(&config, &pub_der);
        cap.open_channel(
            1,
            RecChannelKind::Terminal {
                command: Some(b"scp -t /x; echo pwned".to_vec()),
                scp: Some(crate::ssh::bridge::ScpMode {
                    upload: true,
                    target: b"/x".to_vec(),
                }),
                cols: 0,
                rows: 0,
            },
        )
        .unwrap();
        // Output that a command-string-driven capture bypass would have hidden.
        cap.tap(1, TapDirection::Output, None, b"pwned\n").unwrap();
        cap.close_channel(1);

        let object = object_bytes(cap.finalize_object().source);
        let header = seal::parse_header(&object).unwrap();
        let key = seal::unseal_data_key(&header, &secret).unwrap();
        let plaintext = seal::decrypt_frames(&object, &header, &key).unwrap();
        let (_h, events) = parse_asciicast(&plaintext);
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
        assert!(
            out.contains("pwned"),
            "post-; output MUST be recorded (no bypass)"
        );
        assert!(
            inp.contains("scp -t /x; echo pwned"),
            "exec command recorded"
        );
    }

    /// Part D: altering a recorded record changes the hash-chain head (tamper
    /// detection at the record layer).
    #[test]
    fn altering_a_record_changes_the_chain_head() {
        let (pub_der, _s) = customer_keypair();
        let config = RecorderConfig::default();

        let mut a = capture(&config, &pub_der);
        a.open_channel(
            1,
            RecChannelKind::Terminal {
                command: None,
                scp: None,
                cols: 0,
                rows: 0,
            },
        )
        .unwrap();
        a.tap(1, TapDirection::Output, None, b"secret output")
            .unwrap();
        let head_a = a.finalize_object().chain_head;

        let mut b = capture(&config, &pub_der);
        b.open_channel(
            1,
            RecChannelKind::Terminal {
                command: None,
                scp: None,
                cols: 0,
                rows: 0,
            },
        )
        .unwrap();
        b.tap(1, TapDirection::Output, None, b"secret 0utput")
            .unwrap();
        let head_b = b.finalize_object().chain_head;

        assert_ne!(head_a, head_b, "a changed record must change the head");
    }

    /// Part B + #7: an SFTP upload over the tap yields a per-op file-transfer audit
    /// (cleartext copy) AND folds it into the sealed stream as an `m` marker, so
    /// the decrypted object carries the transfer record and no terminal I/O.
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
        cap.tap(2, TapDirection::Input, None, &sftp_packet(3, &open))
            .unwrap();
        let mut handle = 1u32.to_be_bytes().to_vec();
        handle.extend_from_slice(&sftp_string(b"h"));
        cap.tap(2, TapDirection::Output, None, &sftp_packet(102, &handle))
            .unwrap();
        let mut write = 2u32.to_be_bytes().to_vec();
        write.extend_from_slice(&sftp_string(b"h"));
        write.extend_from_slice(&0u64.to_be_bytes());
        write.extend_from_slice(&sftp_string(content));
        cap.tap(2, TapDirection::Input, None, &sftp_packet(6, &write))
            .unwrap();
        let mut close = 3u32.to_be_bytes().to_vec();
        close.extend_from_slice(&sftp_string(b"h"));
        cap.tap(2, TapDirection::Input, None, &sftp_packet(4, &close))
            .unwrap();
        cap.close_channel(2);

        let fin = cap.finalize_object();
        let chain_head = fin.chain_head.clone();
        assert_eq!(fin.audits.len(), 1);
        assert_eq!(fin.audits[0].direction, "upload");
        assert_eq!(fin.audits[0].size, content.len() as i64);
        assert_eq!(fin.audits[0].sha256, chain::sha256_hex(content));

        // The object decrypts to an asciicast whose only event is the `m` marker
        // for the transfer (no terminal I/O), and the head recomputes from it (#7).
        let object = object_bytes(fin.source);
        let header = seal::parse_header(&object).unwrap();
        let key = seal::unseal_data_key(&header, &secret).unwrap();
        let plaintext = seal::decrypt_frames(&object, &header, &key).unwrap();
        assert_eq!(recompute_chain(&plaintext), chain_head);
        let (_hdr, events) = parse_asciicast(&plaintext);
        assert_eq!(events.len(), 1, "one file-transfer marker, no terminal I/O");
        assert_eq!(events[0].0, "m");
        assert!(events[0].1.contains("upload"), "marker carries the audit");
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
        cap.open_channel(
            1,
            RecChannelKind::Terminal {
                command: None,
                scp: None,
                cols: 0,
                rows: 0,
            },
        )
        .unwrap();
        // Enough output that sealing crosses the threshold → spill to the bad dir.
        let err = cap.tap(1, TapDirection::Output, None, &vec![b'x'; 200_000]);
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
            uploader: Arc::new(HttpUploader::new(
                std::time::Duration::from_secs(1),
                false,
                None,
            )),
            upload_max_attempts: 1,
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
