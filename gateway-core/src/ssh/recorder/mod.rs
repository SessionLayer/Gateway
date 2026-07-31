//! Session recorder: asciicast v2 + file-transfer audit + hash-chain + WORM upload under customer key (fail-closed).

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
    BeginRecordingRequest, FileTransferAudit, FinalizeRecordingRequest, FinalizeRecordingResponse,
    KeySealAlgorithm, RecordingContext, RecordingStatus, TunnelAudit,
};
use crate::ssh::bridge::{
    RecChannelKind, RecorderError, RecorderFactory, RecorderTap, RecordingParams, SessionRecorder,
    TapDirection, TunnelCounters, TunnelDirection,
};
use crate::ssh::outcome::RECORDING_UNAVAILABLE;

use asciicast::{EventCode, Utf8Chunker};
use chain::HashChain;
use scp::ScpDecoder;
use seal::RecordingCipher;
use sftp::SftpDecoder;
use upload::HttpUploader;

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

enum ChannelRec {
    Terminal {
        out: Utf8Chunker,
        inp: Utf8Chunker,
        scp: Option<ScpDecoder>,
    },
    Sftp(SftpDecoder),
    Tunnel {
        direction: TunnelDirection,
        target: String,
        counters: TunnelCounters,
        opened_at: Instant,
    },
}

struct Capture<K: Eq + std::hash::Hash + Copy> {
    started: Instant,
    started_unix: u64,
    header_written: bool,
    chain: HashChain,
    sealer: RecordingCipher,
    spool: CipherSpool,
    frame_index: u64,
    frame_size: usize,
    pending_pt: Zeroizing<Vec<u8>>,
    channels: HashMap<K, ChannelRec>,
    sftp_audit: Vec<FileTransferAudit>,
    tunnel_audit: Vec<TunnelAudit>,
    failed: Option<String>,
    finalized: bool,
}

struct FinalizedObject {
    source: ClosedSpool,
    capture_failed: bool,
    chain_head: String,
    content_digest: String,
    byte_len: i64,
    audits: Vec<FileTransferAudit>,
    tunnel_audits: Vec<TunnelAudit>,
}

impl<K: Eq + std::hash::Hash + Copy> Capture<K> {
    fn new(
        sealer: RecordingCipher,
        config: &RecorderConfig,
        spool_file: SpoolFile,
    ) -> io::Result<Self> {
        let mut spool = CipherSpool::new(
            spool_file,
            config.spool_memory_threshold_bytes,
            config.max_object_bytes,
        );
        spool.write_all(sealer.header())?;
        let started_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
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
            tunnel_audit: Vec::new(),
            failed: None,
            finalized: false,
        })
    }

    fn elapsed(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    fn ensure_header(&mut self, cols: u16, rows: u16) -> Result<(), String> {
        if self.header_written {
            return Ok(());
        }
        self.header_written = true;
        let w = if cols == 0 { 80 } else { cols };
        let h = if rows == 0 { 24 } else { rows };
        self.push_asciicast(&asciicast::header_line(w, h, self.started_unix))
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
                    // for a legacy scp-over-exec, whose content is ALSO captured). The
                    // command may itself be sensitive, so the transient copy scrubs.
                    let text = Zeroizing::new(String::from_utf8_lossy(&cmd).into_owned());
                    let line = asciicast::event_line(self.elapsed(), EventCode::Input, &text);
                    self.push_asciicast(&line)?;
                }
            }
            RecChannelKind::Sftp => {
                self.ensure_header(0, 0)?;
                self.channels
                    .insert(channel, ChannelRec::Sftp(SftpDecoder::new()));
            }
            RecChannelKind::Tunnel {
                direction,
                target,
                counters,
            } => {
                // Metadata-only (FR-SESS-2): emit a `<family>.opened` marker into the
                // sealed stream — target, direction, capability, correlation id — but
                // NEVER the forwarded bytes (arbitrary/binary, no universal decode).
                self.ensure_header(0, 0)?;
                let label = tunnel_marker_open(direction, &target);
                let line = asciicast::event_line(self.elapsed(), EventCode::Marker, &label);
                self.push_asciicast(&line)?;
                self.channels.insert(
                    channel,
                    ChannelRec::Tunnel {
                        direction,
                        target,
                        counters,
                        opened_at: Instant::now(),
                    },
                );
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
        let (lines, audits) = match self.channels.get_mut(&channel) {
            Some(ChannelRec::Terminal { out, inp, scp }) => {
                let (chunker, code) = match direction {
                    TapDirection::Output => (out, EventCode::Output),
                    TapDirection::Input => (inp, EventCode::Input),
                };
                let text = chunker.push(data);
                let mut lines = Vec::new();
                if !text.is_empty() {
                    lines.push(asciicast::event_line(elapsed, code, &text));
                }
                drop(text); // scrub the transient chunk plaintext promptly
                let audits = match scp {
                    Some(d) if ext.is_none() => d.feed(direction, data),
                    _ => Vec::new(),
                };
                (lines, audits)
            }
            Some(ChannelRec::Sftp(d)) => {
                let audits = if ext.is_none() {
                    d.feed(direction, data)
                } else {
                    Vec::new()
                };
                (Vec::new(), audits)
            }
            Some(ChannelRec::Tunnel { .. }) => (Vec::new(), Vec::new()),
            None => (Vec::new(), Vec::new()),
        };
        for l in lines {
            self.push_asciicast(&l)?;
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
            self.push_asciicast(&line)?;
        }
        Ok(())
    }

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
                        self.push_asciicast(&asciicast::event_line(elapsed, EventCode::Output, &t));
                    self.note_push(r);
                }
                if let Some(t) = inp.flush() {
                    let r =
                        self.push_asciicast(&asciicast::event_line(elapsed, EventCode::Input, &t));
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
            ChannelRec::Tunnel {
                direction,
                target,
                counters,
                opened_at,
            } => {
                let bytes_in = counters.bytes_in.load(Ordering::Relaxed);
                let bytes_out = counters.bytes_out.load(Ordering::Relaxed);
                let duration = opened_at.elapsed().as_secs_f64();
                let label = tunnel_marker_close(direction, &target, bytes_in, bytes_out, duration);
                let r =
                    self.push_asciicast(&asciicast::event_line(elapsed, EventCode::Marker, &label));
                self.note_push(r);
                self.tunnel_audit.push(TunnelAudit {
                    capability: direction.capability_label().to_string(),
                    direction: direction.direction_label().to_string(),
                    target,
                    bytes_in: bytes_in as i64,
                    bytes_out: bytes_out as i64,
                    duration_seconds: duration as i64,
                });
            }
        }
    }

    fn close_channel(&mut self, channel: K) {
        if let Some(ch) = self.channels.remove(&channel) {
            self.drain_channel(ch);
        }
    }

    fn finalize_object(&mut self) -> FinalizedObject {
        self.finalized = true;
        let r = self.ensure_header(0, 0);
        self.note_push(r);
        let channels = std::mem::take(&mut self.channels);
        for (_id, ch) in channels {
            self.drain_channel(ch);
        }
        let capture_failed = self.failed.is_some() || self.seal_remaining().is_err();
        FinalizedObject {
            source: self.spool.close(),
            capture_failed,
            chain_head: self.chain.head_hex(),
            content_digest: self.spool.content_digest_hex(),
            byte_len: self.spool.len() as i64,
            audits: std::mem::take(&mut self.sftp_audit),
            tunnel_audits: std::mem::take(&mut self.tunnel_audit),
        }
    }

    fn push_asciicast(&mut self, line: &[u8]) -> Result<(), String> {
        self.chain.extend(line);
        self.pending_pt.extend_from_slice(line);
        self.seal_ready_frames()
    }

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
        self.push_asciicast(&line)?;
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
fn audit_marker_label(a: &FileTransferAudit) -> Zeroizing<String> {
    // The label carries the transferred path — treat as sensitive; scrub the
    // transient copy once folded into the sealed marker stream.
    Zeroizing::new(
        serde_json::to_string(&serde_json::json!({
            "type": "file-transfer",
            "operation": a.operation,
            "path": a.path,
            "direction": a.direction,
            "size": a.size,
            "sha256": a.sha256,
        }))
        .expect("audit marker serializes"),
    )
}

/// The `<family>.opened` audit marker for a forwarded tunnel. A
/// metadata-only asciicast `m` event — target + direction + capability, never the
/// forwarded bytes. The hash-chain (over the sealed stream) commits to it.
fn tunnel_marker_open(direction: TunnelDirection, target: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "type": format!("{}.opened", direction.audit_family()),
        "direction": direction.direction_label(),
        "capability": direction.capability_label(),
        "target": target,
    }))
    .expect("tunnel marker serializes")
}

fn tunnel_marker_close(
    direction: TunnelDirection,
    target: &str,
    bytes_in: u64,
    bytes_out: u64,
    duration_secs: f64,
) -> String {
    serde_json::to_string(&serde_json::json!({
        "type": format!("{}.closed", direction.audit_family()),
        "direction": direction.direction_label(),
        "capability": direction.capability_label(),
        "target": target,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "duration_secs": duration_secs,
    }))
    .expect("tunnel marker serializes")
}

pub struct Recorder {
    cap: Mutex<Capture<ChannelId>>,
    strict: bool,
    teardown: Option<Handle>,
    torn: AtomicBool,
    abort: Arc<AtomicBool>,
    session_id: String,
    recording_id: String,
    cpauth: Arc<CpAuthClient>,
    uploader: Arc<HttpUploader>,
    upload_max_attempts: u32,
    finalize_max_attempts: u32,
}

impl Recorder {
    /// Bounded retry with backoff on FinalizeRecordingRequest, matching upload_with_retry's
    /// shape. By this point the object is already durably uploaded (or the failure is
    /// recorded some other way); the only remaining risk is losing the metadata commit to a
    /// CP blip at exactly the wrong moment, which -- unlike NotifySessionEnd -- has no
    /// CP-side reaper to self-heal it, so it's worth retrying past a single attempt.
    async fn finalize_recording_with_retry(
        &self,
        req: FinalizeRecordingRequest,
    ) -> Result<FinalizeRecordingResponse, crate::cpauth::CpError> {
        let mut backoff = std::time::Duration::from_millis(200);
        for attempt in 1..=self.finalize_max_attempts {
            match self.cpauth.finalize_recording(req.clone()).await {
                Ok(resp) => return Ok(resp),
                Err(e) if e.is_cp_down() && attempt < self.finalize_max_attempts => {
                    tracing::warn!(session_id = %self.session_id, recording_id = %self.recording_id, attempt, error = %e, "FinalizeRecording failed; retrying");
                }
                Err(e) => return Err(e),
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(std::time::Duration::from_secs(5));
        }
        unreachable!("finalize_max_attempts is clamped to at least 1, and the loop's last iteration always returns")
    }

    async fn upload_with_retry(&self, source: &upload::UploadSource) -> (bool, Option<String>) {
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
                    Ok(version_id) => return (true, version_id),
                    Err(e) if e.is_retryable() && attempt < self.upload_max_attempts => {
                        tracing::warn!(session_id = %self.session_id, recording_id = %self.recording_id, attempt, error = %e, "WORM upload failed; retrying");
                    }
                    Err(e) => {
                        tracing::warn!(session_id = %self.session_id, recording_id = %self.recording_id, attempt, error = %e, "WORM upload failed; no more retries");
                        return (false, None);
                    }
                }
            } else if attempt >= self.upload_max_attempts {
                return (false, None);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(std::time::Duration::from_secs(5));
        }
        (false, None)
    }

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
            return;
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
        self.torn.load(Ordering::SeqCst) || self.abort.load(Ordering::SeqCst)
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
            let (upload_ok, object_version_id, spooled) = match prepared.source.resolve().await {
                Ok(source) => {
                    let (ok, version) = self.upload_with_retry(&source).await;
                    let spooled = match source {
                        upload::UploadSource::File { path, .. } => Some(path),
                        upload::UploadSource::Mem(_) => None,
                    };
                    (ok, version, spooled)
                }
                Err(e) => {
                    tracing::warn!(session_id = %self.session_id, recording_id = %self.recording_id, error = %e, outcome = "recording_failed", "recording object unavailable (spool error); not uploaded");
                    (false, None, None)
                }
            };
            // Unlinking a spool file that grew to gigabytes can block; the recorder
            // never does filesystem work on a runtime worker.
            if let Some(path) = spooled {
                let _ = tokio::task::spawn_blocking(move || std::fs::remove_file(path)).await;
            }
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
                tunnel_audit: prepared.tunnel_audits,
                object_version_id: object_version_id.unwrap_or_default(),
            };
            match self.finalize_recording_with_retry(req).await {
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

/// Builds real [`Recorder`] instances per authorized session.
pub struct RecorderFactoryImpl {
    cpauth: Arc<CpAuthClient>,
    uploader: Arc<HttpUploader>,
    config: RecorderConfig,
}

impl RecorderFactoryImpl {
    /// Builds the factory (fail-closed on misconfigured upload-CA).
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
            let spool_dir = self.config.spool_dir.clone();
            let spool_file = tokio::task::spawn_blocking(move || create_spool_file(spool_dir))
                .await
                .map_err(|_| RecorderError::Setup)?
                .map_err(|_| RecorderError::Setup)?;
            let cap =
                Capture::new(sealer, &self.config, spool_file).map_err(|_| RecorderError::Setup)?;

            Ok(Arc::new(Recorder {
                cap: Mutex::new(cap),
                // A break-glass session forces strict regardless of config (FR-ACC-6);
                // `force_strict` can only tighten the configured strict mode.
                strict: self.config.strict || params.force_strict,
                teardown: params.teardown,
                torn: AtomicBool::new(false),
                abort: params.abort,
                session_id: params.session_id,
                recording_id: resp.recording_id,
                cpauth: self.cpauth.clone(),
                uploader: self.uploader.clone(),
                upload_max_attempts: self.config.upload_max_attempts.max(1),
                finalize_max_attempts: self.config.finalize_max_attempts.max(1),
            }) as Arc<dyn SessionRecorder>)
        })
    }
}

/// The spool file, opened **before** the session starts. The tap that drives the
/// spool is synchronous and runs inline on a runtime worker, so opening a file
/// there would block the executor for as long as the filesystem takes; opening it
/// up front also means an unusable spool refuses the session before a byte flows
/// instead of surfacing mid-stream.
struct SpoolFile {
    file: std::fs::File,
    path: PathBuf,
}

fn create_spool_file(spool_dir: Option<PathBuf>) -> io::Result<SpoolFile> {
    let dir = spool_dir.unwrap_or_else(std::env::temp_dir);
    let path = dir.join(format!("slrec-{}.tmp", random_hex()));
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(&path)?;
    Ok(SpoolFile { file, path })
}

struct CipherSpool {
    digest: Sha256,
    len: u64,
    max_bytes: u64,
    threshold: usize,
    file: Option<SpoolFile>,
    path: PathBuf,
    state: SpoolState,
}

enum SpoolState {
    Mem(Vec<u8>),
    File(FileSink),
}

struct FileSink {
    tx: Option<std::sync::mpsc::Sender<Vec<u8>>>,
    handle: Option<std::thread::JoinHandle<io::Result<()>>>,
    err: Arc<AtomicBool>,
}

/// A spool whose writer has been told to stop. Draining and flushing it blocks, so
/// the join is handed back to the caller to run off the executor rather than done
/// under the capture lock.
enum ClosedSpool {
    Mem(bytes::Bytes),
    Spilled {
        writer: std::thread::JoinHandle<io::Result<()>>,
        path: PathBuf,
        len: u64,
    },
    Broken(&'static str),
}

impl ClosedSpool {
    async fn resolve(self) -> io::Result<upload::UploadSource> {
        match self {
            ClosedSpool::Mem(b) => Ok(upload::UploadSource::Mem(b)),
            ClosedSpool::Broken(e) => Err(io::Error::other(e)),
            ClosedSpool::Spilled { writer, path, len } => {
                tokio::task::spawn_blocking(move || writer.join())
                    .await
                    .map_err(|_| io::Error::other("recording spool join failed"))?
                    .map_err(|_| io::Error::other("recording spool writer panicked"))??;
                Ok(upload::UploadSource::File { path, len })
            }
        }
    }
}

impl CipherSpool {
    fn new(spool_file: SpoolFile, threshold: usize, max_bytes: u64) -> Self {
        Self {
            digest: Sha256::new(),
            len: 0,
            max_bytes,
            threshold,
            path: spool_file.path.clone(),
            file: Some(spool_file),
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

    /// Hands the pre-opened file to a dedicated writer thread. Issues no filesystem
    /// syscall of its own: this runs inline on the byte path.
    fn spill(&mut self) -> io::Result<()> {
        let SpoolFile { file, .. } = self
            .file
            .take()
            .ok_or_else(|| io::Error::other("recording spool file already consumed"))?;
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
        if let SpoolState::Mem(buf) = &mut self.state {
            let buffered = std::mem::take(buf);
            tx.send(buffered)
                .map_err(|_| io::Error::other("recording spool writer gone"))?;
        }
        self.state = SpoolState::File(FileSink {
            tx: Some(tx),
            handle: Some(handle),
            err,
        });
        Ok(())
    }

    fn close(&mut self) -> ClosedSpool {
        let len = self.len;
        let path = self.path.clone();
        match &mut self.state {
            SpoolState::Mem(buf) => ClosedSpool::Mem(bytes::Bytes::from(std::mem::take(buf))),
            SpoolState::File(sink) => {
                drop(sink.tx.take()); // close the channel → writer flushes + exits
                match sink.handle.take() {
                    Some(writer) => ClosedSpool::Spilled { writer, path, len },
                    None => ClosedSpool::Broken("recording spool already finalized"),
                }
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

/// Last-resort cleanup for a session that never reached `finalize` (abort, panic,
/// shutdown). The normal path unlinks off the executor once the upload is done, so
/// this usually finds nothing.
impl Drop for CipherSpool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
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
        let spool_file = create_spool_file(config.spool_dir.clone()).unwrap();
        Capture::new(sealer, config, spool_file).unwrap()
    }

    async fn object_bytes(source: ClosedSpool) -> Vec<u8> {
        match source.resolve().await.unwrap() {
            upload::UploadSource::Mem(b) => b.to_vec(),
            upload::UploadSource::File { path, .. } => std::fs::read(path).unwrap(),
        }
    }

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

    /// A scripted terminal session's recording replays to the exact
    /// original output/keystroke bytes, records a resize, seals under the customer
    /// key, and the hash-chain head commits to the content.
    #[tokio::test]
    async fn terminal_round_trips_through_seal_and_chain() {
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
        let object = object_bytes(fin.source).await;
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

    /// An exec whose command LOOKS like a legacy scp still records
    /// asciicast for ALL I/O — the command string can never suppress mandatory
    /// content capture (the SCP decoder runs additively, not instead of).
    #[tokio::test]
    async fn scp_classified_exec_still_records_asciicast() {
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

        let object = object_bytes(cap.finalize_object().source).await;
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

    /// A forwarded tunnel is recorded METADATA-ONLY — the
    /// sealed object carries an `opened`/`closed` marker pair (target, direction,
    /// capability, byte counts, duration) and NO forwarded byte content, and the
    /// hash-chain commits to them.
    #[tokio::test]
    async fn tunnel_channel_records_metadata_only() {
        let (pub_der, secret) = customer_keypair();
        let config = RecorderConfig::default();
        let mut cap = capture(&config, &pub_der);

        let counters = TunnelCounters::default();
        cap.open_channel(
            7,
            RecChannelKind::Tunnel {
                direction: TunnelDirection::Local,
                target: "db.internal:5432".to_string(),
                counters: counters.clone(),
            },
        )
        .unwrap();
        // Bytes moved by the (real) forward pumps; here we set the shared counters
        // directly, then a stray content tap MUST be ignored (no capture).
        counters.bytes_in.store(4096, Ordering::Relaxed);
        counters.bytes_out.store(8192, Ordering::Relaxed);
        cap.tap(7, TapDirection::Input, None, b"\x00\x01\x02 binary payload")
            .unwrap();
        cap.tap(7, TapDirection::Output, None, b"more opaque bytes")
            .unwrap();
        cap.close_channel(7);

        let object = object_bytes(cap.finalize_object().source).await;
        let header = seal::parse_header(&object).unwrap();
        let key = seal::unseal_data_key(&header, &secret).unwrap();
        let plaintext = seal::decrypt_frames(&object, &header, &key).unwrap();
        let text = String::from_utf8(plaintext).unwrap();

        // No forwarded byte content anywhere in the sealed object.
        assert!(
            !text.contains("binary payload") && !text.contains("opaque bytes"),
            "forwarded bytes MUST NOT be captured"
        );
        let (_hdr, events) = parse_asciicast(text.as_bytes());
        assert_eq!(events.len(), 2, "one opened + one closed marker only");
        assert!(events.iter().all(|(c, _)| c == "m"), "markers only");
        assert!(events[0].1.contains("port_forward.opened"));
        assert!(events[0].1.contains("db.internal:5432"));
        assert!(events[0].1.contains("port_forward_local"));
        assert!(events[1].1.contains("port_forward.closed"));
        assert!(events[1].1.contains("4096") && events[1].1.contains("8192"));
    }

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

    /// An SFTP upload over the tap yields a per-op file-transfer audit
    /// (cleartext copy) AND folds it into the sealed stream as an `m` marker, so
    /// the decrypted object carries the transfer record and no terminal I/O.
    #[tokio::test]
    async fn sftp_channel_produces_file_transfer_audit_only() {
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
        let object = object_bytes(fin.source).await;
        let header = seal::parse_header(&object).unwrap();
        let key = seal::unseal_data_key(&header, &secret).unwrap();
        let plaintext = seal::decrypt_frames(&object, &header, &key).unwrap();
        assert_eq!(recompute_chain(&plaintext), chain_head);
        let (_hdr, events) = parse_asciicast(&plaintext);
        assert_eq!(events.len(), 1, "one file-transfer marker, no terminal I/O");
        assert_eq!(events[0].0, "m");
        assert!(events[0].1.contains("upload"), "marker carries the audit");
    }

    /// An unusable spool must be refused at setup, before the session runs. Strict
    /// mode turns this into "no recording, no session" (`recorder_it.rs`'s
    /// `strict_mode_refuses_when_spool_is_unwritable` drives the same path end to
    /// end), so it must fail here and not somewhere down the byte path.
    #[test]
    fn an_unusable_spool_dir_fails_before_the_session_starts() {
        let err = match create_spool_file(Some(PathBuf::from("/nonexistent/sessionlayer-spill"))) {
            Ok(_) => panic!("an unwritable spool dir must refuse setup"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// The byte path is synchronous and runs inline on a runtime worker, so it must
    /// never issue a filesystem open. Proven by making a new file at the configured
    /// spool path impossible *after* setup: the parent directory is renamed away, so
    /// only the descriptor opened up front can still reach the object.
    #[tokio::test]
    async fn spilling_opens_no_file_because_the_byte_path_may_not_block() {
        let (pub_der, secret) = customer_keypair();
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("spool");
        std::fs::create_dir(&dir).unwrap();
        let config = RecorderConfig {
            spool_dir: Some(dir.clone()),
            spool_memory_threshold_bytes: 4096,
            ..RecorderConfig::default()
        };
        let mut cap = capture(&config, &pub_der);

        let moved = base.path().join("moved");
        std::fs::rename(&dir, &moved).unwrap();
        assert!(
            !dir.exists(),
            "no file can be created at the spool path now"
        );

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
        let payload = vec![b'x'; 200_000];
        cap.tap(1, TapDirection::Output, None, &payload)
            .expect("spilling must not need to open a file");

        let fin = cap.finalize_object();
        assert!(
            matches!(fin.source, ClosedSpool::Spilled { .. }),
            "the payload must have crossed the threshold"
        );
        fin.source.resolve().await.expect("writer drained cleanly");

        // Nothing was lost or reordered on the way to disk: the object still decrypts
        // to the recorded stream under the customer key, and its hash-chain head is
        // recomputable from the decrypted bytes alone.
        let entries: Vec<_> = std::fs::read_dir(&moved).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1, "exactly one spool object");
        let object = std::fs::read(entries[0].path()).unwrap();
        assert_eq!(object.len() as i64, fin.byte_len);
        assert_eq!(fin.content_digest, chain::sha256_hex(&object));
        let header = seal::parse_header(&object).unwrap();
        let key = seal::unseal_data_key(&header, &secret).unwrap();
        let plaintext = seal::decrypt_frames(&object, &header, &key).unwrap();
        assert_eq!(recompute_chain(&plaintext), fin.chain_head);
        let (_, events) = parse_asciicast(&plaintext);
        let recorded: String = events
            .iter()
            .filter(|(code, _)| code == "o")
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(
            recorded,
            String::from_utf8(payload).unwrap(),
            "every spilled byte survives, in order"
        );
    }

    /// Draining the spool writer blocks until the object is flushed, so it must not
    /// happen on a runtime worker. The writer here exits only once an async task has
    /// run: if the join held the thread, that task could never be polled and this
    /// deadlocks rather than merely being slow.
    #[test]
    fn draining_the_spool_writer_leaves_the_runtime_free() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            let _ = release_rx.recv();
            Ok(())
        });
        let closed = ClosedSpool::Spilled {
            writer,
            path: PathBuf::from("/nonexistent/never-read"),
            len: 0,
        };

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let resolved = rt.block_on(async move {
                tokio::spawn(async move {
                    let _ = release_tx.send(());
                });
                closed.resolve().await
            });
            let _ = done_tx.send(resolved.is_ok());
        });

        assert_eq!(
            done_rx.recv_timeout(Duration::from_secs(30)),
            Ok(true),
            "the spool join must run off the runtime worker"
        );
    }

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
        let spool_file = create_spool_file(config.spool_dir.clone()).unwrap();
        let cap = Capture::new(sealer, &config, spool_file).unwrap();
        Recorder {
            cap: Mutex::new(cap),
            strict,
            teardown: None,
            torn: AtomicBool::new(false),
            abort: Arc::new(AtomicBool::new(false)),
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
            finalize_max_attempts: 3,
        }
    }

    #[tokio::test]
    async fn finalize_retries_with_backoff_instead_of_giving_up_on_the_first_cp_blip() {
        let recorder = recorder_for_test(false);
        let req = FinalizeRecordingRequest {
            recording_id: "r".into(),
            status: RecordingStatus::Finalized as i32,
            hash_chain_head: String::new(),
            content_digest: String::new(),
            byte_len: 0,
            sftp_audit: Vec::new(),
            tunnel_audit: Vec::new(),
            object_version_id: String::new(),
        };
        let start = std::time::Instant::now();
        let result = recorder.finalize_recording_with_retry(req).await;
        let elapsed = start.elapsed();
        assert!(
            result.is_err(),
            "an unreachable Control Plane must still surface as an error once retries are exhausted"
        );
        // finalize_max_attempts=3 with 200ms/400ms backoff between attempts: a
        // single-shot call fails in a few ms, so this floor only holds if the retry
        // loop actually slept between attempts instead of giving up after the first.
        assert!(
            elapsed >= std::time::Duration::from_millis(550),
            "expected the bounded retry loop's backoff sleeps to elapse (>=550ms), took {elapsed:?}"
        );
    }

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
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["gw".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        crate::mtls::ClientIdentity {
            cert_pem: cert.pem().into_bytes(),
            key_pem: zeroize::Zeroizing::new(kp.serialize_pem()),
        }
    }
}
