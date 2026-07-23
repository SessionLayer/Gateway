//! The byte bridge (Part D) and the recorder tap seam (§12.1).
//!
//! Once the inner leg is up, each bridged channel runs two directions:
//!
//! - **outer → inner** (user keystrokes / uploads): driven from the outer
//!   [`Handler::data`](russh::server::Handler::data) callback, which writes to the
//!   inner channel's write half (see `handler.rs`). This is the `i` (input)
//!   stream for the recorder.
//! - **inner → outer** (node output): [`pump_inner_to_outer`] drives the inner
//!   channel's read half and relays each message to the outer session's
//!   [`Handle`](russh::server::Handle) — data, extended data, exit status/signal,
//!   eof, close. This is the `o` (output) stream for the recorder.
//!
//! **Recorder tap seam (S9 attaches here).** Every plaintext chunk in both
//! directions is offered to a [`RecorderTap`] *before* it is forwarded. Session
//! Eight ships only [`NullRecorder`] (no capture, no plaintext retained/logged);
//! Session Nine implements asciicast v2 + SFTP/SCP decode + the hash-chained WORM
//! store behind this exact trait, with **no change to the bridge**.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use russh::server::{Handle, Msg as ServerMsg};
use russh::{ChannelId, ChannelMsg, ChannelWriteHalf};

use crate::ssh::innerleg::InnerReadHalf;

/// The outer (client-facing) channel write half. Its `data_bytes` blocks on the
/// client's channel window (real end-to-end backpressure) — unlike `Handle::data`,
/// which buffers without bound (F-bridge-backpressure-1).
pub(crate) type OuterWriteHalf = ChannelWriteHalf<ServerMsg>;

/// Direction of a plaintext chunk at the tap (asciicast v2 event kinds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapDirection {
    /// User → node (keystrokes, uploads): asciicast `i`.
    Input,
    /// Node → user (output): asciicast `o`.
    Output,
}

/// The recording tap seam (Design §12.1). The bridge offers every plaintext
/// chunk here; Session Nine attaches the real recorder. Implementations MUST be
/// cheap and non-blocking (the bridge is the Tier-0 hot path) and MUST NOT log
/// plaintext.
pub trait RecorderTap: Send + Sync {
    /// A plaintext chunk on `channel` flowing in `direction`. `ext` is the SSH
    /// extended-data code for stderr (`Some(1)`), else `None` for the primary
    /// data stream.
    fn tap(&self, channel: ChannelId, direction: TapDirection, ext: Option<u32>, data: &[u8]);

    /// A terminal resize on `channel` (from `window_change_request` / `pty_request`)
    /// → an asciicast `r` event. Defaulted so [`NullRecorder`] and non-recording
    /// call sites need not implement it (additive, S9).
    fn resize(&self, _channel: ChannelId, _cols: u16, _rows: u16) {}

    /// Whether a strict-mode recording failure has torn (or is tearing) the session
    /// down. The output pump checks this and STOPS forwarding node output the moment
    /// recording fails, so no un-recorded bytes reach the client during the async
    /// disconnect (fail closed, mirrors the input path). Defaulted to `false`.
    fn should_abort(&self) -> bool {
        false
    }
}

/// The Session-Eight recorder: captures nothing. The bridge is fully wired to the
/// seam so S9 drops in without touching the hot path.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullRecorder;

impl RecorderTap for NullRecorder {
    fn tap(&self, _channel: ChannelId, _direction: TapDirection, _ext: Option<u32>, _data: &[u8]) {}
}

/// A legacy scp-over-exec transfer mode, decoded ADDITIVELY on a terminal channel.
#[derive(Debug, Clone)]
pub struct ScpMode {
    /// `true` for `scp -t` (client→node upload), `false` for `scp -f` (download).
    pub upload: bool,
    /// The scp target path argument (from the exec command line), for the audit.
    pub target: Vec<u8>,
}

/// The direction/kind of a forwarded (tunnel) channel, for the metadata-only
/// audit (Session 29, FR-SESS-2). Forwarded bytes are arbitrary/binary with no
/// universal decode, so a tunnel is NEVER content-captured — only its open/close
/// metadata is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelDirection {
    /// `ssh -L`: client → node-dialled `host:port` (`direct-tcpip`).
    Local,
    /// `ssh -R`: a node-bound listener → client (`forwarded-tcpip`).
    Remote,
    /// `ssh -X`/`-Y`: an X11 channel the node opened back to the client.
    X11,
}

impl TunnelDirection {
    /// The granted capability label for the audit event (stable, non-secret).
    pub fn capability_label(self) -> &'static str {
        match self {
            TunnelDirection::Local => "port_forward_local",
            TunnelDirection::Remote => "port_forward_remote",
            TunnelDirection::X11 => "x11",
        }
    }

    /// The audit-event family for the open/close marker `type`.
    pub fn audit_family(self) -> &'static str {
        match self {
            TunnelDirection::X11 => "x11_forward",
            _ => "port_forward",
        }
    }

    /// The direction label recorded in the audit event.
    pub fn direction_label(self) -> &'static str {
        match self {
            TunnelDirection::Local => "local",
            TunnelDirection::Remote => "remote",
            TunnelDirection::X11 => "x11",
        }
    }
}

/// Shared byte counters for a live tunnel, updated by the two directional pumps
/// and read at close to emit the `*.closed` audit event. Cheap to clone (`Arc`s).
#[derive(Debug, Clone, Default)]
pub struct TunnelCounters {
    /// Client → node bytes (`ssh -L`/`-R` payload, X11 requests).
    pub bytes_in: Arc<std::sync::atomic::AtomicU64>,
    /// Node → client bytes.
    pub bytes_out: Arc<std::sync::atomic::AtomicU64>,
}

/// How a bridged channel's plaintext is captured (Design §12.1). The handler
/// classifies the channel at open time so the tap routes its bytes.
///
/// **Every shell/exec channel is ALWAYS recorded as asciicast v2** — the exec
/// command string can never suppress mandatory content capture (a legacy
/// scp-over-exec is decoded for file-transfer audit *in addition to*, never
/// instead of, the asciicast stream). Only the sftp SUBSYSTEM (the node runs
/// `sftp-server`, no shell) is decode-only.
#[derive(Debug, Clone)]
pub enum RecChannelKind {
    /// Interactive shell or exec: asciicast v2 (output + input). `command` is the
    /// exec command line (recorded as an input event); `scp`, when set, additively
    /// decodes a legacy scp-over-exec transfer; `cols`/`rows` seed the asciicast
    /// header (0 ⇒ default 80×24).
    Terminal {
        /// The exec command line, if this is an exec (not an interactive shell).
        command: Option<Vec<u8>>,
        /// Additive legacy scp-over-exec decode, when the exec is `scp -t`/`-f`.
        scp: Option<ScpMode>,
        /// PTY columns (0 ⇒ unknown → 80).
        cols: u16,
        /// PTY rows (0 ⇒ unknown → 24).
        rows: u16,
    },
    /// The SFTP subsystem: decoded into per-operation file-transfer audit only.
    Sftp,
    /// A forwarded TCP/X11 tunnel (Session 29, FR-SESS-2): **metadata-only**. The
    /// recorder emits `<family>.opened` on open and `<family>.closed` on close
    /// (with the byte counts from `counters` + duration) — NEVER the forwarded
    /// bytes. `target` is the dial/bind/originator descriptor for the audit.
    Tunnel {
        /// Which forward shape (`ssh -L`/`-R`/X11) this tunnel is.
        direction: TunnelDirection,
        /// The dial/bind/originator descriptor recorded in the audit event.
        target: String,
        /// Shared byte counters, read at close for the `*.closed` audit.
        counters: TunnelCounters,
    },
}

/// The inputs [`RecorderFactory::begin`] needs to register + key a recording. The
/// `recording_token` is the single-use per-request authority minted by Authorize
/// ALLOW (§15); `teardown` lets a strict-mode mid-session failure drop the whole
/// SSH connection (fail closed).
pub struct RecordingParams {
    /// Single-use Recording.BeginRecording authority (from Authorize ALLOW).
    pub recording_token: String,
    /// The SessionLayer session id (1:1 with the recording; audit correlation).
    pub session_id: String,
    /// The target node id (advisory correlation; the token is authoritative).
    pub node_id: String,
    /// The chosen inner-leg principal (advisory correlation).
    pub principal: String,
    /// The connection handle a strict-mode continuation failure disconnects. The
    /// real handler always supplies it; `None` is only for a recorder driven
    /// directly by a unit test.
    pub teardown: Option<Handle>,
    /// Shared session-abort flag (Session Ten). A lock-triggered teardown flips it
    /// so `should_abort()` returns true and the bridge stops forwarding plaintext
    /// at once — the same immediate-stop discipline as a strict-mode failure.
    pub abort: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Force strict recording for THIS session regardless of the recorder config's
    /// `strict` (Session Thirteen, FR-ACC-6): a break-glass session dies if its
    /// recording fails. OR'd into the built recorder's strict flag; it can only
    /// tighten, never loosen, the configured strict mode.
    pub force_strict: bool,
}

/// A fail-closed recorder setup failure. The user only ever sees the generic
/// [`RecordingUnavailable`](crate::ssh::outcome::SshOutcome::RecordingUnavailable);
/// these variants exist for the operator log.
#[derive(Debug, thiserror::Error)]
pub enum RecorderError {
    /// BeginRecording was refused / unreachable (fail closed).
    #[error("recording registration failed")]
    Begin,
    /// The CP returned no usable customer encryption key. Keystroke capture is
    /// always on, so encryption is mandatory (FR-AUD-2) — refuse rather than store
    /// keystrokes in the clear.
    #[error("no customer encryption key configured for the recording")]
    NoCustomerKey,
    /// The customer key or seal parameters could not be set up (unsupported
    /// algorithm, malformed key, spool error).
    #[error("recorder setup failed")]
    Setup,
}

/// A per-connection recorder, built once by [`RecorderFactory::begin`] when a
/// session is authorized. It is a [`RecorderTap`] (fed by the bridge, both
/// directions) plus the lifecycle the handler drives: channel classification and
/// finalize. One recorder is 1:1 with the SSH session (Design §12, Part G).
pub trait SessionRecorder: RecorderTap {
    /// Classify a bridged channel so the tap routes its bytes.
    fn open_channel(&self, channel: ChannelId, kind: RecChannelKind);

    /// A bridged channel closed — flush its per-channel decoder (emit any pending
    /// file-transfer audit).
    fn close_channel(&self, channel: ChannelId);

    /// Whether a strict-mode continuation failure has (already) torn the session
    /// down. The handler checks this to avoid bridging further bytes.
    fn is_torn_down(&self) -> bool;

    /// Flush, seal the final frame, upload the ciphertext object, and commit the
    /// hash-chain + audit via FinalizeRecording. Consumes the `Arc`; the caller
    /// spawns this so it never blocks connection teardown.
    fn finalize(self: Arc<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// The future returned by [`RecorderFactory::begin`].
pub type BeginFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Arc<dyn SessionRecorder>, RecorderError>> + Send + 'a>>;

/// Builds a per-session [`SessionRecorder`] when a session is authorized. One
/// shared factory (holding the CP client + recorder config + HTTP uploader) is
/// cloned into every connection's [`HandlerDeps`](crate::ssh::handler::HandlerDeps).
pub trait RecorderFactory: Send + Sync {
    /// Register + key a recording for an authorized session (fail-closed). In
    /// strict mode the handler refuses the session on `Err`.
    fn begin(&self, params: RecordingParams) -> BeginFuture<'_>;
}

/// A recorder factory that records nothing (the Session-Eight behaviour). Used by
/// tests that exercise the SSH legs without the recorder, and as the scaffold
/// default. **Not for production** — recording is mandatory (FR-AUD-1).
#[derive(Debug, Clone, Copy, Default)]
pub struct NullRecorderFactory;

impl RecorderFactory for NullRecorderFactory {
    fn begin(&self, _params: RecordingParams) -> BeginFuture<'_> {
        Box::pin(async { Ok(Arc::new(NullSessionRecorder) as Arc<dyn SessionRecorder>) })
    }
}

/// The no-op per-session recorder returned by [`NullRecorderFactory`].
#[derive(Debug, Clone, Copy, Default)]
struct NullSessionRecorder;

impl RecorderTap for NullSessionRecorder {
    fn tap(&self, _channel: ChannelId, _direction: TapDirection, _ext: Option<u32>, _data: &[u8]) {}
}

impl SessionRecorder for NullSessionRecorder {
    fn open_channel(&self, _channel: ChannelId, _kind: RecChannelKind) {}
    fn close_channel(&self, _channel: ChannelId) {}
    fn is_torn_down(&self) -> bool {
        false
    }
    fn finalize(self: Arc<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }
}

/// A no-op per-session recorder. Used only for the **non-strict degraded path**
/// (a recording setup failure with `strict = false`): the session proceeds
/// UNRECORDED, logged loudly. Never used in strict mode.
pub fn disabled_recorder() -> Arc<dyn SessionRecorder> {
    Arc::new(NullSessionRecorder)
}

/// Whether the inner→outer pump must stop forwarding node output: the shared
/// session-abort flag (a lock/expiry teardown, §8.4) OR the recorder tap (torn /
/// strict-recording failure). The flag is checked DIRECTLY — not only through the
/// tap — because the non-strict `disabled_recorder()` answers `should_abort()==false`,
/// so the tap alone would keep relaying post-lock node output on a degraded session
/// (F-bridge-output-teardown-1).
fn should_stop(abort: &std::sync::atomic::AtomicBool, tap: &dyn RecorderTap) -> bool {
    abort.load(std::sync::atomic::Ordering::SeqCst) || tap.should_abort()
}

/// Relay the inner channel's messages to the outer session until the inner
/// channel closes. Runs on its own task per bridged channel; `outer` is the outer
/// channel id the node output is written back to.
pub(crate) async fn pump_inner_to_outer(
    mut inner: InnerReadHalf,
    outer_write: OuterWriteHalf,
    handle: Handle,
    outer: ChannelId,
    tap: Arc<dyn RecorderTap>,
    abort: Arc<std::sync::atomic::AtomicBool>,
) {
    while let Some(msg) = inner.wait().await {
        // Fail closed: a lock/expiry teardown flips the shared abort flag, or strict
        // recording fails → STOP forwarding node output immediately (no bytes reach
        // the client while the disconnect is in flight; mirrors the input path).
        if should_stop(&abort, tap.as_ref()) {
            break;
        }
        match msg {
            // The bulk streams go through the outer WRITE HALF, whose `data_bytes`
            // blocks on the client's channel window → the node is throttled to the
            // client's receive rate (no unbounded buffering, F-bridge-backpressure-1).
            ChannelMsg::Data { data } => {
                tap.tap(outer, TapDirection::Output, None, &data);
                if should_stop(&abort, tap.as_ref()) || outer_write.data_bytes(data).await.is_err()
                {
                    break;
                }
            }
            ChannelMsg::ExtendedData { data, ext } => {
                tap.tap(outer, TapDirection::Output, Some(ext), &data);
                if should_stop(&abort, tap.as_ref())
                    || outer_write.extended_data_bytes(ext, data).await.is_err()
                {
                    break;
                }
            }
            // With the data path backpressured the outbound backlog stays ~empty,
            // so these control messages do not overtake buffered stdout.
            ChannelMsg::ExitStatus { exit_status } => {
                let _ = outer_write.exit_status(exit_status).await;
            }
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                let _ = handle
                    .exit_signal_request(outer, signal_name, core_dumped, error_message, lang_tag)
                    .await;
            }
            ChannelMsg::Eof => {
                let _ = outer_write.eof().await;
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    // The node closed the channel (or we broke on a write error): close the outer
    // channel so the client's session ends cleanly.
    let _ = outer_write.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FixedTap(bool);
    impl RecorderTap for FixedTap {
        fn tap(&self, _c: ChannelId, _d: TapDirection, _e: Option<u32>, _data: &[u8]) {}
        fn should_abort(&self) -> bool {
            self.0
        }
    }

    // F-bridge-output-teardown-1: the non-strict disabled_recorder() answers
    // should_abort()==false, so the output pump must stop on the SHARED session-abort
    // flag (a lock/expiry teardown) — else it relays post-lock node output on a
    // degraded/unrecorded session. Pre-fix the pump checked only the tap → this was
    // false and node output kept flowing.
    #[test]
    fn output_pump_stops_on_shared_abort_even_when_tap_never_aborts() {
        let abort = AtomicBool::new(false);
        let disabled = FixedTap(false);
        assert!(!should_stop(&abort, &disabled)); // flowing while un-locked
        abort.store(true, Ordering::SeqCst); // lock/expiry teardown fires
        assert!(should_stop(&abort, &disabled)); // MUST stop
    }

    // Control: the strict recorder's own torn/abort signal still stops the pump.
    #[test]
    fn output_pump_stops_on_recorder_tap_abort() {
        assert!(should_stop(&AtomicBool::new(false), &FixedTap(true)));
    }
}
