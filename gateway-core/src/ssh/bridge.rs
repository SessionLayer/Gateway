//! Byte bridge with recorder tap (no plaintext retained or logged at this seam); backpressure on outer WRITE half.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use russh::server::{Handle, Msg as ServerMsg};
use russh::{ChannelId, ChannelMsg, ChannelWriteHalf};

use crate::ssh::innerleg::InnerReadHalf;

/// Backpressure: `data_bytes` blocks on the client's channel window (real end-to-end).
pub(crate) type OuterWriteHalf = ChannelWriteHalf<ServerMsg>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapDirection {
    Input,
    Output,
}

/// The recording tap seam. Implementations MUST be cheap and
/// non-blocking (the bridge is the Tier-0 hot path) and MUST NOT log plaintext.
pub trait RecorderTap: Send + Sync {
    fn tap(&self, channel: ChannelId, direction: TapDirection, ext: Option<u32>, data: &[u8]);

    fn resize(&self, _channel: ChannelId, _cols: u16, _rows: u16) {}

    /// Whether a strict-mode recording failure has torn (or is tearing) the session
    /// down. The output pump stops forwarding node output the moment recording
    /// fails, so no un-recorded bytes reach the client during the async disconnect
    /// (fail closed, mirrors the input path).
    fn should_abort(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NullRecorder;

impl RecorderTap for NullRecorder {
    fn tap(&self, _channel: ChannelId, _direction: TapDirection, _ext: Option<u32>, _data: &[u8]) {}
}

#[derive(Debug, Clone)]
pub struct ScpMode {
    pub upload: bool,
    pub target: Vec<u8>,
}

/// Tunnel direction; metadata-only (NEVER content-captured).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelDirection {
    Local,
    Remote,
    X11,
}

impl TunnelDirection {
    pub fn capability_label(self) -> &'static str {
        match self {
            TunnelDirection::Local => "port_forward_local",
            TunnelDirection::Remote => "port_forward_remote",
            TunnelDirection::X11 => "x11",
        }
    }
    pub fn audit_family(self) -> &'static str {
        match self {
            TunnelDirection::X11 => "x11_forward",
            _ => "port_forward",
        }
    }
    pub fn direction_label(self) -> &'static str {
        match self {
            TunnelDirection::Local => "local",
            TunnelDirection::Remote => "remote",
            TunnelDirection::X11 => "x11",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TunnelCounters {
    pub bytes_in: Arc<std::sync::atomic::AtomicU64>,
    pub bytes_out: Arc<std::sync::atomic::AtomicU64>,
}

/// How a bridged channel's plaintext is captured: shell/exec as asciicast v2 (ALWAYS); SFTP decode-only.
#[derive(Debug, Clone)]
pub enum RecChannelKind {
    /// Interactive shell or exec: asciicast v2 (output + input).
    Terminal {
        command: Option<Vec<u8>>,
        scp: Option<ScpMode>,
        cols: u16,
        rows: u16,
    },
    /// The SFTP subsystem: per-operation file-transfer audit only.
    Sftp,
    /// Forwarded tunnel (metadata-only; NEVER the forwarded bytes).
    Tunnel {
        direction: TunnelDirection,
        target: String,
        counters: TunnelCounters,
    },
}

pub struct RecordingParams {
    pub recording_token: String,
    pub session_id: String,
    pub node_id: String,
    pub principal: String,
    pub teardown: Option<Handle>,
    pub abort: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Force strict recording for THIS session regardless of the recorder config: it can only tighten, never loosen, the configured strict mode.
    pub force_strict: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RecorderError {
    #[error("recording registration failed")]
    Begin,
    #[error("no customer encryption key configured for the recording")]
    NoCustomerKey,
    #[error("recorder setup failed")]
    Setup,
}

pub trait SessionRecorder: RecorderTap {
    fn open_channel(&self, channel: ChannelId, kind: RecChannelKind);

    fn close_channel(&self, channel: ChannelId);

    fn is_torn_down(&self) -> bool;

    fn finalize(self: Arc<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

pub type BeginFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Arc<dyn SessionRecorder>, RecorderError>> + Send + 'a>>;

pub trait RecorderFactory: Send + Sync {
    fn begin(&self, params: RecordingParams) -> BeginFuture<'_>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NullRecorderFactory;

impl RecorderFactory for NullRecorderFactory {
    fn begin(&self, _params: RecordingParams) -> BeginFuture<'_> {
        Box::pin(async { Ok(Arc::new(NullSessionRecorder) as Arc<dyn SessionRecorder>) })
    }
}

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

/// Non-strict degraded path only: session proceeds UNRECORDED, logged loudly.
pub fn disabled_recorder() -> Arc<dyn SessionRecorder> {
    Arc::new(NullSessionRecorder)
}

fn should_stop(abort: &std::sync::atomic::AtomicBool, tap: &dyn RecorderTap) -> bool {
    abort.load(std::sync::atomic::Ordering::SeqCst) || tap.should_abort()
}

pub(crate) async fn pump_inner_to_outer(
    mut inner: InnerReadHalf,
    outer_write: OuterWriteHalf,
    handle: Handle,
    outer: ChannelId,
    tap: Arc<dyn RecorderTap>,
    abort: Arc<std::sync::atomic::AtomicBool>,
) {
    while let Some(msg) = inner.wait().await {
        if should_stop(&abort, tap.as_ref()) {
            break;
        }
        match msg {
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

    #[test]
    fn output_pump_stops_on_shared_abort_even_when_tap_never_aborts() {
        let abort = AtomicBool::new(false);
        let disabled = FixedTap(false);
        assert!(!should_stop(&abort, &disabled));
        abort.store(true, Ordering::SeqCst);
        assert!(should_stop(&abort, &disabled));
    }

    #[test]
    fn output_pump_stops_on_recorder_tap_abort() {
        assert!(should_stop(&AtomicBool::new(false), &FixedTap(true)));
    }
}
