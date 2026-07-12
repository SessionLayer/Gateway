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

use std::sync::Arc;

use russh::server::Handle;
use russh::{ChannelId, ChannelMsg};

use crate::ssh::innerleg::InnerReadHalf;

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
}

/// The Session-Eight recorder: captures nothing. The bridge is fully wired to the
/// seam so S9 drops in without touching the hot path.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullRecorder;

impl RecorderTap for NullRecorder {
    fn tap(&self, _channel: ChannelId, _direction: TapDirection, _ext: Option<u32>, _data: &[u8]) {}
}

/// Relay the inner channel's messages to the outer session until the inner
/// channel closes. Runs on its own task per bridged channel; `outer` is the outer
/// channel id the node output is written back to.
pub(crate) async fn pump_inner_to_outer(
    mut inner: InnerReadHalf,
    handle: Handle,
    outer: ChannelId,
    tap: Arc<dyn RecorderTap>,
) {
    while let Some(msg) = inner.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                tap.tap(outer, TapDirection::Output, None, &data);
                if handle.data(outer, data).await.is_err() {
                    break;
                }
            }
            ChannelMsg::ExtendedData { data, ext } => {
                tap.tap(outer, TapDirection::Output, Some(ext), &data);
                if handle.extended_data(outer, ext, data).await.is_err() {
                    break;
                }
            }
            ChannelMsg::ExitStatus { exit_status } => {
                let _ = handle.exit_status_request(outer, exit_status).await;
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
                let _ = handle.eof(outer).await;
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    // The node closed the channel (or we broke on a write error): close the outer
    // channel so the client's session ends cleanly.
    let _ = handle.close(outer).await;
}
