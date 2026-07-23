//! Port-forwarding + X11 data plane (Session 29, FR-SESS-2).
//!
//! Three forward shapes, each admitted ONLY when the session's signed CP grant
//! carries the matching capability (`port_forward_local`/`_remote`/`x11`) — the
//! same default-deny, lock-aware, resource-bounded gate every other channel gets:
//!
//! - **Local (`ssh -L`)** — a `direct-tcpip` open is dialled FROM THE NODE (via
//!   the inner leg), so a granted forward can only reach what the node itself can
//!   reach (no Gateway-side SSRF escape). See [`crate::ssh::handler`].
//! - **Remote (`ssh -R`)** — the node binds the listener (`tcpip_forward`); a
//!   connection to it opens a `forwarded-tcpip` back to the Gateway, which relays
//!   it to the real client.
//! - **X11 (`ssh -X`/`-Y`)** — the client's `x11-req` is relayed UNCHANGED to the
//!   node; the node's `x11` channel is relayed back to the client.
//!
//! Reverse channels (remote-forward + X11) arrive on the inner (client) leg's
//! [`Handler`](russh::client::Handler) and are dispatched here to the outer leg.
//! Forwarded bytes are opaque — bridged with **no content tap** and recorded
//! **metadata-only** (open/close audit with target, direction, capability, byte
//! counts, duration).

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh::client::Msg as ClientMsg;
use russh::server::{Handle as ServerHandle, Msg as ServerMsg};
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::ssh::bridge::{RecChannelKind, SessionRecorder, TunnelCounters, TunnelDirection};
use crate::ssh::handler::{grant_is_expired, now_epoch_secs, sanitize};
use crate::ssh::innerleg::ReverseOpen;
use crate::ssh::locks::{LockBindings, LockSet};

/// One directional pump of a forwarded (opaque) tunnel half: relay bytes,
/// counting them, until either side closes or the shared abort flag flips (a
/// lock/expiry teardown, §8.4). No content is tapped — tunnels are metadata-only.
async fn pump_tunnel<T>(
    mut read: ChannelReadHalf,
    write: ChannelWriteHalf<T>,
    counter: Arc<AtomicU64>,
    abort: Arc<AtomicBool>,
) where
    T: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    while let Some(msg) = read.wait().await {
        if abort.load(Ordering::SeqCst) {
            break;
        }
        match msg {
            ChannelMsg::Data { data } => {
                counter.fetch_add(data.len() as u64, Ordering::Relaxed);
                if abort.load(Ordering::SeqCst) || write.data_bytes(data).await.is_err() {
                    break;
                }
            }
            ChannelMsg::Eof => {
                let _ = write.eof().await;
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    let _ = write.close().await;
}

/// Reserve one concurrent-tunnel slot against the per-connection cap. Returns
/// `false` (and reserves nothing) when the cap is already reached — a granted
/// forward capability is not a licence for unbounded concurrent fan-out
/// (mirrors S16 `F-proxyjump-dos`). Release with [`AtomicUsize::fetch_sub`].
pub(crate) fn reserve_tunnel_slot(active: &AtomicUsize, max: usize) -> bool {
    if active.fetch_add(1, Ordering::SeqCst) >= max {
        active.fetch_sub(1, Ordering::SeqCst);
        false
    } else {
        true
    }
}

/// Bridge an already-open outer↔inner tunnel channel pair opaquely (both
/// directions), returning ONE task that owns both pumps. Aborting the returned
/// handle (on connection Drop / dispatcher teardown) cancels both pump futures at
/// once — they are run inside this task, not detached, so teardown is deterministic
/// and does not wait for transport close. Byte counts land in `counters` for the
/// close audit.
pub(crate) fn tunnel_bridge_task(
    outer: Channel<ServerMsg>,
    inner: Channel<ClientMsg>,
    counters: TunnelCounters,
    abort: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let (outer_read, outer_write) = outer.split();
    let (inner_read, inner_write) = inner.split();
    tokio::spawn(async move {
        let node_to_client = pump_tunnel(
            inner_read,
            outer_write,
            counters.bytes_out.clone(),
            abort.clone(),
        );
        let client_to_node = pump_tunnel(outer_read, inner_write, counters.bytes_in.clone(), abort);
        // Either half closing tears the tunnel down; select drops (cancels) the peer.
        tokio::select! {
            _ = node_to_client => {}
            _ = client_to_node => {}
        }
    })
}

/// Per-connection dispatcher for node-initiated reverse channels (remote-forward
/// and X11). Spawned once the inner leg is established; owns the outer server
/// handle ([`ServerHandle`]) so it can open the matching outer channel and bridge.
pub(crate) struct ReverseDispatcher {
    pub rx: mpsc::Receiver<ReverseOpen>,
    pub outer: ServerHandle,
    pub recorder: Arc<dyn SessionRecorder>,
    pub lock_set: Arc<LockSet>,
    pub bindings: LockBindings,
    pub abort: Arc<AtomicBool>,
    /// Shared concurrent-tunnel count (local-forward + reverse channels) so a
    /// single connection's forward fan-out is bounded regardless of which side
    /// opened the channel (S16 `F-proxyjump-dos`). Decremented when a tunnel ends.
    pub active_tunnels: Arc<AtomicUsize>,
    pub max_channels: usize,
    /// Whether the session's grant carries `port_forward_remote` — a node-initiated
    /// `forwarded-tcpip` is relayed ONLY when true (fail-closed against a
    /// compromised node opening one unbidden).
    pub allow_remote: bool,
    /// Whether the grant carries `x11` — gates a node-initiated `x11` open likewise.
    pub allow_x11: bool,
    /// The session's signed `grant_expiry` (epoch seconds), shared so a mid-session
    /// re-authorize updates it. A reverse channel opened after expiry is refused —
    /// the same time-box the local-forward path enforces (Part F / §8.4), so a
    /// remote-forward/X11 listener cannot outlive the grant in RunToTtl mode.
    pub grant_expiry: Arc<AtomicI64>,
    /// Conservative grant-expiry skew (seconds) — treat the grant as expired early.
    pub grant_expiry_skew_secs: i64,
    /// Bound on the outer reverse-channel open, so an unresponsive/stalled client
    /// cannot hang the (serial) dispatcher and back-pressure the inner run loop.
    pub op_timeout: Duration,
    pub session_id: String,
    pub source_ip: IpAddr,
}

impl ReverseDispatcher {
    pub(crate) async fn run(mut self) {
        let mut tunnels: JoinSet<()> = JoinSet::new();
        while let Some(open) = self.rx.recv().await {
            // Reap finished tunnels so the JoinSet does not grow unbounded.
            while tunnels.try_join_next().is_some() {}
            self.handle_open(open, &mut tunnels).await;
        }
        // The inner leg closed: abort any live reverse tunnels deterministically.
        tunnels.abort_all();
    }

    async fn handle_open(&mut self, open: ReverseOpen, tunnels: &mut JoinSet<()>) {
        // Fail-closed per direction: a reverse channel is relayed ONLY for a
        // capability the session actually holds — a node must never push an
        // unsolicited forwarded-tcpip/x11 at the client.
        let permitted = match &open {
            ReverseOpen::ForwardedTcpip { .. } => self.allow_remote,
            ReverseOpen::X11 { .. } => self.allow_x11,
        };
        if !permitted {
            tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "reverse_not_granted", "reverse forward refused: capability not granted");
            return; // dropping `open` closes the inner channel
        }
        // Deny-wins: a lock or teardown in flight refuses new reverse channels (the
        // same lock-set match every other channel-open runs, §8.4).
        if self.abort.load(Ordering::SeqCst) || self.lock_set.matching(&self.bindings).is_some() {
            tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "locked_or_torn", "reverse forward refused (lock/teardown)");
            return; // dropping `open` closes the inner channel
        }
        // Time-box: a reverse channel opened after the signed grant expired is
        // refused, matching the local-forward path — so a node-bound -R listener
        // (or X11) cannot outlive the grant in the default RunToTtl mode.
        let ge = self.grant_expiry.load(Ordering::SeqCst);
        if grant_is_expired(now_epoch_secs(), ge, self.grant_expiry_skew_secs) {
            tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "grant_expired", "reverse forward refused (grant expired)");
            return;
        }
        // Per-connection concurrent-tunnel cap (bounds reverse fan-out from one grant).
        if !reserve_tunnel_slot(&self.active_tunnels, self.max_channels) {
            tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "channel_cap", "per-connection tunnel cap exceeded; refusing reverse forward");
            return;
        }

        let (inner, direction, target, outer) = match open {
            ReverseOpen::ForwardedTcpip {
                channel,
                connected_address,
                connected_port,
                originator_address,
                originator_port,
            } => {
                let outer = tokio::time::timeout(
                    self.op_timeout,
                    self.outer.channel_open_forwarded_tcpip(
                        connected_address.clone(),
                        connected_port,
                        originator_address.clone(),
                        originator_port,
                    ),
                )
                .await;
                let target = format!(
                    "{}:{} (from {}:{})",
                    connected_address, connected_port, originator_address, originator_port
                );
                (channel, TunnelDirection::Remote, target, outer)
            }
            ReverseOpen::X11 {
                channel,
                originator_address,
                originator_port,
            } => {
                let outer = tokio::time::timeout(
                    self.op_timeout,
                    self.outer
                        .channel_open_x11(originator_address.clone(), originator_port),
                )
                .await;
                let target = format!("x11 (from {}:{})", originator_address, originator_port);
                (channel, TunnelDirection::X11, target, outer)
            }
        };

        let outer = match outer {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                self.active_tunnels.fetch_sub(1, Ordering::SeqCst);
                tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, error = %e, outcome = "channel_open_failed", "outer reverse channel open refused by client");
                return;
            }
            Err(_) => {
                self.active_tunnels.fetch_sub(1, Ordering::SeqCst);
                tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "channel_open_timeout", "outer reverse channel open timed out (client unresponsive)");
                return;
            }
        };

        let counters = TunnelCounters::default();
        let outer_id = outer.id();
        self.recorder.open_channel(
            outer_id,
            RecChannelKind::Tunnel {
                direction,
                target: sanitize(&target),
                counters: counters.clone(),
            },
        );
        tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, direction = direction.direction_label(), capability = direction.capability_label(), outcome = "forward_opened", "reverse forward bridged");

        let bridge = tunnel_bridge_task(outer, inner, counters, self.abort.clone());
        let recorder = self.recorder.clone();
        let active = self.active_tunnels.clone();
        tunnels.spawn(async move {
            let _ = bridge.await;
            recorder.close_channel(outer_id);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_slot_reservation_bounds_concurrency() {
        let active = AtomicUsize::new(0);
        // Reserve up to the cap, then refuse; a release re-opens exactly one slot.
        assert!(reserve_tunnel_slot(&active, 2));
        assert!(reserve_tunnel_slot(&active, 2));
        assert!(!reserve_tunnel_slot(&active, 2), "cap reached → refuse");
        assert_eq!(
            active.load(Ordering::SeqCst),
            2,
            "a refusal reserves nothing"
        );
        active.fetch_sub(1, Ordering::SeqCst);
        assert!(reserve_tunnel_slot(&active, 2), "a released slot reopens");
        assert_eq!(active.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn direction_labels_are_stable() {
        assert_eq!(
            TunnelDirection::Local.capability_label(),
            "port_forward_local"
        );
        assert_eq!(
            TunnelDirection::Remote.capability_label(),
            "port_forward_remote"
        );
        assert_eq!(TunnelDirection::X11.capability_label(), "x11");
        assert_eq!(TunnelDirection::Local.audit_family(), "port_forward");
        assert_eq!(TunnelDirection::X11.audit_family(), "x11_forward");
    }
}
