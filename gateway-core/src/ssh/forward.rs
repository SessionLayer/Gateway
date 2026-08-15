//! Port-forwarding + X11 data plane: default-deny, lock-aware, resource-bounded — a forward
//! is permitted only when the session's grant carries the matching capability.
//! Local forward (`-L`): dialled from node (no Gateway-side SSRF). Remote (`-R`): node binds listener.
//! X11 (`-Y`): request relayed unchanged; bytes opaque, metadata-only audit (open/close + counts/duration).

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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

pub(crate) fn reserve_tunnel_slot(active: &AtomicUsize, max: usize) -> bool {
    if active.fetch_add(1, Ordering::SeqCst) >= max {
        active.fetch_sub(1, Ordering::SeqCst);
        false
    } else {
        true
    }
}

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

pub(crate) struct ReverseDispatcher {
    pub rx: mpsc::Receiver<ReverseOpen>,
    pub outer: ServerHandle,
    pub recorder: Arc<dyn SessionRecorder>,
    pub lock_set: Arc<LockSet>,
    pub bindings: Arc<Mutex<LockBindings>>,
    pub abort: Arc<AtomicBool>,
    pub active_tunnels: Arc<AtomicUsize>,
    pub max_channels: usize,
    // Shared with the handler, not frozen copies: a mid-session re-authorize that
    // narrows the capability set must refuse subsequent reverse opens, the same way
    // a re-authorize already retightens `bindings` and `grant_expiry` below.
    pub allow_remote: Arc<AtomicBool>,
    pub allow_x11: Arc<AtomicBool>,
    pub grant_expiry: Arc<AtomicI64>,
    pub grant_expiry_skew_secs: i64,
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
        tunnels.abort_all();
    }

    async fn handle_open(&mut self, open: ReverseOpen, tunnels: &mut JoinSet<()>) {
        let permitted = match &open {
            ReverseOpen::ForwardedTcpip { .. } => self.allow_remote.load(Ordering::SeqCst),
            ReverseOpen::X11 { .. } => self.allow_x11.load(Ordering::SeqCst),
        };
        if !permitted {
            tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "reverse_not_granted", "reverse forward refused: capability not granted");
            return; // dropping `open` closes the inner channel
        }
        // Deny-wins: a lock or teardown in flight refuses new reverse channels (the
        // same lock-set match every other channel-open runs), against the
        // LIVE bindings (guard scoped: never held across an await).
        let locked = {
            let b = self.bindings.lock().unwrap();
            self.lock_set.matching(&b).is_some()
        };
        if self.abort.load(Ordering::SeqCst) || locked {
            tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "locked_or_torn", "reverse forward refused (lock/teardown)");
            return; // dropping `open` closes the inner channel
        }
        let ge = self.grant_expiry.load(Ordering::SeqCst);
        if grant_is_expired(now_epoch_secs(), ge, self.grant_expiry_skew_secs) {
            tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "grant_expired", "reverse forward refused (grant expired)");
            return;
        }
        if !reserve_tunnel_slot(&self.active_tunnels, self.max_channels) {
            tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "channel_cap", "per-connection tunnel cap exceeded; refusing reverse forward");
            return;
        }

        // Spawn the outer open call rather than awaiting it inline, so a timeout
        // can walk away from it without dropping it: the vendored server has
        // already allocated a ChannelId and wired it into its own session-scoped
        // channel table the instant CHANNEL_OPEN is dispatched
        // (server/session.rs `channel_open_generic`), well before this future
        // would resolve. Dropping the future here would abandon the receiver
        // that is the only way we ever learn that id, orphaning the entry for
        // the life of the connection (M5). `race_with_reclaim` below is the
        // reusable shape that keeps it alive across the timeout.
        let (inner, direction, target, open_task) = match open {
            ReverseOpen::ForwardedTcpip {
                channel,
                connected_address,
                connected_port,
                originator_address,
                originator_port,
            } => {
                let target = format!(
                    "{}:{} (from {}:{})",
                    connected_address, connected_port, originator_address, originator_port
                );
                let outer = self.outer.clone();
                let task = tokio::spawn(async move {
                    outer
                        .channel_open_forwarded_tcpip(
                            connected_address,
                            connected_port,
                            originator_address,
                            originator_port,
                        )
                        .await
                });
                (channel, TunnelDirection::Remote, target, task)
            }
            ReverseOpen::X11 {
                channel,
                originator_address,
                originator_port,
            } => {
                let target = format!("x11 (from {}:{})", originator_address, originator_port);
                let outer = self.outer.clone();
                let task = tokio::spawn(async move {
                    outer
                        .channel_open_x11(originator_address, originator_port)
                        .await
                });
                (channel, TunnelDirection::X11, target, task)
            }
        };

        // Timed out waiting on the client's confirmation/failure: `on_late` runs
        // later, in the background, if the call eventually resolves. Do NOT close
        // over `return`-ing from here early -- the tunnel slot stays reserved
        // until the entry is actually reclaimed (closed, refused, or the
        // connection tears down and the receiver sees the sender drop), so a
        // stalling/hostile peer can't outrun the reservation and rack up
        // unbounded leaked entries -- the same cap that bounds live tunnels now
        // also bounds pending-late ones.
        let active_on_late = self.active_tunnels.clone();
        let outer = match race_with_reclaim(self.op_timeout, open_task, move |result| {
            if let Ok(channel) = result {
                tokio::spawn(async move {
                    let _ = channel.close().await;
                });
            }
            active_on_late.fetch_sub(1, Ordering::SeqCst);
        })
        .await
        {
            RaceOutcome::Resolved(Ok(c)) => c,
            RaceOutcome::Resolved(Err(e)) => {
                self.active_tunnels.fetch_sub(1, Ordering::SeqCst);
                tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, error = %e, outcome = "channel_open_failed", "outer reverse channel open refused by client");
                return;
            }
            RaceOutcome::Panicked(join_err) => {
                // The spawned open call panicked, not the protocol call failing;
                // treat it the same as a refusal rather than propagating a panic
                // out of the dispatcher loop.
                self.active_tunnels.fetch_sub(1, Ordering::SeqCst);
                tracing::error!(source_ip = %self.source_ip, session_id = %self.session_id, error = %join_err, outcome = "channel_open_task_panic", "outer reverse channel-open task panicked");
                return;
            }
            RaceOutcome::TimedOut => {
                tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "channel_open_timeout", "outer reverse channel open timed out (client unresponsive); reclaiming in background");
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

/// Outcome of [`race_with_reclaim`]: distinguishes a normal result from the
/// task itself panicking from a timeout, since callers handle each differently.
enum RaceOutcome<T> {
    Resolved(T),
    Panicked(tokio::task::JoinError),
    TimedOut,
}

/// Race a spawned `task` against `timeout` without abandoning it on elapse.
///
/// A bare `tokio::time::timeout(dur, future).await` drops `future` the instant
/// it elapses. For `handle_open`'s outer channel-open call that is
/// catastrophic (M5): the vendored server has already allocated a `ChannelId`
/// and wired it into its own session-scoped channel table before this could
/// ever resolve, so dropping the future here abandons the only receiver that
/// would ever learn that id -- a real, permanently leaked resource, not a
/// harmless cancellation.
///
/// Passing a `JoinHandle` instead of the raw future avoids that: the
/// underlying task keeps running even after `timeout` walks away from
/// `&mut task`. On elapse this spawns a reclaimer that keeps polling it and
/// hands a late `Ok` to `on_late` instead of discarding it.
async fn race_with_reclaim<T: Send + 'static>(
    timeout: Duration,
    mut task: tokio::task::JoinHandle<T>,
    on_late: impl FnOnce(T) + Send + 'static,
) -> RaceOutcome<T> {
    match tokio::time::timeout(timeout, &mut task).await {
        Ok(Ok(value)) => RaceOutcome::Resolved(value),
        Ok(Err(join_err)) => RaceOutcome::Panicked(join_err),
        Err(_) => {
            tokio::spawn(async move {
                if let Ok(value) = task.await {
                    on_late(value);
                }
            });
            RaceOutcome::TimedOut
        }
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

    /// M5: this is the exact function `handle_open` races the real
    /// `channel_open_forwarded_tcpip`/`channel_open_x11` calls through (typed
    /// here over a plain `u32` rather than the vendored `Channel<Msg>`, which
    /// only a live session can construct -- the mechanism under test doesn't
    /// depend on the payload type). A regression back to awaiting the task
    /// inline under a bare `tokio::time::timeout` (dropping it on elapse, the
    /// pre-fix shape) would silently lose this late resolution too, exactly as
    /// it silently lost the vendored server's `ChannelId`.
    #[tokio::test(start_paused = true)]
    async fn a_late_resolution_past_the_timeout_is_still_reclaimed_not_dropped() {
        let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
        let task = tokio::spawn(async move { rx.await.unwrap() });

        let (late_tx, late_rx) = tokio::sync::oneshot::channel::<u32>();
        let outcome = race_with_reclaim(Duration::from_millis(10), task, move |value| {
            let _ = late_tx.send(value);
        })
        .await;
        assert!(
            matches!(outcome, RaceOutcome::TimedOut),
            "the task must not have resolved within the timeout"
        );

        tx.send(42).unwrap(); // the stalling peer finally answers, late
        let late_value = late_rx
            .await
            .expect("a late resolution past the timeout must still reach `on_late`, not be silently dropped");
        assert_eq!(late_value, 42);
    }

    #[tokio::test(start_paused = true)]
    async fn race_with_reclaim_resolves_promptly_without_touching_on_late() {
        let task = tokio::spawn(async { 7u32 });
        let outcome = race_with_reclaim(Duration::from_secs(1), task, |_| {
            panic!("on_late must not fire for a task that resolved within the timeout");
        })
        .await;
        assert!(matches!(outcome, RaceOutcome::Resolved(7)));
    }
}
