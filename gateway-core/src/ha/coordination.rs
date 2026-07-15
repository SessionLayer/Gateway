//! The coordination signal bus (Session Fifteen; Design §10.2, FR-HA-3). The bus
//! carries **only** the [`DialBackSignal`] — session bytes NEVER traverse it (the byte
//! path is the direct Gateway↔Gateway relay). An ingress publishes a signal addressed
//! to the owner of a node; the owner subscribes to its own id and, on a signal, dials
//! the relay back.
//!
//! Two backends behind one seam:
//! - [`InProcessBackend`] — single-instance default, **zero extra dependencies**: an
//!   in-memory broadcast keyed by gateway id. In single mode the owner is always self,
//!   so a real cross-gateway signal never fires, but the code path is identical
//!   (mode-symmetry). Two Gateway instances in one process can share one backend, which
//!   is exactly how the HA E2E exercises the cross-gateway relay without a broker.
//!
//! A distributed backend (core NATS pub/sub, no JetStream) plugs in at the same seam
//! for a true multi-host deployment; it is a drop-in `impl CoordinationBackend`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use futures_util::stream::BoxStream;
use tokio::sync::broadcast;

use crate::pbgw::DialBackSignal;

/// A failure publishing a coordination signal. Never fatal to the Gateway: a failure to
/// deliver just means the ingress times out and fails the session closed (§7 invariant
/// 3); the bus is transient (no durability, no retry).
#[derive(Debug, thiserror::Error)]
pub enum CoordinationError {
    /// No live subscriber for the addressed owner (in-process), or the broker rejected
    /// the publish. The ingress will time out and fail closed.
    #[error("no live subscriber for the addressed owner gateway")]
    NoSubscriber,
    /// The transport (NATS) failed to publish.
    #[error("coordination transport error: {0}")]
    Transport(String),
}

/// The boxed publish future (object-safe: the backend is held as `Arc<dyn …>`).
pub type PublishFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), CoordinationError>> + Send + 'a>>;

/// The signalling seam (Design §10.2). Signalling ONLY — the byte relay is separate and
/// the bus never carries session bytes.
pub trait CoordinationBackend: Send + Sync {
    /// Publish `signal` to the Gateway that owns the target node (`owner_gateway_id`).
    fn publish_dial_back<'a>(
        &'a self,
        owner_gateway_id: &'a str,
        signal: &'a DialBackSignal,
    ) -> PublishFuture<'a>;

    /// Subscribe to the signals addressed to THIS Gateway (`my_gateway_id`). The stream
    /// yields each [`DialBackSignal`] as it arrives; it never completes on transient loss
    /// (a dropped signal just means that one session times out — fail closed).
    fn subscribe(&self, my_gateway_id: &str) -> BoxStream<'static, DialBackSignal>;
}

/// Per-owner broadcast capacity. A signal is tiny and consumed immediately; this only
/// bounds a burst before the single subscriber drains it. On overflow the oldest signals
/// are dropped (those sessions time out and fail closed — never a byte-path effect).
const CHANNEL_CAPACITY: usize = 256;

/// In-process signal bus: an in-memory broadcast keyed by gateway id (single-instance
/// default; zero extra dependencies). Cheap to share behind an `Arc`.
#[derive(Default)]
pub struct InProcessBackend {
    channels: Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>,
}

impl InProcessBackend {
    /// A fresh, empty in-process bus.
    pub fn new() -> Self {
        Self::default()
    }

    fn sender(&self, gateway_id: &str) -> broadcast::Sender<DialBackSignal> {
        // Recover a poisoned lock (Tier-0 signalling path: the critical section runs no user
        // code, so the state is consistent; never wedge the bus because another task panicked).
        self.channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(gateway_id.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .clone()
    }
}

impl CoordinationBackend for InProcessBackend {
    fn publish_dial_back<'a>(
        &'a self,
        owner_gateway_id: &'a str,
        signal: &'a DialBackSignal,
    ) -> PublishFuture<'a> {
        let sender = self.sender(owner_gateway_id);
        let signal = signal.clone();
        Box::pin(async move {
            // `send` errors only when there is no live receiver — i.e. the owner is not
            // subscribed here. That is a routing miss: fail closed (the ingress times out).
            sender
                .send(signal)
                .map(|_| ())
                .map_err(|_| CoordinationError::NoSubscriber)
        })
    }

    fn subscribe(&self, my_gateway_id: &str) -> BoxStream<'static, DialBackSignal> {
        let rx = self.sender(my_gateway_id).subscribe();
        Box::pin(broadcast_stream(rx))
    }
}

/// Turn a broadcast receiver into a stream of signals. A lagged receiver (a burst
/// overran the buffer) skips the dropped signals rather than ending the stream — those
/// sessions time out and fail closed, but the subscriber stays live for the next signal.
fn broadcast_stream(
    rx: broadcast::Receiver<DialBackSignal>,
) -> impl futures_util::Stream<Item = DialBackSignal> {
    futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(signal) => return Some((signal, rx)),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::sync::Arc;
    use std::time::Duration;

    fn signal(node: &str, owner: &str) -> DialBackSignal {
        DialBackSignal {
            node_id: format!("{node}-id"),
            node_name: node.to_string(),
            session_id: "sess-1".into(),
            ingress_gateway_id: "gw-A".into(),
            ingress_relay_addr: "gw-a.internal:9444".into(),
            owner_gateway_id: owner.to_string(),
            owner_nonce: 7,
            principal: "deploy".into(),
            relay_token: "SLGW1.x.y".into(),
            exp_epoch_ms: 1,
        }
    }

    #[tokio::test]
    async fn a_published_signal_reaches_the_owners_subscriber() {
        let bus = InProcessBackend::new();
        let mut sub = bus.subscribe("gw-B");
        bus.publish_dial_back("gw-B", &signal("node-a", "gw-B"))
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(1), sub.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.node_name, "node-a");
        assert_eq!(got.owner_gateway_id, "gw-B");
    }

    #[tokio::test]
    async fn a_signal_is_delivered_only_to_the_addressed_owner() {
        // The whole point of the subject/id keying: gw-C must not see gw-B's signal.
        let bus = InProcessBackend::new();
        let mut for_b = bus.subscribe("gw-B");
        let mut for_c = bus.subscribe("gw-C");
        bus.publish_dial_back("gw-B", &signal("node-a", "gw-B"))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), for_b.next())
                .await
                .unwrap()
                .unwrap()
                .node_name,
            "node-a"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), for_c.next())
                .await
                .is_err(),
            "gw-C must not receive a signal addressed to gw-B"
        );
    }

    #[tokio::test]
    async fn publishing_with_no_subscriber_fails_closed() {
        // No owner subscribed ⇒ NoSubscriber ⇒ the ingress will time out and fail closed.
        let bus = InProcessBackend::new();
        let err = bus
            .publish_dial_back("gw-nobody", &signal("node-a", "gw-nobody"))
            .await
            .unwrap_err();
        assert!(matches!(err, CoordinationError::NoSubscriber));
    }

    #[tokio::test]
    async fn two_gateways_sharing_one_bus_route_across_each_other() {
        // The HA-E2E topology: gw-A (ingress) and gw-B (owner) share one Arc<bus>. gw-A
        // publishes to gw-B and gw-B's own subscriber receives it — a real cross-gateway
        // signal, in-process, no broker.
        let bus: Arc<dyn CoordinationBackend> = Arc::new(InProcessBackend::new());
        let mut owner_sub = bus.subscribe("gw-B");
        bus.publish_dial_back("gw-B", &signal("node-x", "gw-B"))
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(1), owner_sub.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.node_name, "node-x");
    }
}
