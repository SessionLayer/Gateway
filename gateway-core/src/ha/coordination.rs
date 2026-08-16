use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use futures_util::stream::BoxStream;
use tokio::sync::broadcast;

use crate::pbgw::DialBackSignal;

#[derive(Debug, thiserror::Error)]
pub enum CoordinationError {
    #[error("no live subscriber for the addressed owner gateway")]
    NoSubscriber,
    #[error("coordination transport error: {0}")]
    Transport(String),
}

pub type PublishFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), CoordinationError>> + Send + 'a>>;

/// Signalling only — the byte relay is separate and the bus never carries session bytes.
pub trait CoordinationBackend: Send + Sync {
    fn publish_dial_back<'a>(
        &'a self,
        owner_gateway_id: &'a str,
        signal: &'a DialBackSignal,
    ) -> PublishFuture<'a>;

    fn subscribe(&self, my_gateway_id: &str) -> BoxStream<'static, DialBackSignal>;
}

const CHANNEL_CAPACITY: usize = 256;

#[derive(Default)]
pub struct InProcessBackend {
    channels: Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>,
}

impl InProcessBackend {
    pub fn new() -> Self {
        Self::default()
    }

    fn sender(&self, gateway_id: &str) -> broadcast::Sender<DialBackSignal> {
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
        let bus = InProcessBackend::new();
        let err = bus
            .publish_dial_back("gw-nobody", &signal("node-a", "gw-nobody"))
            .await
            .unwrap_err();
        assert!(matches!(err, CoordinationError::NoSubscriber));
    }

    #[tokio::test]
    async fn two_gateways_sharing_one_bus_route_across_each_other() {
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
