use std::sync::Arc;
use std::time::Duration;

use crate::ha::coordination::CoordinationBackend;
use crate::ha::presence::OwnerCache;
use crate::ha::relay_token::{now_epoch_ms, PendingRelays, RelayBinding, RelaySigner};
use crate::pbgw::DialBackSignal;
use crate::ssh::connector::{ConnectFuture, NodeConnectError, NodeConnector, NodeDial};
use crate::telemetry::metrics::{self, UnreachableReason};

pub struct AgentRouter {
    /// HA identity: gateway NAME (not uuid).
    self_gateway_id: String,
    local: Arc<dyn NodeConnector>,
    remote: Arc<dyn NodeConnector>,
    cache: Arc<OwnerCache>,
}

impl AgentRouter {
    pub fn new(
        self_gateway_id: String,
        local: Arc<dyn NodeConnector>,
        remote: Arc<dyn NodeConnector>,
        cache: Arc<OwnerCache>,
    ) -> Self {
        Self {
            self_gateway_id,
            local,
            remote,
            cache,
        }
    }
}

impl NodeConnector for AgentRouter {
    fn connect<'a>(&'a self, dial: &'a NodeDial) -> ConnectFuture<'a> {
        Box::pin(async move {
            self.cache.observe(
                &dial.node_name,
                &dial.owning_gateway_id,
                &dial.owning_gateway_addr,
                dial.owner_nonce,
            );

            if dial.owning_gateway_id.is_empty() {
                let m = metrics::node_unreachable(UnreachableReason::NoFreshOwner);
                tracing::info!(node = %dial.node_name, outcome = m.outcome(), reason = m.reason(), "no gateway owns this node's agent channel; failing closed");
                return Err(NodeConnectError::NoAgent);
            }
            if dial.owning_gateway_id == self.self_gateway_id {
                self.local.connect(dial).await
            } else {
                tracing::info!(node = %dial.node_name, owner = %dial.owning_gateway_id, "node owned by a peer gateway; routing over the direct relay");
                self.remote.connect(dial).await
            }
        })
    }
}

pub struct RemoteGatewayConnector {
    coordination: Arc<dyn CoordinationBackend>,
    signer: Arc<RelaySigner>,
    pending: Arc<PendingRelays>,
    self_gateway_id: String,
    ingress_relay_addr: String,
    relay_timeout: Duration,
    token_ttl: Duration,
}

impl RemoteGatewayConnector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coordination: Arc<dyn CoordinationBackend>,
        signer: Arc<RelaySigner>,
        pending: Arc<PendingRelays>,
        self_gateway_id: String,
        ingress_relay_addr: String,
        relay_timeout: Duration,
        token_ttl: Duration,
    ) -> Self {
        Self {
            coordination,
            signer,
            pending,
            self_gateway_id,
            ingress_relay_addr,
            relay_timeout,
            token_ttl,
        }
    }
}

impl NodeConnector for RemoteGatewayConnector {
    fn connect<'a>(&'a self, dial: &'a NodeDial) -> ConnectFuture<'a> {
        Box::pin(async move {
            let owner = dial.owning_gateway_id.clone();
            let binding = RelayBinding {
                node_id: dial.node_id.clone(),
                node_name: dial.node_name.clone(),
                session_id: dial.session_id.clone(),
                owner_gateway_id: owner.clone(),
                principal: dial.principal.clone(),
                owner_nonce: dial.owner_nonce,
            };
            let now_ms = now_epoch_ms();
            let ttl_ms = self.token_ttl.as_millis() as i64;
            let exp_ms = now_ms.saturating_add(ttl_ms);
            let (jti, token) = self
                .signer
                .mint(&self.self_gateway_id, &binding, ttl_ms, now_ms);

            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            if !self.pending.insert(jti.clone(), binding, exp_ms, ready_tx) {
                let m = metrics::node_unreachable(UnreachableReason::RelayLedgerFull);
                tracing::warn!(node = %dial.node_name, owner = %owner, outcome = m.outcome(), reason = m.reason(), "pending-relay ledger at capacity; failing closed");
                return Err(NodeConnectError::RelayUnavailable);
            }

            let signal = DialBackSignal {
                node_id: dial.node_id.clone(),
                node_name: dial.node_name.clone(),
                session_id: dial.session_id.clone(),
                ingress_gateway_id: self.self_gateway_id.clone(),
                ingress_relay_addr: self.ingress_relay_addr.clone(),
                owner_gateway_id: owner.clone(),
                owner_nonce: dial.owner_nonce,
                principal: dial.principal.clone(),
                relay_token: token,
                exp_epoch_ms: exp_ms,
            };
            if let Err(e) = self.coordination.publish_dial_back(&owner, &signal).await {
                self.pending.abandon(&jti);
                let m = metrics::node_unreachable(UnreachableReason::CoordinationPublishFailed);
                tracing::info!(node = %dial.node_name, owner = %owner, error = %e, outcome = m.outcome(), reason = m.reason(), "could not signal the owning gateway; failing closed");
                return Err(NodeConnectError::RelayUnavailable);
            }

            match tokio::time::timeout(self.relay_timeout, ready_rx).await {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(_)) => {
                    let m = metrics::node_unreachable(UnreachableReason::RelayRejected);
                    tracing::info!(node = %dial.node_name, owner = %owner, outcome = m.outcome(), reason = m.reason(), "the owning gateway did not complete the relay");
                    Err(NodeConnectError::RelayUnavailable)
                }
                Err(_) => {
                    self.pending.abandon(&jti);
                    let m = metrics::node_unreachable(UnreachableReason::RelayTimeout);
                    tracing::info!(node = %dial.node_name, owner = %owner, outcome = m.outcome(), reason = m.reason(), "the owning gateway did not dial the relay back within the bound");
                    Err(NodeConnectError::Timeout(self.relay_timeout))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ha::coordination::InProcessBackend;
    use crate::ssh::connector::ByteStream;
    use futures_util::StreamExt;

    const SELF: &str = "gw-A";

    fn dial(owner: &str) -> NodeDial {
        NodeDial {
            node_id: "node-uuid".into(),
            connector_kind: crate::pb::ConnectorKind::OutboundAgent as i32,
            node_name: "node-a".into(),
            session_id: "sess-1".into(),
            principal: "deploy".into(),
            owning_gateway_id: owner.to_string(),
            owning_gateway_addr: "gw-b:9444".into(),
            owner_nonce: 7,
            ..Default::default()
        }
    }

    struct Spy(std::sync::atomic::AtomicBool);
    impl NodeConnector for Spy {
        fn connect<'a>(&'a self, _dial: &'a NodeDial) -> ConnectFuture<'a> {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                let (a, _b) = tokio::io::duplex(64);
                Ok(Box::new(a) as Box<dyn ByteStream>)
            })
        }
    }

    fn spy() -> Arc<Spy> {
        Arc::new(Spy(std::sync::atomic::AtomicBool::new(false)))
    }

    #[tokio::test]
    async fn router_fails_closed_when_no_owner() {
        let cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
        let router = AgentRouter::new(SELF.into(), spy(), spy(), cache);
        let err = router.connect(&dial("")).await.unwrap_err();
        assert!(matches!(err, NodeConnectError::NoAgent));
    }

    #[tokio::test]
    async fn router_routes_local_when_owner_is_self_and_caches_owner() {
        let cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
        let local = spy();
        let remote = spy();
        let router = AgentRouter::new(SELF.into(), local.clone(), remote.clone(), cache.clone());
        assert!(router.connect(&dial(SELF)).await.is_ok());
        assert!(local.0.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!remote.0.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(cache.get("node-a").unwrap().owner_id, SELF);
    }

    #[tokio::test]
    async fn router_routes_remote_when_owner_is_a_peer() {
        let cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
        let local = spy();
        let remote = spy();
        let router = AgentRouter::new(SELF.into(), local.clone(), remote.clone(), cache);
        assert!(router.connect(&dial("gw-B")).await.is_ok());
        assert!(remote.0.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!local.0.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn remote_publishes_a_signal_and_the_relay_stream_is_returned_on_accept() {
        let bus: Arc<dyn CoordinationBackend> = Arc::new(InProcessBackend::new());
        let signer = Arc::new(RelaySigner::generate());
        let pending = Arc::new(PendingRelays::default());
        let remote = RemoteGatewayConnector::new(
            bus.clone(),
            signer.clone(),
            pending.clone(),
            SELF.into(),
            "gw-a:9444".into(),
            Duration::from_secs(2),
            Duration::from_secs(30),
        );

        let mut owner_sub = bus.subscribe("gw-B");
        let pending2 = pending.clone();
        let signer2 = signer.clone();
        let owner = tokio::spawn(async move {
            let sig = owner_sub.next().await.unwrap();
            assert_eq!(sig.node_name, "node-a");
            assert!(sig.relay_token.starts_with("SLGW1."));
            let payload = signer2
                .verify(&sig.relay_token, SELF, now_epoch_ms())
                .unwrap();
            let tx = pending2.consume(&payload).unwrap();
            let (a, _b) = tokio::io::duplex(64);
            tx.send(Box::new(a) as Box<dyn ByteStream>).ok();
        });

        let stream = remote.connect(&dial("gw-B")).await;
        assert!(
            stream.is_ok(),
            "the accepted relay stream is returned to the inner leg"
        );
        owner.await.unwrap();
        assert!(pending.is_empty(), "the token was consumed");
    }

    #[tokio::test]
    async fn remote_fails_closed_when_no_owner_subscriber() {
        let bus: Arc<dyn CoordinationBackend> = Arc::new(InProcessBackend::new());
        let remote = RemoteGatewayConnector::new(
            bus,
            Arc::new(RelaySigner::generate()),
            Arc::new(PendingRelays::default()),
            SELF.into(),
            "gw-a:9444".into(),
            Duration::from_millis(200),
            Duration::from_secs(30),
        );
        let err = remote.connect(&dial("gw-B")).await.unwrap_err();
        assert!(matches!(err, NodeConnectError::RelayUnavailable));
    }

    #[tokio::test]
    async fn remote_times_out_when_the_owner_never_relays() {
        let bus: Arc<dyn CoordinationBackend> = Arc::new(InProcessBackend::new());
        let pending = Arc::new(PendingRelays::default());
        let remote = RemoteGatewayConnector::new(
            bus.clone(),
            Arc::new(RelaySigner::generate()),
            pending.clone(),
            SELF.into(),
            "gw-a:9444".into(),
            Duration::from_millis(150),
            Duration::from_secs(30),
        );
        let _owner_sub = bus.subscribe("gw-B");
        let err = remote.connect(&dial("gw-B")).await.unwrap_err();
        assert!(matches!(err, NodeConnectError::Timeout(_)));
        assert!(
            pending.is_empty(),
            "the abandoned token stops being redeemable"
        );
    }

    #[tokio::test]
    async fn routing_failures_increment_the_node_unreachable_counter() {
        use crate::telemetry::metrics::testutil::CounterProbe;
        use crate::telemetry::metrics::{ATTR_LAYER, ATTR_REASON, NODE_UNREACHABLE};

        let probe = CounterProbe::install();
        let no_owner = [(ATTR_REASON, "no_fresh_owner"), (ATTR_LAYER, "route")];
        let timeout = [(ATTR_REASON, "relay_timeout"), (ATTR_LAYER, "route")];
        assert_eq!(probe.read(NODE_UNREACHABLE, &no_owner), None);
        assert_eq!(probe.read(NODE_UNREACHABLE, &timeout), None);

        let cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
        let router = AgentRouter::new(SELF.into(), spy(), spy(), cache);
        router.connect(&dial("")).await.unwrap_err();
        assert_eq!(probe.read(NODE_UNREACHABLE, &no_owner), Some(1));
        assert_eq!(
            probe.read(NODE_UNREACHABLE, &timeout),
            None,
            "a no-owner refusal is not credited to the relay-timeout series"
        );

        let bus: Arc<dyn CoordinationBackend> = Arc::new(InProcessBackend::new());
        let remote = RemoteGatewayConnector::new(
            bus.clone(),
            Arc::new(RelaySigner::generate()),
            Arc::new(PendingRelays::default()),
            SELF.into(),
            "gw-a:9444".into(),
            Duration::from_millis(100),
            Duration::from_secs(30),
        );
        let _owner_sub = bus.subscribe("gw-B");
        remote.connect(&dial("gw-B")).await.unwrap_err();
        assert_eq!(probe.read(NODE_UNREACHABLE, &timeout), Some(1));
        assert_eq!(
            probe.read(NODE_UNREACHABLE, &no_owner),
            Some(1),
            "the earlier series is unchanged by an unrelated failure"
        );
    }
}
