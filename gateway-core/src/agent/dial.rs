use std::sync::Arc;
use std::time::Duration;

use crate::agent::registry::AgentRegistry;
use crate::agent::token::{now_epoch_secs, DialBackBinding, DialBackSigner, PendingDialBacks};
use crate::pbagent::DialBackRequest;
use crate::ssh::connector::{ConnectFuture, NodeConnectError, NodeConnector, NodeDial};
use crate::ssh::locks::{LockBindings, LockSet};
use crate::telemetry::metrics::{self, UnreachableReason};

pub struct AgentDial {
    registry: Arc<AgentRegistry>,
    pending: Arc<PendingDialBacks>,
    signer: Arc<DialBackSigner>,
    lock_set: Arc<LockSet>,
    gateway_id: String,
    advertise_url: String,
    token_ttl_secs: i64,
    dial_back_timeout: Duration,
}

impl AgentDial {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: Arc<AgentRegistry>,
        pending: Arc<PendingDialBacks>,
        signer: Arc<DialBackSigner>,
        lock_set: Arc<LockSet>,
        gateway_id: String,
        advertise_url: String,
        token_ttl_secs: i64,
        dial_back_timeout: Duration,
    ) -> Self {
        Self {
            registry,
            pending,
            signer,
            lock_set,
            gateway_id,
            advertise_url,
            token_ttl_secs,
            dial_back_timeout,
        }
    }
}

impl NodeConnector for AgentDial {
    fn connect<'a>(&'a self, dial: &'a NodeDial) -> ConnectFuture<'a> {
        Box::pin(async move {
            if dial.node_name.is_empty() {
                return Err(NodeConnectError::NoNodeName);
            }
            let agent = match self.registry.lookup(&dial.node_name) {
                Ok(a) => a,
                Err(_) => {
                    let m = metrics::node_unreachable(UnreachableReason::NoAgentRegistered);
                    tracing::info!(node = %dial.node_name, outcome = m.outcome(), reason = m.reason(), "no agent is connected for this node");
                    return Err(NodeConnectError::NoAgent);
                }
            };

            // Deny wins, and deny fails CLOSED. An unhealthy lock feed
            // cannot confirm the ABSENCE of a lock, so an empty deny-set is NOT evidence the
            // agent is unlocked - refuse rather than mint a single-use dial-back capability
            // for a peer we cannot vouch for. The session path reaches the
            // same conclusion from the same signal (handler.rs local_recheck).
            if !self.lock_set.healthy() {
                let m = metrics::node_unreachable(UnreachableReason::LockFeedUnhealthy);
                tracing::warn!(
                    node = %dial.node_name,
                    outcome = m.outcome(),
                    reason = m.reason(),
                    "lock feed cannot confirm the agent is unlocked; refusing to signal (deny fails closed)"
                );
                return Err(NodeConnectError::AgentLocked);
            }
            let bindings = LockBindings::for_agent(&agent.agent_id, &dial.node_name);
            if let Some(lock) = self.lock_set.matching(&bindings) {
                let m = metrics::node_unreachable(UnreachableReason::AgentLocked);
                tracing::warn!(
                    node = %dial.node_name,
                    lock_id = %lock.lock_id,
                    outcome = m.outcome(),
                    reason = m.reason(),
                    "refusing to signal a locked agent"
                );
                return Err(NodeConnectError::AgentLocked);
            }

            let binding = DialBackBinding {
                node_name: dial.node_name.clone(),
                session_id: dial.session_id.clone(),
                principal: dial.principal.clone(),
                agent_id: agent.agent_id.clone(),
            };
            let now = now_epoch_secs();
            let not_after = now.saturating_add(self.token_ttl_secs);
            let (jti, token) =
                self.signer
                    .mint(&self.gateway_id, &binding, self.token_ttl_secs, now);
            let request_id = random_request_id();

            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            self.pending.insert(
                jti.clone(),
                request_id.clone(),
                binding,
                not_after,
                ready_tx,
            );

            let request = DialBackRequest {
                request_id,
                node_name: dial.node_name.clone(),
                session_id: dial.session_id.clone(),
                principal: dial.principal.clone(),
                gateway_id: self.gateway_id.clone(),
                dial_back_endpoint: self.advertise_url.clone(),
                token,
                not_after_epoch_seconds: not_after,
            };
            let deadline = tokio::time::Instant::now() + self.dial_back_timeout;
            match agent.send_dial_back(request, self.dial_back_timeout).await {
                Ok(()) => {}
                Err(crate::agent::registry::RegistryError::Busy) => {
                    self.pending.abandon(&jti);
                    let m = metrics::node_unreachable(UnreachableReason::AgentSignalSaturated);
                    tracing::warn!(node = %dial.node_name, outcome = m.outcome(), reason = m.reason(), "the node's agent control channel is saturated; shedding this session");
                    return Err(NodeConnectError::AgentBusy);
                }
                Err(_) => {
                    self.pending.abandon(&jti);
                    let m = metrics::node_unreachable(UnreachableReason::AgentDisconnected);
                    tracing::info!(node = %dial.node_name, outcome = m.outcome(), reason = m.reason(), "the node's agent disconnected before the signal could be sent");
                    return Err(NodeConnectError::NoAgent);
                }
            }

            match tokio::time::timeout_at(deadline, ready_rx).await {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(_)) => {
                    let m =
                        metrics::node_unreachable(UnreachableReason::AgentRefusedOrLocalDialFailed);
                    tracing::info!(node = %dial.node_name, outcome = m.outcome(), reason = m.reason(), "the agent refused the dial-back or could not reach its node's sshd");
                    Err(NodeConnectError::AgentRefused)
                }
                Err(_) => {
                    self.pending.abandon(&jti);
                    let m = metrics::node_unreachable(UnreachableReason::DialBackTimeout);
                    tracing::info!(node = %dial.node_name, outcome = m.outcome(), reason = m.reason(), "the agent did not complete the dial-back within the deadline");
                    Err(NodeConnectError::Timeout(self.dial_back_timeout))
                }
            }
        })
    }
}

fn random_request_id() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::registry::ControlOut;
    use crate::pb::{Lock, LockTarget};

    const GW: &str = "gw-1";

    fn dialer(registry: Arc<AgentRegistry>, lock_set: Arc<LockSet>) -> AgentDial {
        AgentDial::new(
            registry,
            Arc::new(PendingDialBacks::default()),
            Arc::new(DialBackSigner::generate()),
            lock_set,
            GW.to_string(),
            "wss://gw.internal:9444".to_string(),
            30,
            Duration::from_millis(150),
        )
    }

    fn node_dial(node_name: &str) -> NodeDial {
        NodeDial {
            node_id: "node-uuid".into(),
            dial_address: String::new(),
            connector_kind: crate::pb::ConnectorKind::OutboundAgent as i32,
            node_name: node_name.into(),
            session_id: "sess-1".into(),
            principal: "deploy".into(),
            ..Default::default()
        }
    }

    fn healthy_locks() -> Arc<LockSet> {
        let set = Arc::new(LockSet::new(30, 30));
        set.replace_snapshot(Vec::new(), 1);
        set
    }

    fn unhealthy_locks() -> Arc<LockSet> {
        Arc::new(LockSet::new(30, 30))
    }

    #[tokio::test]
    async fn an_unhealthy_lock_feed_refuses_to_signal_and_mints_no_token() {
        let registry = Arc::new(AgentRegistry::new(8));
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let _g = registry.register("node-a", "agent-a", tx).unwrap();
        let pending = Arc::new(PendingDialBacks::default());
        let dial = AgentDial::new(
            registry,
            pending.clone(),
            Arc::new(DialBackSigner::generate()),
            unhealthy_locks(),
            GW.to_string(),
            "wss://gw:9444".into(),
            30,
            Duration::from_millis(100),
        );
        let err = dial.connect(&node_dial("node-a")).await.unwrap_err();
        assert!(matches!(err, NodeConnectError::AgentLocked));
        assert!(pending.is_empty(), "no dial-back capability may be minted");
        assert!(rx.try_recv().is_err(), "no signal may be sent");
    }

    #[tokio::test]
    async fn a_dropped_lock_feed_refuses_to_signal() {
        let locks = healthy_locks();
        locks.mark_disconnected();
        assert!(!locks.healthy());
        let registry = Arc::new(AgentRegistry::new(8));
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let _g = registry.register("node-a", "agent-a", tx).unwrap();
        let dial = dialer(registry, locks);
        assert!(matches!(
            dial.connect(&node_dial("node-a")).await,
            Err(NodeConnectError::AgentLocked)
        ));
    }

    #[tokio::test]
    async fn a_node_with_no_registered_agent_is_offline_immediately() {
        let dial = dialer(Arc::new(AgentRegistry::new(8)), healthy_locks());
        let err = dial.connect(&node_dial("node-a")).await.unwrap_err();
        assert!(matches!(err, NodeConnectError::NoAgent));
    }

    #[tokio::test]
    async fn an_agent_node_without_a_node_name_fails_closed() {
        let dial = dialer(Arc::new(AgentRegistry::new(8)), healthy_locks());
        let err = dial.connect(&node_dial("")).await.unwrap_err();
        assert!(matches!(err, NodeConnectError::NoNodeName));
    }

    #[tokio::test]
    async fn signalling_a_locked_agent_is_refused_before_the_dial_back() {
        let registry = Arc::new(AgentRegistry::new(8));
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let _g = registry.register("node-a", "agent-a", tx).unwrap();

        let locks = healthy_locks();
        locks.add(Lock {
            lock_id: "l1".into(),
            target: Some(LockTarget {
                identities: vec!["agent-a".into()],
                ..Default::default()
            }),
            expires_at_epoch_seconds: 0,
            created_at_epoch_seconds: 0,
            reason: "clone detected".into(),
            ..Default::default()
        });

        let dial = dialer(registry, locks);
        let err = dial.connect(&node_dial("node-a")).await.unwrap_err();
        assert!(matches!(err, NodeConnectError::AgentLocked));
    }

    #[tokio::test]
    async fn the_signal_carries_the_token_and_no_splice_target() {
        let registry = Arc::new(AgentRegistry::new(8));
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let _g = registry.register("node-a", "agent-a", tx).unwrap();
        let dial = dialer(registry, healthy_locks());

        let connect = tokio::spawn(async move {
            let d = node_dial("node-a");
            dial.connect(&d).await.map(|_| ()).unwrap_err().to_string()
        });

        let ControlOut::DialBack(req) = rx.recv().await.unwrap() else {
            panic!("expected a dial-back request")
        };
        assert_eq!(req.node_name, "node-a");
        assert_eq!(req.session_id, "sess-1");
        assert_eq!(req.principal, "deploy");
        assert_eq!(req.gateway_id, GW);
        assert_eq!(req.dial_back_endpoint, "wss://gw.internal:9444");
        assert!(req.token.starts_with("SLDB1."));
        assert!(req.not_after_epoch_seconds > now_epoch_secs());
        // The confused-deputy defence: there is nowhere on this wire to name a target.
        // The Agent splices to its own configured loopback and nothing else.
        assert!(
            !format!("{req:?}").contains("127.0.0.1"),
            "the signal must carry no splice target"
        );

        assert!(connect.await.unwrap().contains("timed out"));
    }

    #[tokio::test]
    async fn a_dial_back_that_never_arrives_times_out_and_kills_the_token() {
        let registry = Arc::new(AgentRegistry::new(8));
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let _g = registry.register("node-a", "agent-a", tx).unwrap();
        let pending = Arc::new(PendingDialBacks::default());
        let dial = AgentDial::new(
            registry,
            pending.clone(),
            Arc::new(DialBackSigner::generate()),
            healthy_locks(),
            GW.to_string(),
            "wss://gw:9444".into(),
            30,
            Duration::from_millis(100),
        );

        let err = dial.connect(&node_dial("node-a")).await.unwrap_err();
        assert!(matches!(err, NodeConnectError::Timeout(_)));
        assert!(
            pending.is_empty(),
            "the abandoned token must stop being redeemable at once"
        );
    }

    #[tokio::test]
    async fn an_agent_fast_fail_ends_the_connect_without_waiting_out_the_deadline() {
        let registry = Arc::new(AgentRegistry::new(8));
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let _g = registry.register("node-a", "agent-a", tx).unwrap();
        let pending = Arc::new(PendingDialBacks::default());
        let dial = AgentDial::new(
            registry,
            pending.clone(),
            Arc::new(DialBackSigner::generate()),
            healthy_locks(),
            GW.to_string(),
            "wss://gw:9444".into(),
            30,
            Duration::from_secs(30),
        );

        let pending_for_agent = pending.clone();
        tokio::spawn(async move {
            let ControlOut::DialBack(req) = rx.recv().await.unwrap() else {
                panic!("expected a dial-back request")
            };
            pending_for_agent.fail_request(&req.request_id);
        });

        let started = std::time::Instant::now();
        let err = dial.connect(&node_dial("node-a")).await.unwrap_err();
        assert!(matches!(err, NodeConnectError::AgentRefused));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the fast-fail must not wait out the dial-back deadline"
        );
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn an_agent_that_disconnected_between_lookup_and_signal_is_offline() {
        let registry = Arc::new(AgentRegistry::new(8));
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let _g = registry.register("node-a", "agent-a", tx).unwrap();
        drop(rx);
        let pending = Arc::new(PendingDialBacks::default());
        let dial = AgentDial::new(
            registry,
            pending.clone(),
            Arc::new(DialBackSigner::generate()),
            healthy_locks(),
            GW.to_string(),
            "wss://gw:9444".into(),
            30,
            Duration::from_millis(100),
        );
        let err = dial.connect(&node_dial("node-a")).await.unwrap_err();
        assert!(matches!(err, NodeConnectError::NoAgent));
        assert!(pending.is_empty(), "the unsent token must not stay pending");
    }
}
