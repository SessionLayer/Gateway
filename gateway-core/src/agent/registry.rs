//! The live agent registry: `node_name -> control channel` (contract §7).
//!
//! **Re-registration replaces.** If an Agent registers for a node that already has a
//! live control channel, the newer connection wins and the older is closed — a
//! network partition must not lock a node out until a TCP timeout expires. The
//! deregistration guard is therefore conn-id-scoped: a superseded connection's guard
//! cannot evict the connection that replaced it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::pbagent::DialBackRequest;

/// What the Gateway sends down a live control channel.
pub enum ControlOut {
    /// Ask the owning Agent to dial back for one session.
    DialBack(Box<DialBackRequest>),
    /// This connection has been superseded by a newer one for the same node: close.
    Superseded,
}

/// Hand-written so the dial-back **token cannot transit `Debug`** (contract §6: "never
/// logged, never persisted, never echoed"). `DialBackRequest` is prost-generated and would
/// otherwise derive `Debug` including its `token` field, so a single future `debug!(?out)`
/// in the control loop would dump a live single-use capability. Mirrors S9's
/// `SessionGrant` redaction (F-agentlog-1).
impl std::fmt::Debug for ControlOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DialBack(req) => f
                .debug_struct("DialBack")
                .field("request_id", &req.request_id)
                .field("node_name", &req.node_name)
                .field("session_id", &req.session_id)
                .field("token", &"<redacted>")
                .finish(),
            Self::Superseded => f.write_str("Superseded"),
        }
    }
}

/// A live control channel to the Agent that owns one node.
#[derive(Clone, Debug)]
pub struct ControlHandle {
    /// The agent identity resolved from the connection's mTLS client certificate.
    pub agent_id: String,
    conn_id: u64,
    tx: mpsc::Sender<ControlOut>,
}

impl ControlHandle {
    /// Signal the Agent to dial back, waiting up to `queue_timeout` for room in the control
    /// channel's outbound queue.
    ///
    /// A **bounded `send`, not `try_send`** (F-agentsignal-1): a momentary burst of
    /// concurrent sessions to a healthy agent queues and drains rather than shedding the
    /// 17th onto the "node offline" path. Only a queue that stays full for the whole bound —
    /// a genuinely saturated or wedged control channel — sheds, and it sheds as the distinct
    /// [`RegistryError::Busy`], never conflated with [`RegistryError::ChannelGone`] (the
    /// agent actually disconnected). Fail-closed either way; the two just log differently.
    pub async fn send_dial_back(
        &self,
        req: DialBackRequest,
        queue_timeout: std::time::Duration,
    ) -> Result<(), RegistryError> {
        match tokio::time::timeout(
            queue_timeout,
            self.tx.send(ControlOut::DialBack(Box::new(req))),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(RegistryError::ChannelGone),
            Err(_) => Err(RegistryError::Busy),
        }
    }
}

/// A registry failure. All are fail-closed: the session becomes "node offline". They are
/// distinguished so an operator can tell a dead agent from a saturated one (F-agentsignal-1).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    /// No Agent is registered for this node (never connected, or dropped).
    #[error("no agent is registered for this node")]
    NotRegistered,
    /// The control channel closed between lookup and send (the agent disconnected).
    #[error("the agent control channel is gone")]
    ChannelGone,
    /// The control channel's outbound queue stayed full for the whole bound — the agent is
    /// registered and (probably) alive but its signal path is saturated or wedged.
    #[error("the agent control channel is saturated")]
    Busy,
    /// The registry is at its configured agent cap (bounded resource use).
    #[error("agent registry is at capacity")]
    AtCapacity,
}

/// The `node_name -> live control channel` map.
#[derive(Debug)]
pub struct AgentRegistry {
    agents: Mutex<HashMap<String, ControlHandle>>,
    next_conn_id: AtomicU64,
    max_agents: usize,
}

impl AgentRegistry {
    /// A registry bounded to `max_agents` live control channels.
    pub fn new(max_agents: usize) -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(1),
            max_agents,
        }
    }

    /// Register (or replace) the control channel for `node_name`. An existing
    /// registration for the same node is superseded: it is told to close, and the
    /// new connection takes ownership.
    pub fn register(
        self: &Arc<Self>,
        node_name: &str,
        agent_id: &str,
        tx: mpsc::Sender<ControlOut>,
    ) -> Result<Registration, RegistryError> {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::SeqCst);
        let superseded = {
            let mut agents = self.agents.lock().unwrap();
            let replacing = agents.contains_key(node_name);
            if !replacing && agents.len() >= self.max_agents {
                return Err(RegistryError::AtCapacity);
            }
            agents.insert(
                node_name.to_string(),
                ControlHandle {
                    agent_id: agent_id.to_string(),
                    conn_id,
                    tx,
                },
            )
        };
        if let Some(old) = superseded {
            let _ = old.tx.try_send(ControlOut::Superseded);
        }
        Ok(Registration {
            registry: self.clone(),
            node_name: node_name.to_string(),
            conn_id,
        })
    }

    /// The control channel that owns `node_name`, if one is live.
    pub fn lookup(&self, node_name: &str) -> Result<ControlHandle, RegistryError> {
        self.agents
            .lock()
            .unwrap()
            .get(node_name)
            .cloned()
            .ok_or(RegistryError::NotRegistered)
    }

    /// Whether `agent_id` is the registered owner of `node_name` — contract §6
    /// check 5: a token captured by a different Agent, even a valid unlocked one,
    /// is worthless to it.
    pub fn owns(&self, agent_id: &str, node_name: &str) -> bool {
        self.agents
            .lock()
            .unwrap()
            .get(node_name)
            .is_some_and(|h| h.agent_id == agent_id)
    }

    /// The number of live control channels.
    pub fn len(&self) -> usize {
        self.agents.lock().unwrap().len()
    }

    /// Whether no Agent is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn deregister(&self, node_name: &str, conn_id: u64) {
        let mut agents = self.agents.lock().unwrap();
        // Only evict our own registration: a superseded connection's guard must not
        // remove the newer connection that replaced it.
        if agents.get(node_name).is_some_and(|h| h.conn_id == conn_id) {
            agents.remove(node_name);
        }
    }
}

/// Deregisters a control channel when its connection ends (heartbeat loss, close,
/// or supersession). The node then has no owner and is simply offline (§7.1).
#[derive(Debug)]
pub struct Registration {
    registry: Arc<AgentRegistry>,
    node_name: String,
    conn_id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.registry.deregister(&self.node_name, self.conn_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn chan() -> (mpsc::Sender<ControlOut>, mpsc::Receiver<ControlOut>) {
        mpsc::channel(4)
    }

    #[test]
    fn lookup_finds_the_registered_owner() {
        let reg = Arc::new(AgentRegistry::new(8));
        assert!(matches!(
            reg.lookup("node-a"),
            Err(RegistryError::NotRegistered)
        ));

        let (tx, _rx) = chan();
        let _g = reg.register("node-a", "agent-a", tx).unwrap();
        assert_eq!(reg.lookup("node-a").unwrap().agent_id, "agent-a");
        assert!(reg.owns("agent-a", "node-a"));
        // Ownership is exact: another (valid) agent does not own this node.
        assert!(!reg.owns("agent-b", "node-a"));
        assert!(!reg.owns("agent-a", "node-b"));
    }

    #[test]
    fn reregistration_replaces_and_closes_the_older_connection() {
        let reg = Arc::new(AgentRegistry::new(8));
        let (tx1, mut rx1) = chan();
        let g1 = reg.register("node-a", "agent-a", tx1).unwrap();

        let (tx2, _rx2) = chan();
        let _g2 = reg.register("node-a", "agent-a", tx2).unwrap();

        // The older connection is told to close (a partition must not lock the node
        // out until a TCP timeout expires).
        assert!(matches!(rx1.try_recv(), Ok(ControlOut::Superseded)));
        assert_eq!(reg.len(), 1);

        // …and when the superseded connection finally tears down, its guard must NOT
        // evict the newer registration.
        drop(g1);
        assert_eq!(reg.len(), 1, "the newer connection still owns the node");
        assert!(reg.lookup("node-a").is_ok());
    }

    #[test]
    fn dropping_the_registration_makes_the_node_offline() {
        let reg = Arc::new(AgentRegistry::new(8));
        let (tx, _rx) = chan();
        let g = reg.register("node-a", "agent-a", tx).unwrap();
        drop(g);
        assert!(matches!(
            reg.lookup("node-a"),
            Err(RegistryError::NotRegistered)
        ));
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_is_capped_but_a_reconnect_of_a_known_node_still_wins() {
        let reg = Arc::new(AgentRegistry::new(1));
        let (tx, _rx) = chan();
        let _g = reg.register("node-a", "agent-a", tx).unwrap();

        let (tx2, _rx2) = chan();
        assert!(matches!(
            reg.register("node-b", "agent-b", tx2),
            Err(RegistryError::AtCapacity)
        ));
        // A reconnect for an ALREADY-registered node is a replace, not a new slot —
        // the cap must not lock an existing node out of reconnecting.
        let (tx3, _rx3) = chan();
        assert!(reg.register("node-a", "agent-a", tx3).is_ok());
    }

    #[test]
    fn control_out_debug_redacts_the_dial_back_token() {
        // F-agentlog-1: a future debug!(?out) must never dump the single-use capability.
        let out = ControlOut::DialBack(Box::new(DialBackRequest {
            request_id: "req-1".into(),
            token: "SLDB1.supersecretpayload.sig".into(),
            ..Default::default()
        }));
        let shown = format!("{out:?}");
        assert!(!shown.contains("SLDB1"), "token leaked via Debug: {shown}");
        assert!(!shown.contains("supersecret"));
        assert!(
            shown.contains("request_id"),
            "non-secret fields still shown"
        );
    }

    #[tokio::test]
    async fn a_burst_queues_up_to_the_channel_capacity() {
        // A momentary burst must not shed: sends within capacity succeed without draining.
        let reg = Arc::new(AgentRegistry::new(8));
        let (tx, _rx) = mpsc::channel(4);
        let _g = reg.register("node-a", "agent-a", tx).unwrap();
        let handle = reg.lookup("node-a").unwrap();
        for _ in 0..4 {
            assert!(handle
                .send_dial_back(DialBackRequest::default(), Duration::from_millis(50))
                .await
                .is_ok());
        }
    }

    #[tokio::test]
    async fn a_saturated_channel_sheds_as_busy_not_channel_gone() {
        // The receiver exists but never drains: a full queue sheds as Busy — distinct from a
        // disconnected agent — after the bound, so an operator is not sent to chase a dead
        // agent that is actually just overloaded (F-agentsignal-1).
        let reg = Arc::new(AgentRegistry::new(8));
        let (tx, _rx) = mpsc::channel(1);
        let _g = reg.register("node-a", "agent-a", tx).unwrap();
        let handle = reg.lookup("node-a").unwrap();
        // Fill the single slot, then a second send has nowhere to go and times out.
        handle
            .send_dial_back(DialBackRequest::default(), Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(
            handle
                .send_dial_back(DialBackRequest::default(), Duration::from_millis(50))
                .await,
            Err(RegistryError::Busy)
        );
    }

    #[tokio::test]
    async fn send_after_the_agent_is_gone_is_channel_gone_not_busy() {
        let reg = Arc::new(AgentRegistry::new(8));
        let (tx, rx) = chan();
        let _g = reg.register("node-a", "agent-a", tx).unwrap();
        let handle = reg.lookup("node-a").unwrap();
        drop(rx); // the control task ended between lookup and send
        assert_eq!(
            handle
                .send_dial_back(DialBackRequest::default(), Duration::from_millis(50))
                .await,
            Err(RegistryError::ChannelGone)
        );
    }
}
