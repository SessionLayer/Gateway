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
#[derive(Debug)]
pub enum ControlOut {
    /// Ask the owning Agent to dial back for one session.
    DialBack(Box<DialBackRequest>),
    /// This connection has been superseded by a newer one for the same node: close.
    Superseded,
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
    /// Signal the Agent to dial back. `Err` means the channel is gone (the Agent
    /// disconnected between lookup and send) — the caller fails closed to
    /// node-offline.
    pub fn send_dial_back(&self, req: DialBackRequest) -> Result<(), RegistryError> {
        self.tx
            .try_send(ControlOut::DialBack(Box::new(req)))
            .map_err(|_| RegistryError::ChannelGone)
    }
}

/// A registry failure. Both are fail-closed: the session becomes "node offline".
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    /// No Agent is registered for this node (never connected, or dropped).
    #[error("no agent is registered for this node")]
    NotRegistered,
    /// The control channel closed between lookup and send.
    #[error("the agent control channel is gone")]
    ChannelGone,
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
    fn send_after_the_agent_is_gone_fails_closed() {
        let reg = Arc::new(AgentRegistry::new(8));
        let (tx, rx) = chan();
        let _g = reg.register("node-a", "agent-a", tx).unwrap();
        let handle = reg.lookup("node-a").unwrap();
        drop(rx); // the control task ended between lookup and send
        assert_eq!(
            handle.send_dial_back(DialBackRequest::default()),
            Err(RegistryError::ChannelGone)
        );
    }
}
