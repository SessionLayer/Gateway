use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::sync::watch;

use crate::agent::registry::AgentRegistry;
use crate::cpauth::{CpAuthClient, CpError};
use crate::pb::PresenceHeartbeatResponse;
use crate::telemetry::metrics::{self, CpFailure, PresenceTransition};

const HEARTBEAT_CONCURRENCY: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceState {
    pub owning_gateway_id: String,
    pub gateway_addr: String,
    pub nonce: u64,
    pub nonce_id: String,
    pub last_seen_ms: i64,
    pub is_self_owner: bool,
}

impl From<PresenceHeartbeatResponse> for PresenceState {
    fn from(r: PresenceHeartbeatResponse) -> Self {
        Self {
            owning_gateway_id: r.owning_gateway_id,
            gateway_addr: r.gateway_addr,
            nonce: r.nonce,
            nonce_id: r.nonce_id,
            last_seen_ms: r.last_seen_epoch_ms,
            is_self_owner: r.is_self_owner,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PresenceError {
    #[error("presence RPC failed: {0}")]
    Cp(#[from] CpError),
}

impl PresenceError {
    fn cp_failure(&self) -> CpFailure {
        match self {
            PresenceError::Cp(CpError::Unreachable(_)) => CpFailure::Unreachable,
            PresenceError::Cp(CpError::CircuitOpen) => CpFailure::CircuitOpen,
            PresenceError::Cp(CpError::Timeout(_)) => CpFailure::Timeout,
            PresenceError::Cp(CpError::Rpc(_)) => CpFailure::Rpc,
        }
    }
}

pub type PresenceFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PresenceState, PresenceError>> + Send + 'a>>;
pub type ReleaseFuture<'a> = Pin<Box<dyn Future<Output = Result<(), PresenceError>> + Send + 'a>>;

pub trait PresenceStore: Send + Sync {
    fn heartbeat<'a>(&'a self, node_id: &'a str, gateway_addr: &'a str) -> PresenceFuture<'a>;
    fn release<'a>(&'a self, node_id: &'a str) -> ReleaseFuture<'a>;
}

pub struct CpPresenceStore {
    cpauth: Arc<CpAuthClient>,
}

impl CpPresenceStore {
    pub fn new(cpauth: Arc<CpAuthClient>) -> Self {
        Self { cpauth }
    }
}

impl PresenceStore for CpPresenceStore {
    fn heartbeat<'a>(&'a self, node_id: &'a str, gateway_addr: &'a str) -> PresenceFuture<'a> {
        Box::pin(async move {
            let resp = self
                .cpauth
                .presence_heartbeat(node_id, gateway_addr)
                .await?;
            Ok(PresenceState::from(resp))
        })
    }

    fn release<'a>(&'a self, node_id: &'a str) -> ReleaseFuture<'a> {
        Box::pin(async move {
            self.cpauth.presence_release(node_id).await?;
            Ok(())
        })
    }
}

#[derive(Debug, Clone)]
pub struct OwnerObservation {
    pub owner_id: String,
    pub addr: String,
    pub nonce: u64,
    seen_at: Instant,
}

/// Local `node → owner` cache updated from Heartbeat and Authorize.
/// Nonce-monotonic: a lower-nonce observation never overwrites a higher one.
pub struct OwnerCache {
    inner: Mutex<HashMap<String, OwnerObservation>>,
    ttl: Duration,
}

impl OwnerCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    pub fn observe(&self, node_id: &str, owner_id: &str, addr: &str, nonce: u64) {
        if owner_id.is_empty() {
            return;
        }
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = map.get(node_id) {
            if nonce < existing.nonce {
                return;
            }
        }
        map.insert(
            node_id.to_string(),
            OwnerObservation {
                owner_id: owner_id.to_string(),
                addr: addr.to_string(),
                nonce,
                seen_at: Instant::now(),
            },
        );
    }

    pub fn get(&self, node_id: &str) -> Option<OwnerObservation> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(node_id)
            .filter(|e| e.seen_at.elapsed() <= self.ttl)
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Heartbeat loop (runs in both single and HA modes).
pub struct HeartbeatLoop {
    store: Arc<dyn PresenceStore>,
    registry: Arc<AgentRegistry>,
    cache: Arc<OwnerCache>,
    gateway_addr: String,
    interval: Duration,
    /// Nodes the CP last confirmed THIS Gateway owns. Only for edge-detecting ownership
    /// transitions: the standby log line fires every tick, a failover happens once.
    self_owned: Mutex<HashSet<String>>,
}

impl HeartbeatLoop {
    pub fn new(
        store: Arc<dyn PresenceStore>,
        registry: Arc<AgentRegistry>,
        cache: Arc<OwnerCache>,
        gateway_addr: String,
        interval: Duration,
    ) -> Self {
        Self {
            store,
            registry,
            cache,
            gateway_addr,
            interval,
            self_owned: Mutex::new(HashSet::new()),
        }
    }

    pub fn spawn(self, shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.run(shutdown))
    }

    async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut owned_prev: HashSet<String> = HashSet::new();
        loop {
            if *shutdown.borrow() {
                self.release_all_owned().await;
                return;
            }
            tokio::select! {
                biased;
                res = shutdown.changed() => {
                    if res.is_err() {
                        return;
                    }
                }
                _ = ticker.tick() => {
                    self.tick(&mut owned_prev).await;
                }
            }
        }
    }

    async fn release_all_owned(&self) {
        for node in self.registry.owned_node_names() {
            if let Err(e) = self.store.release(&node).await {
                metrics::presence_transition(PresenceTransition::ReleaseFailed);
                tracing::debug!(node = %node, error = %e, "presence release on drain failed (staleness TTL will cover it)");
            } else {
                metrics::presence_transition(PresenceTransition::Released);
            }
            self.forget_self_owned(&node);
        }
    }

    fn mark_self_owned(&self, node: &str) -> bool {
        self.self_owned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(node.to_string())
    }

    fn forget_self_owned(&self, node: &str) -> bool {
        self.self_owned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(node)
    }

    async fn tick(&self, owned_prev: &mut HashSet<String>) {
        let current: HashSet<String> = self.registry.owned_node_names().into_iter().collect();

        let gone: Vec<String> = owned_prev.difference(&current).cloned().collect();
        futures_util::stream::iter(gone)
            .for_each_concurrent(HEARTBEAT_CONCURRENCY, |node| async move {
                if let Err(e) = self.store.release(&node).await {
                    metrics::presence_transition(PresenceTransition::ReleaseFailed);
                    tracing::debug!(node = %node, error = %e, "presence release on channel drop failed (staleness TTL will cover it)");
                } else {
                    metrics::presence_transition(PresenceTransition::Released);
                }
                self.forget_self_owned(&node);
            })
            .await;
        futures_util::stream::iter(current.iter().cloned())
            .for_each_concurrent(HEARTBEAT_CONCURRENCY, |node| async move {
                match self.store.heartbeat(&node, &self.gateway_addr).await {
                    Ok(state) => {
                        self.cache.observe(
                            &node,
                            &state.owning_gateway_id,
                            &state.gateway_addr,
                            state.nonce,
                        );
                        if state.is_self_owner {
                            if self.mark_self_owned(&node) {
                                metrics::presence_transition(PresenceTransition::Acquired);
                            }
                        } else {
                            if self.forget_self_owned(&node) {
                                metrics::presence_transition(PresenceTransition::Standby);
                            }
                            tracing::debug!(node = %node, owner = %state.owning_gateway_id, "presence: standby (another gateway owns this node)");
                        }
                    }
                    Err(e) => {
                        // Deliberately NOT a Standby transition: a transient RPC failure
                        // proves nothing about who owns the node, and flapping the edge
                        // detector would manufacture a failover on every recovery.
                        metrics::presence_heartbeat_failure(e.cp_failure());
                        tracing::debug!(node = %node, error = %e, "presence heartbeat failed; not owning this tick");
                    }
                }
            })
            .await;

        *owned_prev = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn owner_cache_is_nonce_monotonic_and_ttl_bounded() {
        let cache = OwnerCache::new(Duration::from_secs(30));
        cache.observe("node-a", "gw-B", "gw-b:9444", 5);
        assert_eq!(cache.get("node-a").unwrap().owner_id, "gw-B");

        cache.observe("node-a", "gw-STALE", "gw-stale:9444", 3);
        let got = cache.get("node-a").unwrap();
        assert_eq!(got.owner_id, "gw-B");
        assert_eq!(got.nonce, 5);

        cache.observe("node-a", "gw-C", "gw-c:9444", 6);
        assert_eq!(cache.get("node-a").unwrap().owner_id, "gw-C");

        cache.observe("node-b", "", "", 1);
        assert!(cache.get("node-b").is_none());
    }

    #[test]
    fn owner_cache_get_expires_after_ttl() {
        let cache = OwnerCache::new(Duration::from_millis(0));
        cache.observe("node-a", "gw-B", "gw-b:9444", 1);
        std::thread::sleep(Duration::from_millis(5));
        assert!(
            cache.get("node-a").is_none(),
            "a stale entry is not returned"
        );
        assert_eq!(cache.len(), 1, "but it remains cached until overwritten");
    }

    struct FakeStore {
        heartbeats: Mutex<Vec<(String, String)>>,
        releases: Mutex<Vec<String>>,
        self_owner: AtomicBool,
        fail: AtomicBool,
        rpc_delay: Mutex<Duration>,
    }

    impl FakeStore {
        fn new(self_owner: bool) -> Arc<Self> {
            Arc::new(Self {
                heartbeats: Mutex::new(Vec::new()),
                releases: Mutex::new(Vec::new()),
                self_owner: AtomicBool::new(self_owner),
                fail: AtomicBool::new(false),
                rpc_delay: Mutex::new(Duration::ZERO),
            })
        }

        fn with_delay(self_owner: bool, delay: Duration) -> Arc<Self> {
            let s = Self::new(self_owner);
            *s.rpc_delay.lock().unwrap() = delay;
            s
        }
    }

    impl PresenceStore for FakeStore {
        fn heartbeat<'a>(&'a self, node_id: &'a str, gateway_addr: &'a str) -> PresenceFuture<'a> {
            Box::pin(async move {
                let delay = *self.rpc_delay.lock().unwrap();
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if self.fail.load(Ordering::SeqCst) {
                    return Err(PresenceError::Cp(CpError::CircuitOpen));
                }
                self.heartbeats
                    .lock()
                    .unwrap()
                    .push((node_id.to_string(), gateway_addr.to_string()));
                let is_self = self.self_owner.load(Ordering::SeqCst);
                Ok(PresenceState {
                    owning_gateway_id: if is_self {
                        "gw-self".into()
                    } else {
                        "gw-other".into()
                    },
                    gateway_addr: gateway_addr.to_string(),
                    nonce: 1,
                    nonce_id: "n1".into(),
                    last_seen_ms: 0,
                    is_self_owner: is_self,
                })
            })
        }

        fn release<'a>(&'a self, node_id: &'a str) -> ReleaseFuture<'a> {
            Box::pin(async move {
                self.releases.lock().unwrap().push(node_id.to_string());
                Ok(())
            })
        }
    }

    fn registry_with(nodes: &[&str]) -> Arc<AgentRegistry> {
        let reg = Arc::new(AgentRegistry::new(nodes.len().max(16)));
        // Leak the receivers so the registrations stay live for the test's lifetime.
        for n in nodes {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            std::mem::forget(rx);
            let guard = reg.register(n, &format!("agent-{n}"), tx).unwrap();
            std::mem::forget(guard);
        }
        reg
    }

    #[tokio::test]
    async fn a_tick_heartbeats_every_owned_node_and_caches_the_owner() {
        let store = FakeStore::new(true);
        let registry = registry_with(&["node-a", "node-b"]);
        let cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
        let loop_ = HeartbeatLoop::new(
            store.clone(),
            registry,
            cache.clone(),
            "gw-self:9444".into(),
            Duration::from_secs(10),
        );
        let mut prev = HashSet::new();
        loop_.tick(&mut prev).await;

        let hbs = store.heartbeats.lock().unwrap();
        assert_eq!(hbs.len(), 2);
        assert!(hbs.iter().all(|(_, addr)| addr == "gw-self:9444"));
        assert_eq!(cache.get("node-a").unwrap().owner_id, "gw-self");
        assert_eq!(prev.len(), 2);
    }

    #[tokio::test]
    async fn a_node_that_drops_between_ticks_is_released() {
        let store = FakeStore::new(true);
        let registry = registry_with(&["node-a"]);
        let cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
        let loop_ = HeartbeatLoop::new(
            store.clone(),
            registry,
            cache,
            "gw-self:9444".into(),
            Duration::from_secs(10),
        );
        let mut prev: HashSet<String> = ["node-a".to_string(), "node-gone".to_string()]
            .into_iter()
            .collect();
        loop_.tick(&mut prev).await;

        assert_eq!(&*store.releases.lock().unwrap(), &["node-gone".to_string()]);
        assert!(prev.contains("node-a") && !prev.contains("node-gone"));
    }

    #[tokio::test]
    async fn a_failed_heartbeat_is_not_fatal_and_records_no_owner() {
        let store = FakeStore::new(true);
        store.fail.store(true, Ordering::SeqCst);
        let registry = registry_with(&["node-a"]);
        let cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
        let loop_ = HeartbeatLoop::new(
            store,
            registry,
            cache.clone(),
            "gw-self:9444".into(),
            Duration::from_secs(10),
        );
        let mut prev = HashSet::new();
        loop_.tick(&mut prev).await;
        assert!(
            cache.get("node-a").is_none(),
            "a failed heartbeat records no owner"
        );
    }

    #[tokio::test]
    async fn presence_counters_track_transitions_not_ticks() {
        use crate::telemetry::metrics::testutil::CounterProbe;
        use crate::telemetry::metrics::{
            ATTR_REASON, ATTR_TRANSITION, PRESENCE_HEARTBEAT_FAILURES, PRESENCE_TRANSITIONS,
        };

        let probe = CounterProbe::install();
        let acquired = [(ATTR_TRANSITION, "acquired")];
        let standby = [(ATTR_TRANSITION, "standby")];
        let released = [(ATTR_TRANSITION, "released")];
        let circuit_open = [(ATTR_REASON, "circuit_open")];
        assert_eq!(probe.read(PRESENCE_TRANSITIONS, &acquired), None);
        assert_eq!(probe.read(PRESENCE_HEARTBEAT_FAILURES, &circuit_open), None);

        let store = FakeStore::new(true);
        let loop_ = HeartbeatLoop::new(
            store.clone(),
            registry_with(&["node-a"]),
            Arc::new(OwnerCache::new(Duration::from_secs(30))),
            "gw-self:9444".into(),
            Duration::from_secs(10),
        );
        let mut prev = HashSet::new();

        loop_.tick(&mut prev).await;
        assert_eq!(probe.read(PRESENCE_TRANSITIONS, &acquired), Some(1));
        loop_.tick(&mut prev).await;
        assert_eq!(
            probe.read(PRESENCE_TRANSITIONS, &acquired),
            Some(1),
            "still owning is not a new acquisition"
        );
        assert_eq!(probe.read(PRESENCE_TRANSITIONS, &standby), None);

        store.self_owner.store(false, Ordering::SeqCst);
        loop_.tick(&mut prev).await;
        loop_.tick(&mut prev).await;
        assert_eq!(probe.read(PRESENCE_TRANSITIONS, &standby), Some(1));

        store.self_owner.store(true, Ordering::SeqCst);
        loop_.tick(&mut prev).await;
        assert_eq!(probe.read(PRESENCE_TRANSITIONS, &acquired), Some(2));
        store.fail.store(true, Ordering::SeqCst);
        loop_.tick(&mut prev).await;
        assert_eq!(
            probe.read(PRESENCE_HEARTBEAT_FAILURES, &circuit_open),
            Some(1)
        );
        assert_eq!(
            probe.read(PRESENCE_TRANSITIONS, &standby),
            Some(1),
            "a failed heartbeat is not a failover"
        );
        store.fail.store(false, Ordering::SeqCst);
        loop_.tick(&mut prev).await;
        assert_eq!(
            probe.read(PRESENCE_TRANSITIONS, &acquired),
            Some(2),
            "recovering from an outage is not a fresh acquisition either"
        );

        assert_eq!(probe.read(PRESENCE_TRANSITIONS, &released), None);
        loop_.release_all_owned().await;
        assert_eq!(probe.read(PRESENCE_TRANSITIONS, &released), Some(1));
    }

    #[tokio::test]
    async fn a_large_fleet_refreshes_concurrently_within_the_ttl_budget() {
        // A Gateway holding many nodes must refresh them within the staleness TTL. With a
        // per-RPC delay a SERIAL loop would take node_count * delay (well past any TTL); the
        // bounded fan-out completes in ~ceil(node_count / K) * delay. 100 nodes @ 20ms serial is
        // 2s; concurrent (~16-wide) is ~140ms — assert we are comfortably under a 1s budget AND
        // that every node was actually heartbeated.
        let store = FakeStore::with_delay(true, Duration::from_millis(20));
        let names: Vec<String> = (0..100).map(|i| format!("node-{i}")).collect();
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let registry = registry_with(&refs);
        let cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
        let loop_ = HeartbeatLoop::new(
            store.clone(),
            registry,
            cache,
            "gw-self:9444".into(),
            Duration::from_secs(10),
        );
        let mut prev = HashSet::new();
        let started = std::time::Instant::now();
        loop_.tick(&mut prev).await;
        let elapsed = started.elapsed();
        assert_eq!(
            store.heartbeats.lock().unwrap().len(),
            100,
            "every node heartbeated"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "the concurrent fan-out must beat the serial budget; took {elapsed:?}"
        );
    }
}
