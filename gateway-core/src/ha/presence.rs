//! Presence: the HA ownership WRITE path + the local owner cache (Session Fifteen;
//! Design §10.2/§10.3, FR-HA-2/5).
//!
//! A Gateway holding a node's live agent control channel is *eligible* to own it. The
//! [`HeartbeatLoop`] claims/refreshes ownership through the CP `Presence` service every
//! `heartbeat_interval` and releases it when the channel drops, so a standby claims fast.
//! The datastore boundary (Design D11: the CP is the sole Postgres owner) is preserved —
//! the Gateway has no database; [`PresenceStore`] is the §1.2 seam and its production impl
//! ([`CpPresenceStore`]) is a CP gRPC client.
//!
//! **The ownership identity is the gateway NAME** (`gateway_identity.name`), not the
//! gateway id: it is the routing key the whole HA plane speaks — the ingress compares the
//! Authorize `owning_gateway_id` to its own name, the owner subscribes to
//! `sl.dialback.<name>`, and the relay token binds the owner by name.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::agent::registry::AgentRegistry;
use crate::cpauth::{CpAuthClient, CpError};
use crate::pb::PresenceHeartbeatResponse;

/// The authoritative post-heartbeat presence state the CP returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceState {
    /// The authoritative owner's `gateway_identity.name` (the HA routing key).
    pub owning_gateway_id: String,
    /// The owner's peer-relay advertise address (`host:port`) as last heartbeated.
    pub gateway_addr: String,
    /// The authoritative monotonic fencing nonce after this heartbeat.
    pub nonce: u64,
    /// The nonce_id (uuid) disambiguating two claims that could share a nonce value.
    pub nonce_id: String,
    /// Owner `last_seen` as unix epoch milliseconds.
    pub last_seen_ms: i64,
    /// Whether THIS Gateway owns the node after this heartbeat (claimed or refreshed).
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

/// A presence write failure. Fail-closed: a heartbeat that cannot complete means this
/// Gateway does not (yet) own the node — a session routed to it would fail closed, and a
/// standby will claim once this owner goes stale.
#[derive(Debug, thiserror::Error)]
pub enum PresenceError {
    /// The CP `Presence` RPC failed (unreachable, timed out, or a stale-nonce/contention
    /// reject — treated as "not owner", FR-HA-5).
    #[error("presence RPC failed: {0}")]
    Cp(#[from] CpError),
}

/// Boxed heartbeat future (object-safe: the store is held as `Arc<dyn PresenceStore>`).
pub type PresenceFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PresenceState, PresenceError>> + Send + 'a>>;
/// Boxed release future.
pub type ReleaseFuture<'a> = Pin<Box<dyn Future<Output = Result<(), PresenceError>> + Send + 'a>>;

/// The presence WRITE seam (Design §1.2). The production impl is a CP gRPC client; tests
/// use an in-memory fake. The OWNER is always THIS Gateway (the CP takes it from the
/// authenticated mTLS peer, never a field).
pub trait PresenceStore: Send + Sync {
    /// Claim or refresh ownership of `node_id`, advertising `gateway_addr` as the
    /// peer-relay dial-back address.
    fn heartbeat<'a>(&'a self, node_id: &'a str, gateway_addr: &'a str) -> PresenceFuture<'a>;

    /// Relinquish ownership of `node_id` (idempotent; a no-op unless this Gateway owns it).
    fn release<'a>(&'a self, node_id: &'a str) -> ReleaseFuture<'a>;
}

/// The production [`PresenceStore`]: the CP `Presence` gRPC client (fail-closed like every
/// CP call). Postgres is the presence impl, reached through the CP — the Gateway has no DB.
pub struct CpPresenceStore {
    cpauth: Arc<CpAuthClient>,
}

impl CpPresenceStore {
    /// Build the store over the shared CP client.
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

/// One cached node→owner observation.
#[derive(Debug, Clone)]
pub struct OwnerObservation {
    /// The owner's gateway NAME.
    pub owner_id: String,
    /// The owner's peer-relay advertise address.
    pub addr: String,
    /// The monotonic fencing nonce this observation carried.
    pub nonce: u64,
    seen_at: Instant,
}

/// A best-effort local `node → owner` cache updated from Heartbeat responses and Authorize
/// owner fields (Session Fifteen). Used for staleness/observability; the per-session
/// AUTHORITATIVE owner is always the Authorize response. **Nonce-monotonic**: a lower-nonce
/// observation (a superseded owner) never overwrites a higher one (FR-HA-5).
pub struct OwnerCache {
    inner: Mutex<HashMap<String, OwnerObservation>>,
    ttl: Duration,
}

impl OwnerCache {
    /// A cache whose entries are considered stale after `ttl`.
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Record an observation. A lower nonce than the cached one is dropped (stale owner);
    /// an equal-or-higher nonce updates the owner + refreshes freshness. An empty owner is
    /// ignored (no fresh owner to record).
    pub fn observe(&self, node_id: &str, owner_id: &str, addr: &str, nonce: u64) {
        if owner_id.is_empty() {
            return;
        }
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = map.get(node_id) {
            if nonce < existing.nonce {
                return; // never overwrite a higher nonce with a lower one
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

    /// The current fresh observation for `node_id`, or `None` if unknown or older than the
    /// TTL (stale → the caller must not treat it as authoritative).
    pub fn get(&self, node_id: &str) -> Option<OwnerObservation> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(node_id)
            .filter(|e| e.seen_at.elapsed() <= self.ttl)
            .cloned()
    }

    /// Number of cached entries (fresh or stale) — for tests/metrics.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The presence heartbeat loop (Session Fifteen). Runs in BOTH modes (mode-symmetry: the
/// sole Gateway in single mode owns every node it holds a channel for). Each tick it
/// heartbeats every node the [`AgentRegistry`] currently holds a channel for, releases any
/// that dropped since the last tick, and updates the [`OwnerCache`].
pub struct HeartbeatLoop {
    store: Arc<dyn PresenceStore>,
    registry: Arc<AgentRegistry>,
    cache: Arc<OwnerCache>,
    /// This Gateway's own peer-relay advertise address (`host:port`), stored in presence.
    gateway_addr: String,
    interval: Duration,
}

impl HeartbeatLoop {
    /// Build the loop over the presence store + agent registry.
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
        }
    }

    /// Spawn the loop; it runs until `shutdown` flips true.
    pub fn spawn(self, shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.run(shutdown))
    }

    async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut owned_prev: HashSet<String> = HashSet::new();
        loop {
            if *shutdown.borrow() {
                // Graceful drain (Session Fifteen, §10.3): release every node we own so a
                // standby claims immediately, closing the planned-drain failover window. A CP
                // staleness TTL is the backstop if a release does not land.
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
                tracing::debug!(node = %node, error = %e, "presence release on drain failed (staleness TTL will cover it)");
            }
        }
    }

    async fn tick(&self, owned_prev: &mut HashSet<String>) {
        let current: HashSet<String> = self.registry.owned_node_names().into_iter().collect();

        // Release nodes we owned last tick but no longer hold a channel for (accelerates the
        // failover window on a control-channel drop; the CP staleness TTL is the backstop).
        for gone in owned_prev.difference(&current) {
            if let Err(e) = self.store.release(gone).await {
                tracing::debug!(node = %gone, error = %e, "presence release on channel drop failed (staleness TTL will cover it)");
            }
        }

        for node in &current {
            match self.store.heartbeat(node, &self.gateway_addr).await {
                Ok(state) => {
                    self.cache.observe(
                        node,
                        &state.owning_gateway_id,
                        &state.gateway_addr,
                        state.nonce,
                    );
                    if !state.is_self_owner {
                        // A standby learns another Gateway owns this node (it holds the
                        // channel but lost the ownership race). It keeps the channel and
                        // keeps heartbeating so it can take over when the owner goes stale.
                        tracing::debug!(node = %node, owner = %state.owning_gateway_id, "presence: standby (another gateway owns this node)");
                    }
                }
                Err(e) => {
                    // Fail closed: we simply do not own the node this tick (a session routed
                    // here would fail closed). Not fatal — retry next tick.
                    tracing::debug!(node = %node, error = %e, "presence heartbeat failed; not owning this tick");
                }
            }
        }

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

        // A lower nonce (a superseded owner) must NOT overwrite the higher one.
        cache.observe("node-a", "gw-STALE", "gw-stale:9444", 3);
        let got = cache.get("node-a").unwrap();
        assert_eq!(got.owner_id, "gw-B");
        assert_eq!(got.nonce, 5);

        // An equal-or-higher nonce updates the owner (a real failover).
        cache.observe("node-a", "gw-C", "gw-c:9444", 6);
        assert_eq!(cache.get("node-a").unwrap().owner_id, "gw-C");

        // An empty owner is ignored (no fresh owner to record).
        cache.observe("node-b", "", "", 1);
        assert!(cache.get("node-b").is_none());
    }

    #[test]
    fn owner_cache_get_expires_after_ttl() {
        let cache = OwnerCache::new(Duration::from_millis(0));
        cache.observe("node-a", "gw-B", "gw-b:9444", 1);
        // TTL is zero, so any elapsed time makes it stale.
        std::thread::sleep(Duration::from_millis(5));
        assert!(
            cache.get("node-a").is_none(),
            "a stale entry is not returned"
        );
        assert_eq!(cache.len(), 1, "but it remains cached until overwritten");
    }

    /// An in-memory presence store recording heartbeats + releases, with a self-owner knob.
    struct FakeStore {
        heartbeats: Mutex<Vec<(String, String)>>,
        releases: Mutex<Vec<String>>,
        self_owner: AtomicBool,
        fail: AtomicBool,
    }

    impl FakeStore {
        fn new(self_owner: bool) -> Arc<Self> {
            Arc::new(Self {
                heartbeats: Mutex::new(Vec::new()),
                releases: Mutex::new(Vec::new()),
                self_owner: AtomicBool::new(self_owner),
                fail: AtomicBool::new(false),
            })
        }
    }

    impl PresenceStore for FakeStore {
        fn heartbeat<'a>(&'a self, node_id: &'a str, gateway_addr: &'a str) -> PresenceFuture<'a> {
            Box::pin(async move {
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
        let reg = Arc::new(AgentRegistry::new(16));
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
        // Pretend last tick owned node-a AND node-gone; node-gone is no longer registered.
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
        loop_.tick(&mut prev).await; // must not panic
        assert!(
            cache.get("node-a").is_none(),
            "a failed heartbeat records no owner"
        );
    }
}
