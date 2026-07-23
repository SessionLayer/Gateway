//! The actively-pushed lock deny-list and live-session teardown (Session Ten;
//! Design §6.3/§8.3/§8.4, FR-CHAN-3, FR-LOCK-1/2).
//!
//! The safety spine: a lock lives here on an INDEPENDENT push-fed set, never a
//! poll, so it fails **closed** and wins on every Gateway even under total
//! datastore loss and in break-glass. `LockSet` holds the current deny-set;
//! `LiveSessionRegistry` tracks live sessions so a newly-pushed lock tears down
//! matching ones immediately through the S9 recorder finalize path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pb::{DecisionContext, Lock, LockMode, LockTarget, SessionEndReason};

/// The trusted, per-session facts a lock is matched against — taken from the
/// SIGNED decision context (so a Gateway can never dodge a lock by lying about
/// identity/labels).
#[derive(Clone, Debug)]
pub struct LockBindings {
    identity: String,
    groups: Vec<String>,
    node_id: String,
    node_labels: Vec<(String, String)>,
    allowed_logins: Vec<String>,
    principal: String,
}

impl LockBindings {
    /// The matchable facts for an **agent peer** (Session Fourteen): an agent has no
    /// decision context, only the two facts its CP-stamped certificate carries — the
    /// agent identity and the node it is bound to. Used to refuse a locked agent at
    /// registration and at every dial-back (contract §1/§6; deny wins).
    ///
    /// A lock scoped to the node's CP *id* (rather than its name) is enforced on the
    /// session path instead: the handler matches the signed decision context — which
    /// carries the real `node_id` — before it ever reaches the connector.
    pub fn for_agent(agent_id: &str, node_name: &str) -> Self {
        Self {
            identity: agent_id.to_string(),
            groups: Vec::new(),
            node_id: node_name.to_string(),
            node_labels: Vec::new(),
            allowed_logins: Vec::new(),
            principal: String::new(),
        }
    }

    /// Derive the matchable facts from a verified decision context.
    pub fn from_context(ctx: &DecisionContext) -> Self {
        Self {
            identity: ctx.identity.clone(),
            groups: ctx.identity_groups.clone(),
            node_id: ctx.node_id.clone(),
            node_labels: ctx
                .node_labels
                .iter()
                .filter_map(|l| parse_label(l))
                .collect(),
            allowed_logins: ctx.allowed_logins.clone(),
            principal: ctx.principal.clone(),
        }
    }
}

fn parse_label(kv: &str) -> Option<(String, String)> {
    kv.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
}

/// Whether a lock's target matches a session's bindings (the Rust port of the S5
/// `LockMatching`, facets OR-matched).
///
/// Refinement over S5: an empty target with `all=false` matches NOTHING (S5 read
/// an empty target as match-all "deny wins"). This session added CP-side ingest
/// validation that requires an explicit `all=true` for a global lock, so a
/// facet-less target is a malformed lock — matching it against every session
/// would wipe the fleet. A genuine global lock always sets `all`.
pub fn target_matches(target: &LockTarget, b: &LockBindings) -> bool {
    if target.all {
        return true;
    }
    if !b.identity.is_empty() && target.identities.contains(&b.identity) {
        return true;
    }
    if target.groups.iter().any(|g| b.groups.contains(g)) {
        return true;
    }
    if !b.node_id.is_empty() && target.node_ids.contains(&b.node_id) {
        return true;
    }
    if target
        .principals
        .iter()
        .any(|p| *p == b.principal || b.allowed_logins.iter().any(|l| l == p))
    {
        return true;
    }
    if target.node_labels.iter().any(|tl| {
        parse_label(tl)
            .map(|(tk, tv)| b.node_labels.iter().any(|(bk, bv)| *bk == tk && *bv == tv))
            .unwrap_or(false)
    }) {
        return true;
    }
    false
}

/// Whether a pushed lock tears down already-ESTABLISHED live sessions (Design §8.3,
/// FR-LOCK-2). `STRICT` — and `UNSPECIFIED`, a pre-S20 CP that carried no mode — tear
/// down; `BEST_EFFORT` blocks new sessions/channels (via [`LockSet::matching`]) but lets a
/// live session run to completion. Fail-safe by construction: only the explicit
/// `BEST_EFFORT` value skips teardown, so an unknown/garbled mode still tears down (deny
/// wins). This governs ONLY teardown; new-session denial ([`LockSet::matching`]) is
/// mode-agnostic — every mode blocks new access.
fn tears_down_live_sessions(lock: &Lock) -> bool {
    lock.mode != LockMode::BestEffort as i32
}

/// A DENY expires conservatively (LATE): the lock keeps denying until clearly past
/// its expiry, the opposite of a grant. `expires_at == 0` means no TTL.
fn lock_active(lock: &Lock, now_secs: i64, skew_secs: i64) -> bool {
    lock.expires_at_epoch_seconds == 0
        || now_secs <= lock.expires_at_epoch_seconds.saturating_add(skew_secs)
}

fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The Gateway's near-real-time lock deny-set plus the feed-health signal.
pub struct LockSet {
    locks: RwLock<HashMap<String, Lock>>,
    /// True once a snapshot has been received on a live stream.
    connected: AtomicBool,
    /// Epoch seconds of the last feed activity (event or heartbeat).
    last_activity: AtomicU64,
    /// The feed is unhealthy if idle longer than this (forces per-channel
    /// re-validate: `decision_ttl -> 0`).
    unhealthy_after_secs: u64,
    /// Conservative expiry skew for a lock (keeps it denying slightly longer).
    skew_secs: i64,
    feed_epoch: AtomicU64,
}

impl LockSet {
    /// A fresh, empty, disconnected lock set.
    pub fn new(unhealthy_after_secs: u64, skew_secs: i64) -> Self {
        Self {
            locks: RwLock::new(HashMap::new()),
            connected: AtomicBool::new(false),
            last_activity: AtomicU64::new(0),
            unhealthy_after_secs,
            skew_secs,
            feed_epoch: AtomicU64::new(0),
        }
    }

    /// Replace the whole set (a snapshot / resync). The set is authoritative; the
    /// datastore is not consulted.
    pub fn replace_snapshot(&self, locks: Vec<Lock>, feed_epoch: u64) {
        let mut map = self.locks.write().unwrap();
        map.clear();
        for l in locks {
            map.insert(l.lock_id.clone(), l);
        }
        self.feed_epoch.store(feed_epoch, Ordering::SeqCst);
        self.connected.store(true, Ordering::SeqCst);
        self.touch();
    }

    /// Add (or replace) one pushed lock.
    pub fn add(&self, lock: Lock) {
        self.locks
            .write()
            .unwrap()
            .insert(lock.lock_id.clone(), lock);
        self.touch();
    }

    /// Drop a lock by id (deleted or expired upstream).
    pub fn remove(&self, lock_id: &str) {
        self.locks.write().unwrap().remove(lock_id);
        self.touch();
    }

    /// Record feed liveness (called on every event AND heartbeat).
    pub fn touch(&self) {
        self.last_activity
            .store(now_epoch_secs().max(0) as u64, Ordering::SeqCst);
    }

    /// Mark the stream down (disconnect). The set is NOT cleared — a
    /// previously-pushed lock keeps denying under datastore/CP loss.
    pub fn mark_disconnected(&self) {
        self.connected.store(false, Ordering::SeqCst);
    }

    /// The stream is healthy only if connected and recently active. An unhealthy
    /// stream forces per-channel re-validate (FR-CHAN-4).
    pub fn healthy(&self) -> bool {
        if !self.connected.load(Ordering::SeqCst) {
            return false;
        }
        let last = self.last_activity.load(Ordering::SeqCst) as i64;
        now_epoch_secs().saturating_sub(last) <= self.unhealthy_after_secs as i64
    }

    /// The first active lock matching these bindings, if any (deny wins). The
    /// reason is for the OPERATOR log only — never disclosed to the SSH user.
    pub fn matching(&self, b: &LockBindings) -> Option<Lock> {
        let now = now_epoch_secs();
        self.locks
            .read()
            .unwrap()
            .values()
            .filter(|l| lock_active(l, now, self.skew_secs))
            .find(|l| {
                l.target
                    .as_ref()
                    .map(|t| target_matches(t, b))
                    .unwrap_or(false)
            })
            .cloned()
    }

    /// A snapshot of the currently-active locks (for teardown scans).
    fn active_locks(&self) -> Vec<Lock> {
        let now = now_epoch_secs();
        self.locks
            .read()
            .unwrap()
            .values()
            .filter(|l| lock_active(l, now, self.skew_secs))
            .cloned()
            .collect()
    }
}

/// The out-of-band control surface for one live session: trips the shared abort
/// flag (so the bridge stops forwarding bytes at once) and disconnects the outer
/// SSH connection, which runs the handler's Drop → recorder finalize path.
/// The single generic mid-session teardown message shown to the SSH user for ANY
/// policy teardown (lock or grant-expiry) — §7.1 non-disclosure: the specific
/// cause (deliberate lock vs routine expiry) stays in the operator log only, so an
/// actively-locked attacker cannot tell they were deliberately cut off.
const TEARDOWN_DISCONNECT: &str = "session closed by policy";

/// The out-of-band control surface for one live session: trips the shared abort
/// flag (so the bridge stops plaintext at once) and disconnects the outer SSH
/// connection, which runs the handler's Drop → recorder finalize path.
#[derive(Clone)]
pub struct SessionControl {
    /// The lock-matchable facts, updatable on a mid-connection re-authorize so a
    /// lock targeting a drifted facet (e.g. a relabeled node) still tears the live
    /// session down. Shared across all clones (registry + handler).
    bindings: Arc<Mutex<LockBindings>>,
    handle: russh::server::Handle,
    /// Shared with the session's recorder: `should_abort()` reads it, so tearing
    /// down here stops plaintext immediately (mirrors S9 strict-mode teardown).
    abort: Arc<AtomicBool>,
    terminated: Arc<AtomicBool>,
    /// Why the session was torn down (a `SessionEndReason` value; 0 = unset,
    /// first cause wins). The handler's Drop reads it for the FR-SESS-3
    /// session-end signal (Session 25).
    end_reason: Arc<AtomicI32>,
}

impl SessionControl {
    /// Build a control surface over a live session's handle + shared abort flag.
    pub fn new(
        bindings: LockBindings,
        handle: russh::server::Handle,
        abort: Arc<AtomicBool>,
    ) -> Self {
        Self {
            bindings: Arc::new(Mutex::new(bindings)),
            handle,
            abort,
            terminated: Arc::new(AtomicBool::new(false)),
            end_reason: Arc::new(AtomicI32::new(SessionEndReason::Unspecified as i32)),
        }
    }

    /// Refresh the lock-matchable facts after a mid-connection re-authorize (the
    /// signed context may carry drifted node_labels / allowed_logins).
    pub fn update_bindings(&self, bindings: LockBindings) {
        *self.bindings.lock().unwrap() = bindings;
    }

    /// The live, re-auth-updated bindings, for lock matching outside the registry
    /// (the reverse dispatcher gates each reverse open on these — a frozen clone
    /// would miss a mid-session relabel, F-fwd-reverse-stale-bindings-1).
    pub fn shared_bindings(&self) -> Arc<Mutex<LockBindings>> {
        self.bindings.clone()
    }

    fn matches(&self, target: &LockTarget) -> bool {
        target_matches(target, &self.bindings.lock().unwrap())
    }

    /// Tear the session down, recording WHY (first recorded cause wins — a lock
    /// racing an expiry keeps the earlier cause) so the handler's Drop can carry
    /// it in the session-end signal. Operator-side diagnostics only: the SSH user
    /// still sees the one generic teardown message (§7.1).
    pub fn terminate_with(&self, reason: SessionEndReason) {
        let _ = self.end_reason.compare_exchange(
            SessionEndReason::Unspecified as i32,
            reason as i32,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        self.terminate();
    }

    /// The teardown cause recorded by [`Self::terminate_with`] (UNSPECIFIED when
    /// the session ended without an out-of-band teardown).
    pub fn end_reason(&self) -> SessionEndReason {
        SessionEndReason::try_from(self.end_reason.load(Ordering::SeqCst))
            .unwrap_or(SessionEndReason::Unspecified)
    }

    /// Tear the session down immediately (idempotent). Non-blocking: the outer
    /// disconnect is spawned; the connection end drives the recorder finalize. The
    /// user sees the SAME generic message for a lock and an expiry (§7.1).
    pub fn terminate(&self) {
        self.abort.store(true, Ordering::SeqCst);
        if self.terminated.swap(true, Ordering::SeqCst) {
            return;
        }
        let handle = self.handle.clone();
        tokio::spawn(async move {
            let _ = handle
                .disconnect(
                    russh::Disconnect::ByApplication,
                    TEARDOWN_DISCONNECT.to_string(),
                    String::new(),
                )
                .await;
        });
    }
}

/// Tracks live sessions so a pushed lock can tear down matching ones (FR-LOCK-1).
#[derive(Default)]
pub struct LiveSessionRegistry {
    sessions: Mutex<HashMap<String, SessionControl>>,
}

impl LiveSessionRegistry {
    /// Register a live session under its id; the returned guard deregisters on
    /// drop (connection end).
    pub fn register(self: &Arc<Self>, session_id: String, control: SessionControl) -> SessionGuard {
        self.sessions
            .lock()
            .unwrap()
            .insert(session_id.clone(), control);
        SessionGuard {
            registry: self.clone(),
            session_id,
        }
    }

    fn deregister(&self, session_id: &str) {
        self.sessions.lock().unwrap().remove(session_id);
    }

    /// The number of live sessions (the graceful-drain wait polls this until zero or the
    /// deadline, Session Fifteen).
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Whether no session is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Tear down every live session a newly-added lock matches. Returns the count.
    pub fn apply_added_lock(&self, lock: &Lock) -> usize {
        // BEST_EFFORT blocks NEW sessions/channels (via LockSet::matching) but does not tear
        // a live session down (§8.3, FR-LOCK-2); STRICT / UNSPECIFIED do. The lock is already
        // in the LockSet before this call, so new access is denied regardless of mode.
        if !tears_down_live_sessions(lock) {
            return 0;
        }
        let Some(target) = lock.target.as_ref() else {
            return 0;
        };
        let victims: Vec<SessionControl> = {
            let sessions = self.sessions.lock().unwrap();
            sessions
                .values()
                .filter(|c| c.matches(target))
                .cloned()
                .collect()
        };
        for c in &victims {
            c.terminate_with(SessionEndReason::Locked);
        }
        victims.len()
    }

    /// Tear down EVERY live session (the graceful-drain deadline, L4): trips each session's
    /// abort so its recorder finalize path runs to a bounded deadline, rather than dropping the
    /// tasks un-finalized when the process exits (which would leave un-finalized WORM objects).
    /// Idempotent (a no-op once the registry is empty). Returns the count torn down.
    pub fn terminate_all(&self) -> usize {
        let victims: Vec<SessionControl> = {
            let sessions = self.sessions.lock().unwrap();
            sessions.values().cloned().collect()
        };
        for c in &victims {
            // An orderly drain, not a policy action: CLOSED, not LOCKED/ERROR.
            c.terminate_with(SessionEndReason::Closed);
        }
        victims.len()
    }

    /// After a snapshot/resync, tear down any live session matching any active
    /// lock (a resync may introduce locks that arrived while disconnected).
    pub fn reconcile(&self, lock_set: &LockSet) -> usize {
        let active = lock_set.active_locks();
        if active.is_empty() {
            return 0;
        }
        let victims: Vec<SessionControl> = {
            let sessions = self.sessions.lock().unwrap();
            sessions
                .values()
                .filter(|c| {
                    // Only teardown-mode (STRICT / UNSPECIFIED) locks tear a live session down
                    // on resync; a BEST_EFFORT lock still denies new access via `matching`.
                    active
                        .iter()
                        .filter(|l| tears_down_live_sessions(l))
                        .any(|l| l.target.as_ref().map(|t| c.matches(t)).unwrap_or(false))
                })
                .cloned()
                .collect()
        };
        for c in &victims {
            c.terminate_with(SessionEndReason::Locked);
        }
        victims.len()
    }
}

/// Deregisters a live session from the registry when the connection ends.
pub struct SessionGuard {
    registry: Arc<LiveSessionRegistry>,
    session_id: String,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.registry.deregister(&self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(
        identity: &str,
        groups: &[&str],
        node_id: &str,
        labels: &[&str],
        principal: &str,
        logins: &[&str],
    ) -> DecisionContext {
        DecisionContext {
            node_id: node_id.into(),
            node_name: node_id.into(),
            allowed_logins: logins.iter().map(|s| s.to_string()).collect(),
            capabilities: Vec::new(),
            principal: principal.into(),
            grant_expiry_epoch_seconds: 0,
            policy_epoch: 0,
            decision_ttl_seconds: 45,
            gateway_id: "gw".into(),
            session_id: "s".into(),
            source_address: "1.2.3.4".into(),
            issued_at_epoch_seconds: 0,
            identity: identity.into(),
            identity_groups: groups.iter().map(|s| s.to_string()).collect(),
            node_labels: labels.iter().map(|s| s.to_string()).collect(),
            access_model: crate::pb::AccessModel::Standing as i32,
            idle_timeout_seconds: 0,
        }
    }

    fn tgt() -> LockTarget {
        LockTarget::default()
    }

    fn bindings() -> LockBindings {
        LockBindings::from_context(&ctx(
            "alice",
            &["admins"],
            "node-1",
            &["env=prod", "region=eu"],
            "deploy",
            &["deploy", "root"],
        ))
    }

    #[test]
    fn matches_each_facet() {
        let b = bindings();
        assert!(target_matches(
            &LockTarget {
                identities: vec!["alice".into()],
                ..tgt()
            },
            &b
        ));
        assert!(target_matches(
            &LockTarget {
                groups: vec!["admins".into()],
                ..tgt()
            },
            &b
        ));
        assert!(target_matches(
            &LockTarget {
                node_ids: vec!["node-1".into()],
                ..tgt()
            },
            &b
        ));
        // principal matches the requested principal...
        assert!(target_matches(
            &LockTarget {
                principals: vec!["deploy".into()],
                ..tgt()
            },
            &b
        ));
        // ...or any allowed login.
        assert!(target_matches(
            &LockTarget {
                principals: vec!["root".into()],
                ..tgt()
            },
            &b
        ));
        assert!(target_matches(
            &LockTarget {
                node_labels: vec!["env=prod".into()],
                ..tgt()
            },
            &b
        ));
        assert!(target_matches(&LockTarget { all: true, ..tgt() }, &b));
    }

    #[test]
    fn an_agent_peer_is_matched_by_identity_node_or_a_global_lock() {
        let b = LockBindings::for_agent("agent-7", "node-a");
        assert!(target_matches(
            &LockTarget {
                identities: vec!["agent-7".into()],
                ..tgt()
            },
            &b
        ));
        assert!(target_matches(
            &LockTarget {
                node_ids: vec!["node-a".into()],
                ..tgt()
            },
            &b
        ));
        assert!(target_matches(&LockTarget { all: true, ..tgt() }, &b));
        // A lock aimed at some other agent or node does not touch this one.
        assert!(!target_matches(
            &LockTarget {
                identities: vec!["agent-8".into()],
                node_ids: vec!["node-b".into()],
                ..tgt()
            },
            &b
        ));
    }

    #[test]
    fn empty_target_matches_nothing_but_all_matches_everything() {
        let b = bindings();
        // A facet-less, non-global target matches nothing (avoids a fleet wipe from
        // a malformed lock; a real global lock sets `all`).
        assert!(!target_matches(&tgt(), &b));
        // Non-matching facets do not match.
        assert!(!target_matches(
            &LockTarget {
                identities: vec!["mallory".into()],
                node_labels: vec!["env=dev".into()],
                ..tgt()
            },
            &b
        ));
    }

    fn lock(id: &str, target: LockTarget, expires: i64) -> Lock {
        lock_with_mode(id, target, expires, LockMode::Strict)
    }

    fn lock_with_mode(id: &str, target: LockTarget, expires: i64, mode: LockMode) -> Lock {
        Lock {
            lock_id: id.into(),
            target: Some(target),
            expires_at_epoch_seconds: expires,
            created_at_epoch_seconds: 0,
            reason: "test".into(),
            mode: mode as i32,
        }
    }

    #[test]
    fn teardown_mode_spares_only_best_effort() {
        // STRICT and UNSPECIFIED (a pre-S20 CP that sent no mode) tear down; only the explicit
        // BEST_EFFORT is spared; a garbled value fails safe to teardown (deny wins).
        assert!(tears_down_live_sessions(&lock_with_mode(
            "s",
            tgt(),
            0,
            LockMode::Strict
        )));
        assert!(tears_down_live_sessions(&lock_with_mode(
            "u",
            tgt(),
            0,
            LockMode::Unspecified
        )));
        assert!(!tears_down_live_sessions(&lock_with_mode(
            "b",
            tgt(),
            0,
            LockMode::BestEffort
        )));
        let mut garbled = lock_with_mode("g", tgt(), 0, LockMode::Strict);
        garbled.mode = 99;
        assert!(tears_down_live_sessions(&garbled));
    }

    #[test]
    fn best_effort_lock_still_denies_new_access() {
        // New-access denial is mode-agnostic: a BEST_EFFORT lock is returned by `matching`
        // (so it blocks new sessions/channels) exactly like STRICT — only teardown differs.
        let set = LockSet::new(30, 30);
        let b = bindings();
        set.replace_snapshot(
            vec![lock_with_mode(
                "be",
                LockTarget {
                    identities: vec!["alice".into()],
                    ..tgt()
                },
                0,
                LockMode::BestEffort,
            )],
            1,
        );
        assert_eq!(
            set.matching(&b).map(|l| l.lock_id),
            Some("be".into()),
            "a best_effort lock must still deny new access"
        );
    }

    #[test]
    fn lock_active_conservative_expiry() {
        let now = now_epoch_secs();
        assert!(lock_active(&lock("l", tgt(), 0), now, 30)); // no TTL = always
        assert!(lock_active(&lock("l", tgt(), now + 100), now, 30)); // unexpired
                                                                     // Expired but within the deny-preserving skew window: still active.
        assert!(lock_active(&lock("l", tgt(), now - 10), now, 30));
        // Clearly past expiry + skew: inactive.
        assert!(!lock_active(&lock("l", tgt(), now - 100), now, 30));
    }

    #[test]
    fn lockset_snapshot_add_remove_and_match() {
        let set = LockSet::new(30, 30);
        assert!(!set.healthy()); // never connected
        let b = bindings();
        assert!(set.matching(&b).is_none());

        set.replace_snapshot(
            vec![lock(
                "l1",
                LockTarget {
                    identities: vec!["alice".into()],
                    ..tgt()
                },
                0,
            )],
            7,
        );
        assert!(set.healthy()); // connected + fresh after a snapshot
        assert_eq!(set.matching(&b).map(|l| l.lock_id), Some("l1".into()));

        // A resync replaces the set wholesale.
        set.replace_snapshot(Vec::new(), 8);
        assert!(set.matching(&b).is_none());

        // Add then remove.
        set.add(lock("l2", LockTarget { all: true, ..tgt() }, 0));
        assert_eq!(set.matching(&b).map(|l| l.lock_id), Some("l2".into()));
        set.remove("l2");
        assert!(set.matching(&b).is_none());

        // Disconnect never clears the set (a pushed lock keeps denying).
        set.add(lock("l3", LockTarget { all: true, ..tgt() }, 0));
        set.mark_disconnected();
        assert!(!set.healthy());
        assert!(set.matching(&b).is_some());
    }
}
