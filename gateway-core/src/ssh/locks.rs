use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pb::{DecisionContext, Lock, LockMode, LockTarget, SessionEndReason};

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

fn tears_down_live_sessions(lock: &Lock) -> bool {
    lock.mode != LockMode::BestEffort as i32
}

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

pub struct LockSet {
    locks: RwLock<HashMap<String, Lock>>,
    connected: AtomicBool,
    last_activity: AtomicU64,
    unhealthy_after_secs: u64,
    skew_secs: i64,
    feed_epoch: AtomicU64,
}

impl LockSet {
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

    pub fn add(&self, lock: Lock) {
        self.locks
            .write()
            .unwrap()
            .insert(lock.lock_id.clone(), lock);
        self.touch();
    }

    pub fn remove(&self, lock_id: &str) {
        self.locks.write().unwrap().remove(lock_id);
        self.touch();
    }

    pub fn touch(&self) {
        self.last_activity
            .store(now_epoch_secs().max(0) as u64, Ordering::SeqCst);
    }

    /// Marks stream down; set NOT cleared (locks stay active under datastore loss).
    pub fn mark_disconnected(&self) {
        self.connected.store(false, Ordering::SeqCst);
    }

    pub fn healthy(&self) -> bool {
        if !self.connected.load(Ordering::SeqCst) {
            return false;
        }
        let last = self.last_activity.load(Ordering::SeqCst) as i64;
        now_epoch_secs().saturating_sub(last) <= self.unhealthy_after_secs as i64
    }

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

/// Generic message for all policy teardowns (non-disclosure: attacker cannot tell lock from expiry).
const TEARDOWN_DISCONNECT: &str = "session closed by policy";

#[derive(Clone)]
pub struct SessionControl {
    bindings: Arc<Mutex<LockBindings>>,
    handle: russh::server::Handle,
    abort: Arc<AtomicBool>,
    terminated: Arc<AtomicBool>,
    end_reason: Arc<AtomicI32>,
}

impl SessionControl {
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

    pub fn update_bindings(&self, bindings: LockBindings) {
        *self.bindings.lock().unwrap() = bindings;
    }

    pub fn shared_bindings(&self) -> Arc<Mutex<LockBindings>> {
        self.bindings.clone()
    }

    fn matches(&self, target: &LockTarget) -> bool {
        target_matches(target, &self.bindings.lock().unwrap())
    }

    pub fn terminate_with(&self, reason: SessionEndReason) {
        let _ = self.end_reason.compare_exchange(
            SessionEndReason::Unspecified as i32,
            reason as i32,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        self.terminate();
    }

    pub fn end_reason(&self) -> SessionEndReason {
        SessionEndReason::try_from(self.end_reason.load(Ordering::SeqCst))
            .unwrap_or(SessionEndReason::Unspecified)
    }

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

#[derive(Default)]
pub struct LiveSessionRegistry {
    sessions: Mutex<HashMap<String, SessionControl>>,
}

impl LiveSessionRegistry {
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

    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn apply_added_lock(&self, lock: &Lock) -> usize {
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

    pub fn terminate_all(&self) -> usize {
        let victims: Vec<SessionControl> = {
            let sessions = self.sessions.lock().unwrap();
            sessions.values().cloned().collect()
        };
        for c in &victims {
            c.terminate_with(SessionEndReason::Closed);
        }
        victims.len()
    }

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
        assert!(target_matches(
            &LockTarget {
                principals: vec!["deploy".into()],
                ..tgt()
            },
            &b
        ));
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
        assert!(lock_active(&lock("l", tgt(), 0), now, 30));
        assert!(lock_active(&lock("l", tgt(), now + 100), now, 30));
        assert!(lock_active(&lock("l", tgt(), now - 10), now, 30));
        assert!(!lock_active(&lock("l", tgt(), now - 100), now, 30));
    }

    #[test]
    fn lockset_snapshot_add_remove_and_match() {
        let set = LockSet::new(30, 30);
        assert!(!set.healthy());
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
        assert!(set.healthy());
        assert_eq!(set.matching(&b).map(|l| l.lock_id), Some("l1".into()));

        set.replace_snapshot(Vec::new(), 8);
        assert!(set.matching(&b).is_none());

        set.add(lock("l2", LockTarget { all: true, ..tgt() }, 0));
        assert_eq!(set.matching(&b).map(|l| l.lock_id), Some("l2".into()));
        set.remove("l2");
        assert!(set.matching(&b).is_none());

        set.add(lock("l3", LockTarget { all: true, ..tgt() }, 0));
        set.mark_disconnected();
        assert!(!set.healthy());
        assert!(set.matching(&b).is_some());
    }
}
