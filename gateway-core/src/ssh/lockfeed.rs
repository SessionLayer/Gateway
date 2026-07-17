//! The CP -> Gateway lock-feed stream client (Session Ten; FR-CHAN-3, §8.4).
//!
//! A background task that holds an open `LockFeed.StreamLocks` server stream,
//! applies the authoritative snapshot + incremental add/remove events into the
//! shared [`LockSet`], and tears down matching live sessions on a newly-pushed
//! lock. On any disconnect it marks the feed unhealthy (which forces per-channel
//! re-validate) but NEVER clears the set — a previously-pushed lock keeps denying
//! under datastore/CP loss — and reconnects with backoff, resyncing from a fresh
//! snapshot.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::cpauth::CpChannelFactory;
use crate::pb::lock_feed_client::LockFeedClient;
use crate::pb::{lock_event::Event, StreamLocksRequest};
use crate::ssh::locks::{LiveSessionRegistry, LockSet};
use crate::version;

/// Reconnect backoff bounds for the lock feed.
const BACKOFF_START: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(10);

/// Owns the lock-feed background task: keeps the deny-set current and tears down
/// locked live sessions.
pub struct LockFeedClientTask {
    factory: Arc<CpChannelFactory>,
    lock_set: Arc<LockSet>,
    registry: Arc<LiveSessionRegistry>,
    connect_timeout: Duration,
}

impl LockFeedClientTask {
    /// Build the feed task over the CP channel factory + shared lock state.
    pub fn new(
        factory: Arc<CpChannelFactory>,
        lock_set: Arc<LockSet>,
        registry: Arc<LiveSessionRegistry>,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            factory,
            lock_set,
            registry,
            connect_timeout,
        }
    }

    /// Spawn the feed loop; it runs until `shutdown` flips true.
    pub fn spawn(self, shutdown: watch::Receiver<bool>) {
        tokio::spawn(self.run(shutdown));
    }

    async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut backoff = BACKOFF_START;
        loop {
            if *shutdown.borrow() {
                return;
            }
            match self.connect_and_stream(&mut shutdown, &mut backoff).await {
                Ok(()) => return, // clean shutdown
                Err(e) => {
                    self.lock_set.mark_disconnected();
                    tracing::warn!(error = %e, outcome = "lock_feed_disconnected", "lock feed stream down; deny-set retained (fail closed), reconnecting");
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                res = shutdown.changed() => { if res.is_err() || *shutdown.borrow() { return; } }
            }
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    /// One connect + stream lifetime. Returns Ok(()) only on a requested shutdown.
    /// Resets `backoff` once the stream is established, so a healthy reconnect after
    /// a flap does not inherit an escalated delay.
    async fn connect_and_stream(
        &self,
        shutdown: &mut watch::Receiver<bool>,
        backoff: &mut Duration,
    ) -> Result<(), String> {
        let channel = tokio::time::timeout(self.connect_timeout, self.factory.open_channel())
            .await
            .map_err(|_| "connect timeout".to_string())?
            .map_err(|e| e.to_string())?;

        let mut client = LockFeedClient::new(crate::telemetry::trace_channel(channel));
        let req = StreamLocksRequest {
            client: Some(version::component_info()),
        };
        let mut stream = client
            .stream_locks(req)
            .await
            .map_err(|s| format!("StreamLocks failed: {:?}", s.code()))?
            .into_inner();

        *backoff = BACKOFF_START;
        tracing::info!(
            outcome = "lock_feed_connected",
            "lock feed stream established"
        );
        loop {
            tokio::select! {
                item = stream.message() => {
                    match item {
                        Ok(Some(event)) => self.apply(event),
                        Ok(None) => return Err("stream closed by CP".to_string()),
                        Err(s) => return Err(format!("stream error: {:?}", s.code())),
                    }
                }
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() { return Ok(()); }
                }
            }
        }
    }

    fn apply(&self, event: crate::pb::LockEvent) {
        let Some(ev) = event.event else {
            self.lock_set.touch();
            return;
        };
        match ev {
            Event::Snapshot(snap) => {
                let n = snap.locks.len();
                self.lock_set.replace_snapshot(snap.locks, snap.feed_epoch);
                // A resync may carry locks that arrived while we were disconnected;
                // tear down any live session they match (deny wins).
                let torn = self.registry.reconcile(&self.lock_set);
                tracing::info!(
                    locks = n,
                    feed_epoch = snap.feed_epoch,
                    torn_down = torn,
                    outcome = "lock_snapshot",
                    "lock deny-set resynced"
                );
            }
            Event::Added(lock) => {
                let id = crate::ssh::handler::sanitize(&lock.lock_id);
                // Add to the deny-set FIRST, then scan the registry: this closes the
                // teardown TOCTOU — a session that registers concurrently is caught
                // by the scan, and a session whose per-channel lock-check races the
                // add sees it in the set (pairs with the handler's post-register
                // re-check).
                self.lock_set.add(lock.clone());
                let torn = self.registry.apply_added_lock(&lock);
                tracing::info!(lock_id = %id, torn_down = torn, outcome = "lock_added", "lock pushed; matching live sessions torn down");
            }
            Event::Removed(rm) => {
                self.lock_set.remove(&rm.lock_id);
                tracing::info!(lock_id = %crate::ssh::handler::sanitize(&rm.lock_id), outcome = "lock_removed", "lock cleared");
            }
            Event::Heartbeat(_) => self.lock_set.touch(),
        }
    }
}
