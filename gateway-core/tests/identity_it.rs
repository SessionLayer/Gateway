//! Part B integration tests: bootstrap → enrollment → renewable mTLS identity,
//! generation counter, persist-before-adopt, lockable principal, and the
//! renew-ahead loop — all against the real mTLS mock CP.

mod support;

use gateway_core::identity;
use std::time::Duration;
use support::MockCp;

const CT: Duration = Duration::from_secs(5);
const RT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn enroll_issues_generation_zero_and_persists() {
    let cp = MockCp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    let cred = identity::enroll(
        &store,
        &cp.channel_params(CT, RT),
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-e",
    )
    .await
    .expect("enrollment issues an identity");

    assert_eq!(cred.generation, 0);
    assert!(!cred.gateway_id.is_empty());

    // Persist-before-adopt: the manifest is on disk and reloads identically.
    let loaded = store.load().unwrap().expect("persisted");
    assert_eq!(loaded.gateway_id, cred.gateway_id);
    assert_eq!(loaded.generation, 0);
    assert!(!loaded.ca_chain_der.is_empty());
}

#[tokio::test]
async fn enrollment_token_is_single_use() {
    let cp = MockCp::start().await;
    let token = cp.mint_enrollment_token();

    let dir1 = tempfile::tempdir().unwrap();
    let store1 = identity::IdentityStore::open(dir1.path()).unwrap();
    identity::enroll(
        &store1,
        &cp.channel_params(CT, RT),
        &cp.bootstrap_anchors(),
        &token,
        "gw-1",
    )
    .await
    .expect("first enrollment succeeds");

    // Replaying the same token is refused (atomic single-use).
    let dir2 = tempfile::tempdir().unwrap();
    let store2 = identity::IdentityStore::open(dir2.path()).unwrap();
    let err = identity::enroll(
        &store2,
        &cp.channel_params(CT, RT),
        &cp.bootstrap_anchors(),
        &token,
        "gw-2",
    )
    .await
    .expect_err("replayed enrollment token must be rejected");
    assert!(matches!(err, identity::IdentityError::Rpc(_)));
}

#[tokio::test]
async fn renew_rotates_cert_and_increments_generation_on_disk() {
    let cp = MockCp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    let params = cp.channel_params(CT, RT);

    let c0 = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-r",
    )
    .await
    .unwrap();
    let cert0 = c0.identity.cert_pem.clone();

    let c1 = identity::renew(&store, &params, &c0).await.expect("renew");
    assert_eq!(c1.generation, 1);
    assert_ne!(c1.identity.cert_pem, cert0, "the certificate rotated");

    // Persist-before-adopt: the on-disk generation is the new one.
    assert_eq!(store.load().unwrap().unwrap().generation, 1);
    assert_eq!(cp.recorded_generation(&c1.gateway_id), Some(1));
}

#[tokio::test]
async fn locked_identity_is_refused_and_credential_unchanged() {
    let cp = MockCp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    let params = cp.channel_params(CT, RT);

    let c0 = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-lock",
    )
    .await
    .unwrap();

    // A lockable principal: a locked identity cannot renew (fail closed).
    cp.lock_gateway(&c0.gateway_id);
    let err = identity::renew(&store, &params, &c0)
        .await
        .expect_err("a locked identity must be refused");
    assert!(matches!(err, identity::IdentityError::Rpc(_)));

    // The on-disk credential is unchanged — we never adopted anything.
    assert_eq!(store.load().unwrap().unwrap().generation, 0);
}

#[tokio::test]
async fn generation_mismatch_is_refused_and_flagged() {
    let cp = MockCp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    let params = cp.channel_params(CT, RT);

    let c0 = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-gen",
    )
    .await
    .unwrap();

    // The CP returns a forked generation (current + 2). The monotonic guard
    // refuses to adopt (§8.2 security event) and keeps the old credential.
    cp.force_next_renew_bad_generation();
    let err = identity::renew(&store, &params, &c0)
        .await
        .expect_err("a generation mismatch must be refused");
    assert!(matches!(
        err,
        identity::IdentityError::GenerationMismatch {
            expected: 1,
            got: 2
        }
    ));
    assert_eq!(
        store.load().unwrap().unwrap().generation,
        0,
        "did not adopt"
    );
}

#[tokio::test]
async fn renew_ahead_loop_renews_on_manual_trigger_and_persists() {
    // Drive the real renew-ahead loop deterministically via the manual trigger.
    let cp = MockCp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let store = identity::IdentityStore::open(&data_dir).unwrap();
    let params = cp.channel_params(CT, RT);

    let c0 = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-ahead",
    )
    .await
    .unwrap();
    let gateway_id = c0.gateway_id.clone();

    let renew_ahead = identity::RenewAhead::new(
        store,
        identity::RenewAheadConfig {
            renew_ahead_fraction: 2.0 / 3.0,
            renew_jitter_fraction: 0.1,
            retry_backoff: Duration::from_millis(50),
            channel: params,
        },
        c0,
    );
    let handle = renew_ahead.handle();
    let mut rx = handle.subscribe();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let loop_task = tokio::spawn(async move {
        let shutdown = Box::pin(async move {
            let _ = shutdown_rx.await;
        });
        renew_ahead.run(shutdown).await;
    });

    handle.trigger().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while rx.borrow_and_update().generation < 1 {
            rx.changed().await.unwrap();
        }
    })
    .await
    .expect("renew-ahead renewed within the bound");

    assert_eq!(handle.current().generation, 1);
    assert_eq!(cp.recorded_generation(&gateway_id), Some(1));

    // Stop the loop, which releases the data-dir lock, and confirm the new
    // generation is durably on disk.
    let _ = shutdown_tx.send(());
    let _ = loop_task.await;
    let reopened = identity::IdentityStore::open(&data_dir).unwrap();
    assert_eq!(reopened.load().unwrap().unwrap().generation, 1);
}

#[tokio::test]
async fn renew_ahead_stops_on_repair_needed_rejection() {
    // A rejection the CP will keep returning (here: a locked identity) must STOP
    // the renew-ahead loop — not spin in an infinite transient-retry (GW-GEN-DESYNC).
    let cp = MockCp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    let params = cp.channel_params(CT, RT);

    let c0 = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-repair",
    )
    .await
    .unwrap();
    let gateway_id = c0.gateway_id.clone();
    // Lock it: the next renew returns PermissionDenied (a repair-needed rejection).
    cp.lock_gateway(&gateway_id);

    let renew_ahead = identity::RenewAhead::new(
        store,
        identity::RenewAheadConfig {
            renew_ahead_fraction: 2.0 / 3.0,
            renew_jitter_fraction: 0.1,
            retry_backoff: Duration::from_millis(20),
            channel: params,
        },
        c0,
    );
    let handle = renew_ahead.handle();
    let mut rx = handle.subscribe();
    // No external shutdown: the loop must terminate itself on the repair-needed error.
    let loop_task = tokio::spawn(async move {
        renew_ahead
            .run(Box::pin(std::future::pending::<()>()))
            .await;
    });

    handle.trigger().await;

    // When the loop returns it drops the watch sender → `changed()` errors. If it
    // instead spun on transient retry, this would time out.
    let stopped = tokio::time::timeout(Duration::from_secs(5), async {
        while rx.changed().await.is_ok() {}
    })
    .await;
    assert!(
        stopped.is_ok(),
        "renew-ahead must stop on a repair-needed rejection, not infinite-retry"
    );
    // Never adopted a new generation.
    assert_eq!(cp.recorded_generation(&gateway_id), Some(0));
    let _ = loop_task.await;
}

/// The S12 busy-renew bug, ported from the Agent (which hit it first): a certificate
/// whose renew trigger is ALREADY past yields a zero delay, so after a successful
/// renewal the loop would re-derive the same zero delay and renew again immediately —
/// hammering the CP and burning a generation per iteration.
///
/// This exercises the LOOP, not `compute_renew_delay`: the existing unit tests assert
/// the ZERO delay is *correct* and would never have caught the spin it causes.
#[tokio::test]
async fn renew_ahead_loop_does_not_spin_when_the_renew_trigger_is_already_past() {
    let cp = MockCp::builder()
        .cert_ttl(Duration::from_secs(3600))
        .start()
        .await;
    let dir = tempfile::tempdir().unwrap();
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    let params = cp.channel_params(CT, RT);
    let cred = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-storm",
    )
    .await
    .unwrap();
    let gateway_id = cred.gateway_id.clone();

    let renew_ahead = identity::RenewAhead::new(
        store,
        identity::RenewAheadConfig {
            // fraction 0 => the trigger instant is not_before, which is always in the
            // past => compute_renew_delay returns ZERO on EVERY iteration.
            renew_ahead_fraction: 0.0,
            renew_jitter_fraction: 0.0,
            retry_backoff: Duration::from_millis(20),
            channel: params,
        },
        cred,
    );
    let loop_task = tokio::spawn(async move {
        renew_ahead
            .run(Box::pin(std::future::pending::<()>()))
            .await;
    });

    // Give the loop a couple of seconds of wall-clock to misbehave in.
    tokio::time::sleep(Duration::from_secs(2)).await;
    loop_task.abort();

    // With the floor: the first iteration renews at once (correct — a credential loaded
    // past its trigger should refresh), then waits RENEW_MIN_INTERVAL (60s). So exactly
    // ONE renewal. Without it, the loop would have burned dozens.
    assert_eq!(
        cp.recorded_generation(&gateway_id),
        Some(1),
        "the post-renewal floor must bound the loop to one renewal in this window"
    );
}
