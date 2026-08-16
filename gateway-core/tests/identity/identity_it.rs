use crate::support::MockCp;
use gateway_core::identity;
use std::time::Duration;

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

    cp.lock_gateway(&c0.gateway_id);
    let err = identity::renew(&store, &params, &c0)
        .await
        .expect_err("a locked identity must be refused");
    assert!(matches!(err, identity::IdentityError::Rpc(_)));

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

    let _ = shutdown_tx.send(());
    let _ = loop_task.await;
    let reopened = identity::IdentityStore::open(&data_dir).unwrap();
    assert_eq!(reopened.load().unwrap().unwrap().generation, 1);
}

#[tokio::test]
async fn renew_ahead_stops_on_repair_needed_rejection() {
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
    let loop_task = tokio::spawn(async move {
        renew_ahead
            .run(Box::pin(std::future::pending::<()>()))
            .await;
    });

    handle.trigger().await;

    let stopped = tokio::time::timeout(Duration::from_secs(5), async {
        while rx.changed().await.is_ok() {}
    })
    .await;
    assert!(
        stopped.is_ok(),
        "renew-ahead must stop on a repair-needed rejection, not infinite-retry"
    );
    assert_eq!(cp.recorded_generation(&gateway_id), Some(0));
    let _ = loop_task.await;
}

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
            renew_ahead_fraction: 0.0,
            renew_jitter_fraction: 0.0,
            retry_backoff: Duration::from_millis(20),
            channel: params,
        },
        cred,
    );
    let handle = renew_ahead.handle();
    let mut rx = handle.subscribe();
    let loop_task = tokio::spawn(async move {
        renew_ahead
            .run(Box::pin(std::future::pending::<()>()))
            .await;
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        while rx.borrow_and_update().generation < 1 {
            rx.changed().await.unwrap();
        }
    })
    .await
    .expect("the loop must renew once promptly (immediate trigger, renew_ahead_fraction=0.0)");

    // The property under test is that it STAYS at one renewal, not just that it
    // reaches one -- so watch for a real further change rather than trusting a
    // fixed window to be long enough to reveal a spin without also risking a
    // flake on a slow box. Timing out here (no further change) is the passing case.
    let spun = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match rx.changed().await {
                Ok(()) if rx.borrow().generation > 1 => return true,
                Ok(()) => continue,
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    loop_task.abort();

    assert!(
        !spun,
        "the post-renewal floor must bound the loop to one renewal, not keep going"
    );
    assert_eq!(cp.recorded_generation(&gateway_id), Some(1));
}

/// When the CP issues a certificate that is ALREADY EXPIRED at the Gateway's clock (clock
/// skew beyond the TTL, or a near-zero CP TTL), a `remaining/2` cap on the post-renewal
/// floor collapses it to zero and the loop renews at RPC rate. The RPC keeps *succeeding*
/// (the CP validates against its own clock), so nothing self-limits, and each iteration
/// churns the generation counter, which is the clone-detection primitive.
///
/// This drives the real LOOP (not the helper) with `cert_ttl(0)` — `validity_window()` then
/// returns not_after = now, i.e. "the certificate the CP issued is already expired at us".
/// The bound must be retry-bounded, NOT terminal: a terminal exit on a fleet-wide CP
/// misconfig would be fail-deadly, so the loop keeps running at a few generations over the
/// window instead of hundreds.
#[tokio::test]
async fn renew_ahead_loop_does_not_storm_when_the_cp_issues_an_already_expired_cert() {
    let cp = MockCp::builder()
        .cert_ttl(Duration::from_secs(0))
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
        "gw-storm2",
    )
    .await
    .unwrap();
    let gateway_id = cred.gateway_id.clone();

    let renew_ahead = identity::RenewAhead::new(
        store,
        identity::RenewAheadConfig {
            renew_ahead_fraction: 2.0 / 3.0,
            renew_jitter_fraction: 0.1,
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

    tokio::time::sleep(Duration::from_secs(3)).await;

    let gens = cp.recorded_generation(&gateway_id).unwrap_or(0);
    assert!(
        (1..=5).contains(&gens),
        "generations={gens}: expected a bounded 1..=5 (storm would be dozens; 0 means it never renewed)"
    );
    assert!(
        !loop_task.is_finished(),
        "the loop must keep retrying (bounded), not exit"
    );
    loop_task.abort();
}
