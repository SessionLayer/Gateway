//! Part D end-to-end test: the Gateway's full inner-leg flow, proven against a
//! **real Debian 13 OpenSSH node** in a Docker container — never host ssh.
//!
//! Flow: enroll for an mTLS identity → generate the inner keypair locally →
//! obtain a session-bound inner certificate via `SignSessionCertificate` (the
//! mock CP signs the Gateway-presented public key with its SSH session CA) →
//! present the cert to a node that trusts the session CA via `TrustedUserCAKeys`
//! → complete a real cert-authenticated SSH handshake and run `echo`.
//!
//! The SSH client runs **inside** the node container against the node's own
//! sshd (loopback), so the whole handshake is containerised. The harness is
//! written to be reused by the S7/S8 SSH legs.

mod support;

use gateway_core::{identity, mtls, signing};
use std::time::Duration;
use support::MockCp;
use testcontainers::core::{ExecCommand, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{CopyTargetOptions, GenericImage, ImageExt};

const CT: Duration = Duration::from_secs(5);
const RT: Duration = Duration::from_secs(10);
const NODE_IMAGE: &str = "sessionlayer-gw-testnode";
const NODE_TAG: &str = "s4";

/// Point Testcontainers/bollard at whatever Docker endpoint the `docker` CLI is
/// configured to use (honours a rootless-mode context, whose socket differs from
/// the default `/var/run/docker.sock`). No-op if `DOCKER_HOST` is already set or
/// the endpoint can't be resolved (leaving bollard's default in place).
fn ensure_docker_host() {
    if std::env::var_os("DOCKER_HOST").is_some() {
        return;
    }
    if let Ok(out) = std::process::Command::new("docker")
        .args([
            "context",
            "inspect",
            "--format",
            "{{.Endpoints.docker.Host}}",
        ])
        .output()
    {
        let host = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() && !host.is_empty() {
            std::env::set_var("DOCKER_HOST", host);
        }
    }
}

/// Build the vendored Debian 13 sshd node image (idempotent; Docker layer-caches
/// so repeat runs are fast). Uses the `docker` CLI to assemble the image, which
/// Testcontainers then runs.
async fn build_node_image() -> anyhow::Result<()> {
    ensure_docker_host();
    // The vendored Debian 13 node lives at the repo root `tests/fixtures/sshd`
    // (CARGO_MANIFEST_DIR is the gateway-core crate, one level down).
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gateway-core has a parent (workspace root)")
        .join("tests/fixtures/sshd");
    anyhow::ensure!(dir.is_dir(), "vendored node dir missing: {}", dir.display());
    let tag = format!("{NODE_IMAGE}:{NODE_TAG}");
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("docker")
            .args(["build", "-t", &tag])
            .arg(&dir)
            .output()
    })
    .await??;
    anyhow::ensure!(
        output.status.success(),
        "docker build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[tokio::test]
async fn signed_inner_cert_is_accepted_by_a_real_node() -> anyhow::Result<()> {
    build_node_image().await?;

    // Mock CP with an SSH session CA.
    let cp = MockCp::start().await;

    // Enroll → renewable mTLS identity.
    let dir = tempfile::tempdir()?;
    let store = identity::IdentityStore::open(dir.path())?;
    let params = cp.channel_params(CT, RT);
    let cred = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-e2e",
    )
    .await?;

    // Generate the inner keypair locally; obtain a session-bound certificate.
    let token = cp.mint_session_token(
        &cred.gateway_id,
        "sess-e2e",
        "node-e2e",
        "deploy",
        Duration::from_secs(120),
    );
    let inner = signing::InnerKeyPair::generate()?;
    let channel = mtls::connect_mtls(&params, &cred.ca_chain_der, &cred.identity).await?;
    let signed = signing::sign_session_certificate(channel, &token, &inner, None, RT).await?;
    assert_eq!(signed.key_id, "sess-e2e+deploy");

    // Materialize the inner key + issued cert for the in-container ssh client.
    let key_pem = inner.private_key_openssh_pem()?.as_bytes().to_vec();
    let cert_line = signed.certificate_line.clone().into_bytes();

    // Start the node trusting the session CA; copy the key (0600) + cert in.
    let node = GenericImage::new(NODE_IMAGE, NODE_TAG)
        .with_wait_for(WaitFor::message_on_stderr("Server listening on"))
        .with_startup_timeout(Duration::from_secs(120))
        .with_env_var("TRUSTED_USER_CA", cp.session_ca_public_line())
        .with_copy_to(
            CopyTargetOptions::new("/certs/inner").with_mode(0o600),
            key_pem,
        )
        .with_copy_to(
            CopyTargetOptions::new("/certs/inner-cert.pub").with_mode(0o644),
            cert_line,
        )
        .start()
        .await?;

    // Real, cert-authenticated SSH handshake INSIDE the container (never host
    // ssh): the client presents the inner cert to the node's own sshd.
    let marker = "sessionlayer-s4-e2e-ok";
    let cmd = ExecCommand::new([
        "ssh",
        "-i",
        "/certs/inner",
        "-o",
        "CertificateFile=/certs/inner-cert.pub",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "deploy@localhost",
        "echo",
        marker,
    ]);
    let mut result = node.exec(cmd).await?;
    // Drain stdout/stderr to completion *before* reading the exit code (the
    // command runs until its pipes are consumed).
    let stdout = String::from_utf8_lossy(&result.stdout_to_vec().await?).into_owned();
    let stderr = String::from_utf8_lossy(&result.stderr_to_vec().await?).into_owned();
    let code = result.exit_code().await?;

    assert_eq!(
        code,
        Some(0),
        "cert-authenticated SSH handshake must succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(marker),
        "expected echo marker in stdout; stdout={stdout:?} stderr={stderr:?}"
    );

    Ok(())
}

/// FR-AUD-4: the node's OWN sshd auth log is a tamper-independent SECOND trail. On a
/// cert login the node (VERBOSE) records the certificate **key-id**, which is
/// `session_id + identity` — the exact correlation handle the CP records for the
/// cert it signed (`signed_key_ids`, standing in for the `audit_event` row here).
/// Prove the node-log key-id and the CP's record cross-correlate.
#[tokio::test]
async fn node_sshd_log_key_id_cross_correlates_with_the_cp_signed_cert() -> anyhow::Result<()> {
    build_node_image().await?;
    let cp = MockCp::start().await;

    let dir = tempfile::tempdir()?;
    let store = identity::IdentityStore::open(dir.path())?;
    let params = cp.channel_params(CT, RT);
    let cred = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-aud4",
    )
    .await?;

    let session_id = "sess-aud4";
    let principal = "deploy";
    let token = cp.mint_session_token(
        &cred.gateway_id,
        session_id,
        "node-aud4",
        principal,
        Duration::from_secs(120),
    );
    let inner = signing::InnerKeyPair::generate()?;
    let channel = mtls::connect_mtls(&params, &cred.ca_chain_der, &cred.identity).await?;
    let signed = signing::sign_session_certificate(channel, &token, &inner, None, RT).await?;
    // The key-id the node will log == session_id + identity, and the CP recorded it.
    let expected_key_id = format!("{session_id}+{principal}");
    assert_eq!(signed.key_id, expected_key_id);
    assert!(
        cp.signed_key_ids().contains(&expected_key_id),
        "the CP recorded the signed cert's key-id (the audit correlation handle)"
    );

    let node = GenericImage::new(NODE_IMAGE, NODE_TAG)
        .with_wait_for(WaitFor::message_on_stderr("Server listening on"))
        .with_startup_timeout(Duration::from_secs(120))
        .with_env_var("TRUSTED_USER_CA", cp.session_ca_public_line())
        .with_copy_to(
            CopyTargetOptions::new("/certs/inner").with_mode(0o600),
            inner.private_key_openssh_pem()?.as_bytes().to_vec(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/certs/inner-cert.pub").with_mode(0o644),
            signed.certificate_line.clone().into_bytes(),
        )
        .start()
        .await?;

    let cmd = ExecCommand::new([
        "ssh",
        "-i",
        "/certs/inner",
        "-o",
        "CertificateFile=/certs/inner-cert.pub",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "deploy@localhost",
        "true",
    ]);
    let mut result = node.exec(cmd).await?;
    let _ = result.stdout_to_vec().await?;
    let code = result.exit_code().await?;
    assert_eq!(
        code,
        Some(0),
        "the cert login must succeed so the node logs the key-id"
    );

    // The node's own sshd VERBOSE auth log (its container stderr) is the second trail:
    // it records the cert key-id, cross-correlatable with the CP's signed_key_ids.
    let mut node_log = String::new();
    for _ in 0..40 {
        node_log = String::from_utf8_lossy(&node.stderr_to_vec().await?).into_owned();
        if node_log.contains(&expected_key_id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        node_log.contains(&expected_key_id),
        "the node sshd log must carry the cert key-id (session_id+identity); log tail:\n{}",
        &node_log[node_log.len().saturating_sub(2000)..]
    );
    // The key-id decomposes as session_id + identity, matching the CP record — the
    // node-local trail and the CP audit trail resolve to the SAME session.
    assert!(
        node_log.contains(session_id),
        "the node log carries the session_id"
    );
    assert_eq!(
        signed.key_id,
        *cp.signed_key_ids().last().unwrap(),
        "the node-logged key-id equals the CP's recorded signed key-id"
    );

    drop(node);
    Ok(())
}
