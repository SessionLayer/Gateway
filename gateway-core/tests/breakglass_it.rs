//! Session Thirteen end-to-end: the **break-glass access model** (Design §7,
//! FR-ACC-6/8).
//!
//! Break-glass is the always-available, IdP-independent override path. This file
//! proves, against the real russh outer leg + a real node + the in-process mock CP:
//!
//! - a **real FIDO2 `sk-ecdsa` login** end-to-end: the client image bakes OpenSSH's
//!   `sk-dummy.so` (a virtual authenticator), so stock `ssh` produces a genuine FIDO
//!   possession signature that russh verifies before the Gateway resolves the key as
//!   a break-glass credential — the PRIMARY break-glass auth path;
//! - a single-use **offline code** (keyboard-interactive) authenticates a live
//!   break-glass session on a node, fires the activation + alert, and is rejected
//!   on replay;
//! - break-glass **forces strict recording**: a break-glass session whose recording
//!   cannot start is torn down even when the recorder config is non-strict;
//! - a **locked target refuses break-glass** (deny wins — the CP still records the
//!   activation, then denies);
//! - break-glass works when the **primary IdP / device flow is down**;
//! - a revoke-as-lock **tears down a live break-glass session** via the S10 path.
//!
//! Networking mirrors S8/S9: the client container is `--network host`; the node +
//! MinIO run on the bridge with mapped ports.

mod support;

use std::sync::Arc;
use std::time::Duration;

use gateway_core::config::{
    BreakGlassConfig, DeviceFlowConfig, InnerLegServerConfig, MidSessionExpiryMode, RecorderConfig,
    SshServerConfig,
};
use gateway_core::pb::{KeySealAlgorithm, RecordingStatus};
use gateway_core::ssh;
use gateway_core::ssh::handler::{ConnState, SshHandler};
use p256::pkcs8::EncodePublicKey;
use rand_core::OsRng;
use russh::server::{Auth, Handler};
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use support::sigv4::{self, S3Target};
use support::{MockCp, RecorderChoice};
use testcontainers::core::{ExecCommand, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient";
const CLIENT_TAG: &str = "s13";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode";
const NODE_TAG: &str = "s13";
const NODE_ID: &str = "node-bg";
const MINIO_IMAGE: &str = "minio/minio";
const MINIO_TAG: &str = "RELEASE.2025-04-08T15-41-24Z";
const MINIO_USER: &str = "minioadmin";
const MINIO_PASS: &str = "minioadmin";
const BUCKET: &str = "recordings";

const RECORDING_UNAVAILABLE: &str = "recording unavailable";

// ── The deterministic sk-ecdsa RESOLUTION unit-proof (no Docker) ──────────────
//
// The full FIDO2 login is proven in `sk_ecdsa_fido2_break_glass_session_e2e` below
// (real authenticator, real signature). This is its fast complement: it pins the
// handler's ROUTING without any container — a real `sk-ecdsa` public key offered to
// `auth_publickey` is detected as a security key, serialized to its OpenSSH wire
// blob, and resolved via the CP break-glass resolver (which mints the single-use
// token); an UNREGISTERED sk key degrades to the next method (fail closed).

/// Assemble a well-formed OpenSSH `sk-ecdsa-sha2-nistp256@openssh.com` public key
/// from a fresh P-256 point (the private half is irrelevant here — this test drives
/// `auth_publickey` directly, past russh's signature check).
fn make_sk_ecdsa_pubkey() -> russh::keys::PublicKey {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = p256::SecretKey::random(&mut OsRng);
    let point = secret.public_key().to_encoded_point(false); // uncompressed SEC1
    let mut blob = Vec::new();
    push_ssh_string(&mut blob, b"sk-ecdsa-sha2-nistp256@openssh.com");
    push_ssh_string(&mut blob, b"nistp256");
    push_ssh_string(&mut blob, point.as_bytes());
    push_ssh_string(&mut blob, b"ssh:"); // FIDO application
    russh::keys::PublicKey::from_bytes(&blob).expect("valid sk-ecdsa public key blob")
}

fn push_ssh_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

#[tokio::test]
async fn sk_ecdsa_publickey_resolves_to_break_glass() {
    let cp = MockCp::start().await;
    let config = Arc::new(SshServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        login_grace_secs: 30,
        ..Default::default()
    });
    let deps = support::outer_leg_deps(&cp, config).await;

    let sk = make_sk_ecdsa_pubkey();
    cp.register_break_glass_key(sk.to_bytes().unwrap(), "breakglass-admin", &["deploy"]);

    let conn = Arc::new(ConnState::default());
    let mut handler = SshHandler::new(deps, "10.9.9.9".parse().unwrap(), conn);

    // A registered sk-ecdsa key authenticates via the break-glass path (russh's own
    // FIDO signature verification is exercised in the full E2E when a provider is
    // available; here we drive the resolution routing directly).
    let auth = handler
        .auth_publickey("deploy%node-bg", &sk)
        .await
        .expect("auth_publickey");
    assert!(
        matches!(auth, Auth::Accept),
        "a registered break-glass sk-ecdsa key must authenticate"
    );
    assert_eq!(
        cp.breakglass_token_count(),
        1,
        "the CP minted exactly one single-use break-glass token"
    );

    // An UNREGISTERED security key degrades to the next method (no break-glass).
    let other = make_sk_ecdsa_pubkey();
    let auth2 = handler
        .auth_publickey("deploy%node-bg", &other)
        .await
        .expect("auth_publickey");
    assert!(
        matches!(auth2, Auth::Reject { .. }),
        "an unregistered sk-ecdsa key must degrade, not authenticate"
    );
    assert_eq!(
        cp.breakglass_token_count(),
        1,
        "no extra token is minted for an unresolved key (fail closed)"
    );
}

/// Divergence D6: a normal sk-ecdsa USER key (registered as a PIN, not a break-glass
/// credential) must FALL THROUGH the break-glass resolver to the ordinary pin path
/// and authenticate — never a hard reject. sk-ed25519 and every other algorithm skip
/// the break-glass branch entirely and go straight to the pin path.
#[tokio::test]
async fn sk_ecdsa_non_breakglass_key_falls_through_to_pin() {
    let cp = MockCp::start().await;
    let config = Arc::new(SshServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        login_grace_secs: 30,
        ..Default::default()
    });
    let deps = support::outer_leg_deps(&cp, config).await;

    // A normal sk-ecdsa user key: a PIN, NOT a registered break-glass credential.
    let sk = make_sk_ecdsa_pubkey();
    let fp = sk.fingerprint(russh::keys::HashAlg::Sha256).to_string();
    cp.register_pin(&fp, "alice", &["deploy"]);

    let conn = Arc::new(ConnState::default());
    let mut handler = SshHandler::new(deps, "10.9.9.10".parse().unwrap(), conn);
    let auth = handler
        .auth_publickey("deploy%node-bg", &sk)
        .await
        .expect("auth_publickey");
    assert!(
        matches!(auth, Auth::Accept),
        "a normal sk-ecdsa pin user must authenticate via the pin path (break-glass falls through)"
    );
    assert_eq!(
        cp.breakglass_token_count(),
        0,
        "a non-break-glass sk key mints NO break-glass token"
    );
}

// ── Docker E2E scaffolding (mirrors recorder_it.rs) ──────────────────────────

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

async fn build_image(subdir: &str, tag: &str) -> anyhow::Result<()> {
    ensure_docker_host();
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures")
        .join(subdir);
    anyhow::ensure!(dir.is_dir(), "fixture missing: {}", dir.display());
    let tag = tag.to_string();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("docker")
            .args(["build", "-t", &tag])
            .arg(&dir)
            .output()
    })
    .await??;
    anyhow::ensure!(
        out.status.success(),
        "docker build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

async fn build_images() -> anyhow::Result<()> {
    build_image("ssh-client", &format!("{CLIENT_IMAGE}:{CLIENT_TAG}")).await?;
    build_image("sshd", &format!("{NODE_IMAGE}:{NODE_TAG}")).await?;
    Ok(())
}

struct KeyMat {
    private_openssh: String,
    public_line: String,
    public_wire: Vec<u8>,
    fingerprint: String,
}

fn gen_key(alg: Algorithm) -> KeyMat {
    let key = PrivateKey::random(&mut OsRng, alg).unwrap();
    KeyMat {
        private_openssh: key.to_openssh(LineEnding::LF).unwrap().to_string(),
        public_line: key.public_key().to_openssh().unwrap(),
        public_wire: key.public_key().to_bytes().unwrap(),
        fingerprint: key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
    }
}

fn customer_keypair() -> Vec<u8> {
    let secret = p256::SecretKey::random(&mut OsRng);
    secret
        .public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}

async fn start_node(
    cp: &MockCp,
    host_key: &KeyMat,
) -> anyhow::Result<(ContainerAsync<GenericImage>, u16)> {
    let node = GenericImage::new(NODE_IMAGE, NODE_TAG)
        .with_wait_for(WaitFor::message_on_stderr("Server listening on"))
        .with_startup_timeout(Duration::from_secs(120))
        .with_env_var("TRUSTED_USER_CA", cp.session_ca_public_line())
        .with_copy_to(
            CopyTargetOptions::new("/etc/ssh/ssh_host_ed25519_key").with_mode(0o600),
            host_key.private_openssh.clone().into_bytes(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/etc/ssh/ssh_host_ed25519_key.pub").with_mode(0o644),
            host_key.public_line.clone().into_bytes(),
        )
        .start()
        .await?;
    let port = node.get_host_port_ipv4(22).await?;
    Ok((node, port))
}

async fn start_minio() -> anyhow::Result<(ContainerAsync<GenericImage>, S3Target)> {
    ensure_docker_host();
    let container = GenericImage::new(MINIO_IMAGE, MINIO_TAG)
        .with_wait_for(WaitFor::message_on_stderr("API:"))
        .with_startup_timeout(Duration::from_secs(120))
        .with_env_var("MINIO_ROOT_USER", MINIO_USER)
        .with_env_var("MINIO_ROOT_PASSWORD", MINIO_PASS)
        .with_cmd(["server", "/data"])
        .start()
        .await?;
    let port = container.get_host_port_ipv4(9000).await?;
    let s3 = S3Target {
        endpoint: format!("127.0.0.1:{port}"),
        access_key: MINIO_USER.to_string(),
        secret_key: MINIO_PASS.to_string(),
        region: "us-east-1".to_string(),
        bucket: BUCKET.to_string(),
    };
    wait_minio_ready(&s3).await?;
    create_bucket_with_lock(&s3).await?;
    Ok((container, s3))
}

async fn wait_minio_ready(s3: &S3Target) -> anyhow::Result<()> {
    let url = format!("http://{}/minio/health/live", s3.endpoint);
    for _ in 0..120 {
        if let Ok((status, _)) = sigv4::http_send("GET", &url, &[], Vec::new()).await {
            if status == 200 {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("MinIO did not become ready");
}

async fn create_bucket_with_lock(s3: &S3Target) -> anyhow::Result<()> {
    let path = format!("/{}", s3.bucket);
    let (url, headers) = sigv4::presign(
        s3,
        "PUT",
        &path,
        &[],
        &[("x-amz-bucket-object-lock-enabled", "true")],
        900,
    );
    let hdrs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let (status, body) = sigv4::http_send("PUT", &url, &hdrs, Vec::new()).await?;
    anyhow::ensure!(
        status == 200,
        "create bucket failed ({status}): {}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}

async fn start_gateway(
    cp: &MockCp,
    config: Arc<SshServerConfig>,
) -> (u16, tokio::sync::oneshot::Sender<()>) {
    let connector = Arc::new(ssh::connector::AgentlessDial::new(Duration::from_secs(
        config.inner.connect_timeout_secs,
    )));
    let deps =
        support::outer_leg_deps_with(cp, config.clone(), connector, RecorderChoice::Real).await;
    let server = ssh::bind(config, deps).await.unwrap();
    let port = server.local_addr().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));
    (port, tx)
}

/// A Gateway config whose recorder is DELIBERATELY non-strict, to prove break-glass
/// forces strict on top of it. `require_https=false` for the plain-http MinIO E2E.
fn gw_config(recorder: RecorderConfig) -> SshServerConfig {
    let recorder = RecorderConfig {
        require_https: false,
        ..recorder
    };
    SshServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        login_grace_secs: 60,
        device_flow: DeviceFlowConfig {
            heartbeat_interval_secs: 1,
            poll_timeout_secs: 20,
        },
        inner: InnerLegServerConfig {
            connect_timeout_secs: 4,
            handshake_timeout_secs: 8,
            max_session_idle_secs: 120,
            ..Default::default()
        },
        recorder,
        break_glass: BreakGlassConfig {
            enabled: true,
            // Immediate teardown at grant expiry keeps the mid-session test fast; the
            // Lock override (immediate teardown) is exercised separately.
            mid_session_expiry: MidSessionExpiryMode::HardKill,
        },
        ..Default::default()
    }
}

/// A client container with an askpass helper that echoes `$SL_CODE` (used to answer
/// the keyboard-interactive break-glass offline-code prompt non-interactively).
async fn client_container() -> ContainerAsync<GenericImage> {
    GenericImage::new(CLIENT_IMAGE, CLIENT_TAG)
        .with_network("host")
        .with_startup_timeout(Duration::from_secs(60))
        .with_copy_to(
            CopyTargetOptions::new("/askpass.sh").with_mode(0o755),
            b"#!/bin/sh\necho \"$SL_CODE\"\n".to_vec(),
        )
        .start()
        .await
        .expect("start ssh-client container")
}

/// A client container carrying a private key file for a publickey/pin login (F2).
async fn client_container_with_pin(pin: &KeyMat) -> ContainerAsync<GenericImage> {
    GenericImage::new(CLIENT_IMAGE, CLIENT_TAG)
        .with_network("host")
        .with_startup_timeout(Duration::from_secs(60))
        .with_copy_to(
            CopyTargetOptions::new("/root/pin_key").with_mode(0o600),
            pin.private_openssh.clone().into_bytes(),
        )
        .start()
        .await
        .expect("start ssh-client container")
}

/// publickey/pin ssh args (BatchMode; a single pinned key).
fn pin_ssh(port: u16, target: &str, command: &str) -> Vec<String> {
    let mut a = vec![
        "ssh".into(),
        "-p".into(),
        port.to_string(),
        "-i".into(),
        "/root/pin_key".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        "PreferredAuthentications=publickey".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "ConnectTimeout=30".into(),
        format!("{target}@127.0.0.1"),
    ];
    if !command.is_empty() {
        a.push(command.into());
    }
    a
}

async fn ssh_exec(
    container: &ContainerAsync<GenericImage>,
    args: Vec<String>,
    env: Vec<(String, String)>,
) -> (Option<i64>, String, String) {
    let mut cmd = ExecCommand::new(args);
    if !env.is_empty() {
        cmd = cmd.with_env_vars(env);
    }
    let mut res = container.exec(cmd).await.expect("exec");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

/// Keyboard-interactive ssh args (no publickey, no BatchMode) for the offline-code
/// break-glass path; the code is answered via the askpass helper (see `code_env`).
fn ki_ssh(port: u16, target: &str, command: &str) -> Vec<String> {
    let mut a = vec![
        "ssh".into(),
        "-p".into(),
        port.to_string(),
        "-o".into(),
        "PreferredAuthentications=keyboard-interactive".into(),
        "-o".into(),
        "NumberOfPasswordPrompts=1".into(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "ConnectTimeout=30".into(),
        format!("{target}@127.0.0.1"),
    ];
    if !command.is_empty() {
        a.push(command.into());
    }
    a
}

fn code_env(code: &str) -> Vec<(String, String)> {
    vec![
        ("SSH_ASKPASS".into(), "/askpass.sh".into()),
        ("SSH_ASKPASS_REQUIRE".into(), "force".into()),
        ("SL_CODE".into(), code.into()),
    ]
}

/// Wire the pinned host-CA node connection for `node_port` (as S8/S9).
fn wire_node(cp: &MockCp, host_key: &KeyMat, node_port: u16) {
    let (_l, cert_wire) = cp.sign_host_cert(&host_key.public_wire, &[NODE_ID], 3600);
    let trust = cp.host_ca_verification(cert_wire, &[NODE_ID]);
    cp.set_node_connection(NODE_ID, &format!("127.0.0.1:{node_port}"), trust);
}

async fn await_finalized(cp: &MockCp) -> gateway_core::pb::FinalizeRecordingRequest {
    for _ in 0..80 {
        if let Some(f) = cp.finalized_recordings().into_iter().next() {
            return f;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("the recording was never finalized");
}

// ── E2E 0: the REAL FIDO2 sk-ecdsa break-glass login (software SK provider) ───
//
// The client image bakes OpenSSH's `sk-dummy.so` — a virtual FIDO2 authenticator
// — so a genuine `ecdsa-sk` key is enrolled and the stock `ssh` client produces a
// REAL FIDO possession signature. russh verifies that signature server-side before
// `auth_publickey`, which then resolves the key as a break-glass credential. This
// is the primary break-glass auth path (Design §7, FR-ACC-6) end-to-end.

/// The software SK provider (virtual FIDO2 authenticator) baked into the client image.
const SK_PROVIDER: &str = "/usr/local/lib/sk-dummy.so";

#[tokio::test]
async fn sk_ecdsa_fido2_break_glass_session_e2e() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let (minio, s3) = start_minio().await?;
    cp.set_s3_target(s3);
    cp.set_customer_key(
        "ck",
        customer_keypair(),
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
    );
    // NO standing dp_rule grant: break-glass is the always-available override path.
    cp.register_node(NODE_ID);

    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    // recorder.strict = FALSE; break-glass must force strict on top of it.
    let recorder = RecorderConfig {
        strict: false,
        ..RecorderConfig::default()
    };
    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(recorder))).await;
    let client = client_container().await;

    // Enroll a REAL FIDO2 ecdsa-sk key with the virtual authenticator. It is
    // TOUCH-REQUIRED (no `-O no-touch-required`) — the correct break-glass deployment
    // (BG-1: UP is authenticator-enforced, so prod keys must require touch). sk-dummy
    // auto-asserts user-presence, so the touch key still drives non-interactively.
    let (code, _out, stderr) = ssh_exec(
        &client,
        vec![
            "ssh-keygen".into(),
            "-t".into(),
            "ecdsa-sk".into(),
            "-w".into(),
            SK_PROVIDER.into(),
            "-N".into(),
            String::new(),
            "-f".into(),
            "/root/sk_key".into(),
        ],
        vec![],
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "the software SK provider must enroll a touch-required ecdsa-sk key; stderr={stderr}"
    );

    // Register the enrolled PUBLIC key as the break-glass credential at the CP.
    let (code, pub_line, _e) = ssh_exec(
        &client,
        vec!["cat".into(), "/root/sk_key.pub".into()],
        vec![],
    )
    .await;
    assert_eq!(code, Some(0), "read the enrolled sk public key");
    let sk_pub = ssh_key::PublicKey::from_openssh(pub_line.trim())?;
    assert_eq!(
        sk_pub.algorithm(),
        Algorithm::SkEcdsaSha2NistP256,
        "a genuine sk-ecdsa-sha2-nistp256@openssh.com key"
    );
    cp.register_break_glass_key(sk_pub.to_bytes()?, "breakglass-admin", &["deploy"]);

    // F1 NEGATIVE: the registered break-glass PUBLIC key is listable, so possession
    // of the FIDO private key must be REQUIRED. Offer the same key but with a BROKEN
    // provider so the client cannot produce a FIDO assertion → russh never receives a
    // valid signature → auth fails → NO break-glass session, NO activation. (Possession
    // is enforced by russh before auth_publickey; see the handler comment.)
    let (neg_code, neg_out, _neg_err) = ssh_exec(
        &client,
        vec![
            "ssh".into(),
            "-p".into(),
            gw_port.to_string(),
            "-i".into(),
            "/root/sk_key".into(),
            "-o".into(),
            "SecurityKeyProvider=/nonexistent/no-provider.so".into(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            "PreferredAuthentications=publickey".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=no".into(),
            "-o".into(),
            "UserKnownHostsFile=/dev/null".into(),
            "-o".into(),
            "ConnectTimeout=30".into(),
            "deploy%node-bg@127.0.0.1".into(),
            "echo SHOULD_NOT_RUN".into(),
        ],
        vec![],
    )
    .await;
    assert_ne!(
        neg_code,
        Some(0),
        "a break-glass sk key with no valid FIDO assertion must be rejected"
    );
    assert!(
        !neg_out.contains("SHOULD_NOT_RUN"),
        "no session without possession"
    );
    assert_eq!(
        cp.breakglass_activation_count(),
        0,
        "no FIDO assertion → russh rejects → no Authorize → no activation"
    );

    // Log in with the FIDO2 key: the client signs via the authenticator, russh
    // verifies the FIDO signature, and the Gateway resolves it as break-glass.
    let (code, stdout, stderr) = ssh_exec(
        &client,
        vec![
            "ssh".into(),
            "-p".into(),
            gw_port.to_string(),
            "-i".into(),
            "/root/sk_key".into(),
            "-o".into(),
            format!("SecurityKeyProvider={SK_PROVIDER}"),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            "PreferredAuthentications=publickey".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=no".into(),
            "-o".into(),
            "UserKnownHostsFile=/dev/null".into(),
            "-o".into(),
            "ConnectTimeout=30".into(),
            "deploy%node-bg@127.0.0.1".into(),
            "echo FIDO2_BREAK_GLASS_OK".into(),
        ],
        vec![],
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "the FIDO2 sk-ecdsa break-glass session must run; stderr={stderr}"
    );
    assert!(
        stdout.contains("FIDO2_BREAK_GLASS_OK"),
        "the break-glass session runs on the node; stdout={stdout}"
    );

    // The activation + high-priority alert fired ON USE at Authorize.
    assert_eq!(
        cp.breakglass_activations(),
        vec![("breakglass-admin".to_string(), NODE_ID.to_string())],
        "the FIDO2 break-glass use is recorded as an activation"
    );
    // Break-glass FORCED strict recording despite config strict=false.
    let fin = await_finalized(&cp).await;
    assert_eq!(
        fin.status,
        RecordingStatus::Finalized as i32,
        "break-glass forces strict → the FIDO2 session is recorded"
    );
    assert!(fin.byte_len > 0);

    drop(client);
    drop(node);
    drop(minio);
    Ok(())
}

// ── E2E 1: offline-code break-glass runs, forces strict, is single-use, and
//    works with the primary IdP down ──────────────────────────────────────────

#[tokio::test]
async fn offline_code_break_glass_runs_forces_strict_single_use_idp_down() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let (minio, s3) = start_minio().await?;
    cp.set_s3_target(s3);
    cp.set_customer_key(
        "ck",
        customer_keypair(),
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
    );

    // Primary IdP is DOWN: the device flow is configured to DENY (as if the IdP
    // rejected). Break-glass must remain available regardless (IdP-independent).
    cp.set_device_flow_denied("BG-DOWN", "https://idp.invalid/device");
    // A break-glass offline code; NO standing dp_rule grant (break-glass bypasses it).
    cp.register_offline_code("break-glass-code-XYZ", "breakglass-admin", &["deploy"]);
    cp.register_node(NODE_ID);

    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    // recorder.strict = FALSE in config; break-glass must force strict on top.
    let recorder = RecorderConfig {
        strict: false,
        ..RecorderConfig::default()
    };
    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(recorder))).await;
    let client = client_container().await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        ki_ssh(gw_port, "deploy%node-bg", "echo BREAK_GLASS_OK"),
        code_env("break-glass-code-XYZ"),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "break-glass session must run; stderr={stderr}"
    );
    assert!(
        stdout.contains("BREAK_GLASS_OK"),
        "the break-glass session runs on the node; stdout={stdout}"
    );
    // The activation + high-priority alert fired ON USE at Authorize.
    assert_eq!(
        cp.breakglass_activation_count(),
        1,
        "exactly one break-glass activation was recorded"
    );
    assert_eq!(
        cp.breakglass_activations(),
        vec![("breakglass-admin".to_string(), NODE_ID.to_string())]
    );

    // Break-glass FORCED strict recording even though config strict=false: the
    // session was recorded + finalized in WORM.
    let fin = await_finalized(&cp).await;
    assert_eq!(
        fin.status,
        RecordingStatus::Finalized as i32,
        "break-glass forces strict → the session is recorded"
    );
    assert!(fin.byte_len > 0);

    // Single-use: a REPLAY of the same code is rejected (generic auth failure).
    let (code2, stdout2, _stderr2) = ssh_exec(
        &client,
        ki_ssh(gw_port, "deploy%node-bg", "echo SHOULD_NOT_RUN"),
        code_env("break-glass-code-XYZ"),
    )
    .await;
    assert_ne!(code2, Some(0), "a replayed offline code must be rejected");
    assert!(!stdout2.contains("SHOULD_NOT_RUN"));
    // No SECOND activation: the replayed code never resolved, so no token, no use.
    assert_eq!(
        cp.breakglass_activation_count(),
        1,
        "a replayed code mints no token and drives no activation"
    );

    drop(client);
    drop(node);
    drop(minio);
    Ok(())
}

// ── E2E 1b: a break-glass session serves new channels without re-authorizing
//    (decision_ttl=0, healthy feed) — no single-use-token replay-DENY ───────────

#[tokio::test]
async fn break_glass_serves_channels_when_decision_ttl_zero() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let (minio, s3) = start_minio().await?;
    cp.set_s3_target(s3);
    cp.set_customer_key(
        "ck",
        customer_keypair(),
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
    );
    // Force per-channel re-validate. A break-glass session is authorized once by its
    // single-use token and must NOT re-authorize on the healthy feed: without that
    // posture the FIRST channel would re-authorize (elapsed >= 0), replay the consumed
    // token, and be refused. With it, the healthy LockFeed serves the channel from the
    // cached context (grant_expiry + pushed lock-set still enforced).
    cp.set_decision_ttl(0);
    cp.register_offline_code("bg-ttl0", "breakglass-admin", &["deploy"]);
    cp.register_node(NODE_ID);

    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(RecorderConfig::default()))).await;
    let client = client_container().await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        ki_ssh(gw_port, "deploy%node-bg", "echo BG_TTL0_OK"),
        code_env("bg-ttl0"),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "break-glass with decision_ttl=0 must serve the channel (no token replay); stderr={stderr}"
    );
    assert!(stdout.contains("BG_TTL0_OK"));
    // Exactly one activation: the channel was served from the cached context, NOT
    // re-authorized (a re-auth would have replayed the token).
    assert_eq!(
        cp.breakglass_activation_count(),
        1,
        "the break-glass session did not re-authorize → one activation"
    );

    drop(client);
    drop(node);
    drop(minio);
    Ok(())
}

// ── E2E 2: break-glass forces strict — recording unavailable ⇒ session refused ─

#[tokio::test]
async fn break_glass_forces_strict_refused_when_recording_unavailable() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    // Deliberately NO customer key ⇒ recording setup fails. With config strict=false
    // a STANDING session would run unrecorded; a break-glass session must be REFUSED.
    cp.register_offline_code("bg-nokey", "breakglass-admin", &["deploy"]);
    cp.register_node(NODE_ID);

    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    let recorder = RecorderConfig {
        strict: false, // NON-strict config; break-glass must force strict anyway.
        ..RecorderConfig::default()
    };
    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(recorder))).await;
    let client = client_container().await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        ki_ssh(gw_port, "deploy%node-bg", "echo SHOULD_NOT_RUN"),
        code_env("bg-nokey"),
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "break-glass with unrecordable session must be torn down"
    );
    assert!(
        !stdout.contains("SHOULD_NOT_RUN"),
        "the command must not run"
    );
    assert!(
        stderr.contains(RECORDING_UNAVAILABLE),
        "the user sees the strict recording-unavailable outcome; stderr={stderr}"
    );

    drop(client);
    drop(node);
    Ok(())
}

// ── F2: the GW enforces the SIGNED access_model, never the unsigned `context` ──

#[tokio::test]
async fn gw_enforces_signed_access_model_not_unsigned_context() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    // A STANDING pin auth (the LOCAL break-glass flag is FALSE, isolating the signed-
    // context path), but the CP SIGNS access_model=BREAKGLASS while shipping a
    // DOWNGRADED unsigned context (STANDING). NO customer key + recorder strict=false:
    // reading the SIGNED access_model forces strict → the session is REFUSED; reading
    // the unsigned copy (STANDING) would run it unrecorded. It MUST be refused.
    cp.set_force_signed_breakglass(true);
    let pin = gen_key(Algorithm::Ed25519);
    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", NODE_ID, "deploy");

    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    let recorder = RecorderConfig {
        strict: false,
        ..RecorderConfig::default()
    };
    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(recorder))).await;
    let client = client_container_with_pin(&pin).await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        pin_ssh(gw_port, "deploy%node-bg", "echo SHOULD_NOT_RUN"),
        vec![],
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "the GW must enforce the SIGNED access_model=BREAKGLASS (forced strict → refused)"
    );
    assert!(!stdout.contains("SHOULD_NOT_RUN"));
    assert!(
        stderr.contains(RECORDING_UNAVAILABLE),
        "break-glass from the SIGNED context forces strict; a stripped unsigned context cannot downgrade it; stderr={stderr}"
    );

    drop(client);
    drop(node);
    Ok(())
}

// ── G1: a break-glass ALLOW with grant_expiry==0 is refused (must be time-boxed) ─

#[tokio::test]
async fn break_glass_without_grant_expiry_is_refused() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    cp.set_customer_key(
        "ck",
        customer_keypair(),
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
    );
    // The CP signs a break-glass ALLOW with grant_expiry==0 (a contract violation).
    // The GW must fail closed — an always-available override MUST be time-boxed. A REAL
    // node is wired so that WITHOUT the fix the session would run (echo SHOULD_NOT_RUN).
    cp.set_grant_expiry(0);
    cp.register_offline_code("bg-noexp", "breakglass-admin", &["deploy"]);

    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(RecorderConfig::default()))).await;
    let client = client_container().await;

    let (code, stdout, _stderr) = ssh_exec(
        &client,
        ki_ssh(gw_port, "deploy%node-bg", "echo SHOULD_NOT_RUN"),
        code_env("bg-noexp"),
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "a break-glass ALLOW without a grant_expiry must be refused (time-boxed)"
    );
    assert!(
        !stdout.contains("SHOULD_NOT_RUN"),
        "the un-time-boxed break-glass session must not run"
    );
    // The CP consumed the token + recorded the activation at Authorize; the GW then
    // refused locally on the missing grant_expiry.
    assert_eq!(cp.breakglass_activation_count(), 1);

    drop(client);
    drop(node);
    Ok(())
}

// ── G6: a break-glass session is refused when the lock feed is unhealthy ──────

#[tokio::test]
async fn break_glass_refused_when_lock_feed_unhealthy() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    cp.set_customer_key(
        "ck",
        customer_keypair(),
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
    );
    // The lock feed is DOWN so the Gateway's deny-set is never healthy: a break-glass
    // session cannot confirm the absence of a Lock, so it must refuse NEW privileged
    // channels (fail closed, §8.4). A REAL node → without the fix the session would run.
    cp.set_lock_feed_down(true);
    cp.register_offline_code("bg-feeddown", "breakglass-admin", &["deploy"]);

    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(RecorderConfig::default()))).await;
    let client = client_container().await;

    let (code, stdout, _stderr) = ssh_exec(
        &client,
        ki_ssh(gw_port, "deploy%node-bg", "echo SHOULD_NOT_RUN"),
        code_env("bg-feeddown"),
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "a break-glass session must be refused under an unhealthy lock feed (fail closed)"
    );
    assert!(
        !stdout.contains("SHOULD_NOT_RUN"),
        "no break-glass channel while the deny-feed is unhealthy"
    );

    drop(client);
    drop(node);
    Ok(())
}

// ── E2E 3: a locked target refuses break-glass (deny wins) ───────────────────

#[tokio::test]
async fn locked_target_refuses_break_glass() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    cp.set_customer_key(
        "ck",
        customer_keypair(),
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
    );
    cp.register_offline_code("bg-locked", "breakglass-admin", &["deploy"]);
    cp.register_node(NODE_ID);

    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    // A lock on the node is in effect BEFORE the connection: a matching Lock refuses
    // break-glass (deny wins), even though break-glass bypasses the standing deny.
    cp.add_lock(gateway_core::pb::Lock {
        lock_id: "bg-quarantine".into(),
        target: Some(gateway_core::pb::LockTarget {
            node_ids: vec![NODE_ID.to_string()],
            ..Default::default()
        }),
        expires_at_epoch_seconds: 0,
        created_at_epoch_seconds: 0,
        reason: "incident".into(),
        ..Default::default()
    });

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(RecorderConfig::default()))).await;
    let client = client_container().await;

    let (code, stdout, _stderr) = ssh_exec(
        &client,
        ki_ssh(gw_port, "deploy%node-bg", "echo SHOULD_NOT_RUN"),
        code_env("bg-locked"),
    )
    .await;
    assert_ne!(code, Some(0), "a locked target must refuse break-glass");
    assert!(
        !stdout.contains("SHOULD_NOT_RUN"),
        "the command must never run on a locked target"
    );
    // Deny-wins-after-activation: the CP consumed the token + recorded the activation
    // (fires the alert ON USE), THEN the top-tier Lock denied.
    assert_eq!(
        cp.breakglass_activation_count(),
        1,
        "break-glass use is recorded even when a Lock then denies (deny wins)"
    );

    drop(client);
    drop(node);
    Ok(())
}

// ── E2E 4: a revoke-as-lock tears down a LIVE break-glass session ────────────

#[tokio::test]
async fn revoke_tears_down_a_live_break_glass_session() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let (minio, s3) = start_minio().await?;
    cp.set_s3_target(s3);
    cp.set_customer_key(
        "ck",
        customer_keypair(),
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
    );
    cp.register_offline_code("bg-live", "breakglass-admin", &["deploy"]);
    cp.register_node(NODE_ID);

    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(RecorderConfig::default()))).await;
    let client = client_container().await;

    // Once the break-glass session is live (recording begun), push a lock (the CP's
    // revoke-as-lock) matching the node → the live session is torn down (S10 path).
    cp.push_lock_after_recording_begins(gateway_core::pb::Lock {
        lock_id: "bg-revoke".into(),
        target: Some(gateway_core::pb::LockTarget {
            node_ids: vec![NODE_ID.to_string()],
            ..Default::default()
        }),
        expires_at_epoch_seconds: 0,
        created_at_epoch_seconds: 0,
        reason: "revoked".into(),
        ..Default::default()
    });

    let (code, _stdout, _stderr) = ssh_exec(
        &client,
        ki_ssh(gw_port, "deploy%node-bg", "sh -c 'echo BG_LIVE; sleep 60'"),
        code_env("bg-live"),
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "a revoked (locked) live break-glass session must be torn down"
    );

    // The torn-down break-glass session's recording is still finalized (the S9 path).
    let fin = await_finalized(&cp).await;
    assert_eq!(
        fin.status,
        RecordingStatus::Finalized as i32,
        "the recording is finalized despite the revoke teardown"
    );
    assert!(fin.byte_len > 0);

    drop(client);
    drop(node);
    drop(minio);
    Ok(())
}
