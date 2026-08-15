use std::sync::Arc;
use std::time::Duration;

use crate::support::MockCp;
use gateway_core::config::{DeviceFlowConfig, SshServerConfig};
use gateway_core::ssh;
use gateway_core::ssh::target::{Target, TargetResolver};
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use testcontainers::core::ExecCommand;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient";
const CLIENT_TAG: &str = "test";

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

async fn build_client_image() -> anyhow::Result<()> {
    ensure_docker_host();
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures/ssh-client");
    anyhow::ensure!(dir.is_dir(), "client fixture missing: {}", dir.display());
    let tag = format!("{CLIENT_IMAGE}:{CLIENT_TAG}");
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

struct KeyMaterial {
    private_openssh: String,
    public_line: String,
    fingerprint: String,
}

fn generate_key() -> KeyMaterial {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    KeyMaterial {
        private_openssh: key.to_openssh(LineEnding::LF).unwrap().to_string(),
        public_line: key.public_key().to_openssh().unwrap(),
        fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
    }
}

async fn start_server(
    cp: &MockCp,
    config: Arc<SshServerConfig>,
) -> (u16, tokio::sync::oneshot::Sender<()>) {
    let deps = crate::support::outer_leg_deps(cp, config.clone()).await;
    let server = ssh::bind(config, deps).await.unwrap();
    let port = server.local_addr().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));
    (port, tx)
}

/// Like [`start_server`] but with an explicit target resolver.
async fn start_server_with_resolver(
    cp: &MockCp,
    config: Arc<SshServerConfig>,
    resolver: Arc<dyn TargetResolver>,
) -> (u16, tokio::sync::oneshot::Sender<()>) {
    let mut deps = crate::support::outer_leg_deps(cp, config.clone()).await;
    deps.resolver = resolver;
    let server = ssh::bind(config, deps).await.unwrap();
    let port = server.local_addr().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));
    (port, tx)
}

/// A resolver that knows a fixed inventory and returns `None` for everything else —
/// the shape the shipped `IdentityResolver` (which echoes any non-empty name back)
/// cannot produce.
struct KnownNodesOnly(&'static [&'static str]);

impl TargetResolver for KnownNodesOnly {
    fn resolve_node_id(&self, target: &Target) -> Option<String> {
        self.0
            .contains(&target.node.as_str())
            .then(|| target.node.clone())
    }
}

fn base_config() -> SshServerConfig {
    SshServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        device_flow: DeviceFlowConfig {
            heartbeat_interval_secs: 1,
            poll_timeout_secs: 20,
        },
        login_grace_secs: 60,
        ..Default::default()
    }
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
    let mut res = container.exec(cmd).await.expect("exec ssh");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

/// `ssh -i <key> <target> true`, publickey-only and non-interactive.
fn pubkey_args(port: u16, key_path: &str, target: &str) -> Vec<String> {
    ssh_args(
        port,
        &[
            "-i",
            key_path,
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "BatchMode=yes",
        ],
        target,
        "true",
    )
}

fn ssh_args(port: u16, extra: &[&str], target: &str, command: &str) -> Vec<String> {
    let mut a = vec![
        "ssh".to_string(),
        "-p".to_string(),
        port.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-o".to_string(),
        "ConnectTimeout=30".to_string(),
    ];
    a.extend(extra.iter().map(|s| s.to_string()));
    a.push(format!("{target}@127.0.0.1"));
    a.push(command.to_string());
    a
}

async fn client_container(
    pin_key: &KeyMaterial,
    cert_key: &KeyMaterial,
    cert_line: &str,
) -> ContainerAsync<GenericImage> {
    GenericImage::new(CLIENT_IMAGE, CLIENT_TAG)
        .with_network("host")
        .with_startup_timeout(Duration::from_secs(60))
        .with_copy_to(
            CopyTargetOptions::new("/root/pin_key").with_mode(0o600),
            pin_key.private_openssh.clone().into_bytes(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/root/cert_key").with_mode(0o600),
            cert_key.private_openssh.clone().into_bytes(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/root/cert_key-cert.pub").with_mode(0o644),
            cert_line.as_bytes().to_vec(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/askpass.sh").with_mode(0o755),
            b"#!/bin/sh\necho \"$SL_OTP\"\n".to_vec(),
        )
        .start()
        .await
        .expect("start ssh-client container")
}

const NODE_OFFLINE: &str = "offline or unavailable";
const ACCESS_DENIED: &str = "access denied by policy";
const SERVICE_UNAVAILABLE: &str = "service temporarily unavailable";

#[tokio::test]
async fn publickey_paths_and_error_taxonomy_e2e() -> anyhow::Result<()> {
    build_client_image().await?;

    let cp = MockCp::start().await;
    let pin_key = generate_key();
    let cert_key = generate_key();

    cp.register_pin(&pin_key.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", "web-01", "deploy");
    cp.register_node("web-02");
    let cert_line = cp.sign_user_cert(&cert_key.public_line, "bob", &["dba"], 300);
    cp.allow("bob", "db-1", "dba");

    let (port, _shutdown) = start_server(&cp, Arc::new(base_config())).await;
    let container = client_container(&pin_key, &cert_key, &cert_line).await;

    let (code, stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-i",
                "/root/pin_key",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ],
            "deploy%web-01",
            "true",
        ),
        vec![],
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "pin happy-path: authz ok, node offline\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stderr.contains(NODE_OFFLINE),
        "pin: auth+authz succeeded, inner leg reached; stdout={stdout:?} stderr={stderr:?}"
    );

    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-i",
                "/root/cert_key",
                "-o",
                "CertificateFile=/root/cert_key-cert.pub",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ],
            "dba%db-1",
            "true",
        ),
        vec![],
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "user-cert happy-path: authz ok, node offline\nstderr={stderr}"
    );
    assert!(
        stderr.contains(NODE_OFFLINE),
        "user-cert: auth+authz succeeded, inner leg reached; stderr={stderr:?}"
    );

    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-i",
                "/root/pin_key",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ],
            "deploy%web-02",
            "true",
        ),
        vec![],
    )
    .await;
    assert_ne!(code, Some(0), "denied session must not exit clean");
    assert!(
        stderr.contains(ACCESS_DENIED),
        "denied → generic policy message; stderr={stderr:?}"
    );

    // Unknown node → the SAME generic denial (no existence disclosure).
    let (_code, _stdout, stderr_unknown) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-i",
                "/root/pin_key",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ],
            "deploy%ghost-node",
            "true",
        ),
        vec![],
    )
    .await;
    assert!(
        stderr_unknown.contains(ACCESS_DENIED) && !stderr_unknown.contains("ghost-node"),
        "unknown node must yield the generic denial with no existence disclosure; stderr={stderr_unknown:?}"
    );

    let unknown = generate_key();
    let cont2 = GenericImage::new(CLIENT_IMAGE, CLIENT_TAG)
        .with_network("host")
        .with_copy_to(
            CopyTargetOptions::new("/root/nope").with_mode(0o600),
            unknown.private_openssh.clone().into_bytes(),
        )
        .start()
        .await?;
    let (code, _stdout, stderr) = ssh_exec(
        &cont2,
        ssh_args(
            port,
            &[
                "-i",
                "/root/nope",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ],
            "deploy%web-01",
            "true",
        ),
        vec![],
    )
    .await;
    assert_ne!(code, Some(0), "unpinned key must fail auth");
    assert!(
        stderr.to_lowercase().contains("permission denied"),
        "auth failure must be a standard SSH failure; stderr={stderr:?}"
    );

    // CP unreachable during the connect-time decision → fail closed.
    cp.set_authorize_unavailable(true);
    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-i",
                "/root/pin_key",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ],
            "deploy%web-01",
            "true",
        ),
        vec![],
    )
    .await;
    cp.set_authorize_unavailable(false);
    assert_ne!(code, Some(0));
    assert!(
        stderr.contains(SERVICE_UNAVAILABLE),
        "CP-down must surface the fail-closed service-unavailable message; stderr={stderr:?}"
    );

    Ok(())
}

#[tokio::test]
async fn keyboard_interactive_otp_device_flow_and_degradation_e2e() -> anyhow::Result<()> {
    build_client_image().await?;

    let cp = MockCp::start().await;
    let pin_key = generate_key();
    let cert_key = generate_key();
    let cert_line = cp.sign_user_cert(&cert_key.public_line, "unused", &["x"], 300);

    cp.register_otp("otp-secret-123", "carol", &["ops"]);
    cp.set_device_flow("WDJB-MJHT", "https://cp.example/verify", "dave", 1);
    cp.allow("carol", "app-1", "ops");
    cp.allow("dave", "app-1", "ops");

    let (port, _shutdown) = start_server(&cp, Arc::new(base_config())).await;
    let container = client_container(&pin_key, &cert_key, &cert_line).await;

    let askpass = |otp: &str| -> Vec<(String, String)> {
        vec![
            ("SSH_ASKPASS".to_string(), "/askpass.sh".to_string()),
            ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
            ("SL_OTP".to_string(), otp.to_string()),
        ]
    };

    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "PreferredAuthentications=keyboard-interactive",
            ],
            "ops%app-1",
            "true",
        ),
        askpass("otp-secret-123"),
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "OTP happy-path: authz ok, node offline\nstderr={stderr}"
    );
    assert!(
        stderr.contains(NODE_OFFLINE),
        "OTP: auth+authz succeeded, inner leg reached; stderr={stderr:?}"
    );

    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "PreferredAuthentications=keyboard-interactive",
            ],
            "ops%app-1",
            "true",
        ),
        askpass(""),
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "device-flow login: authz ok, node offline\nstderr={stderr}"
    );
    assert!(
        stderr.contains(NODE_OFFLINE),
        "device flow: auth+authz succeeded, inner leg reached; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("WDJB-MJHT") && stderr.contains("cp.example/verify"),
        "device-flow URL + code must be presented; stderr={stderr:?}"
    );

    cp.register_otp("otp-degrade-9", "carol", &["ops"]);
    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-i",
                "/root/pin_key",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey,keyboard-interactive",
            ],
            "ops%app-1",
            "true",
        ),
        askpass("otp-degrade-9"),
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "degradation publickey→OTP: authz ok, node offline\nstderr={stderr}"
    );
    assert!(
        stderr.contains(NODE_OFFLINE),
        "degradation: auth+authz succeeded, inner leg reached; stderr={stderr:?}"
    );

    Ok(())
}

#[tokio::test]
async fn device_flow_timeout_e2e() -> anyhow::Result<()> {
    build_client_image().await?;

    let cp = MockCp::start().await;
    let pin_key = generate_key();
    let cert_key = generate_key();
    let cert_line = cp.sign_user_cert(&cert_key.public_line, "unused", &["x"], 300);
    cp.set_device_flow("NEVR-APRV", "https://cp.example/verify", "nobody", u32::MAX);

    let config = SshServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        device_flow: DeviceFlowConfig {
            heartbeat_interval_secs: 1,
            poll_timeout_secs: 3,
        },
        login_grace_secs: 60,
        ..Default::default()
    };
    let (port, _shutdown) = start_server(&cp, Arc::new(config)).await;
    let container = client_container(&pin_key, &cert_key, &cert_line).await;

    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "PreferredAuthentications=keyboard-interactive",
            ],
            "ops%app-1",
            "true",
        ),
        vec![
            ("SSH_ASKPASS".to_string(), "/askpass.sh".to_string()),
            ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
            ("SL_OTP".to_string(), String::new()),
        ],
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "a timed-out device flow must not authenticate"
    );
    assert!(
        stderr.contains("authentication timed out"),
        "device-flow timeout must surface the message; stderr={stderr:?}"
    );

    Ok(())
}

#[tokio::test]
async fn cp_down_during_resolution_e2e() -> anyhow::Result<()> {
    build_client_image().await?;

    let cp = MockCp::start().await;
    let pin_key = generate_key();
    let cert_key = generate_key();
    let cert_line = cp.sign_user_cert(&cert_key.public_line, "unused", &["x"], 300);
    cp.register_pin(&pin_key.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", "web-1", "deploy");

    let (port, _shutdown) = start_server(&cp, Arc::new(base_config())).await;
    let container = client_container(&pin_key, &cert_key, &cert_line).await;

    // CP-down during resolution: the pin resolve returns UNAVAILABLE; the
    // publickey attempt degrades to keyboard-interactive, which surfaces the generic
    // "service temporarily unavailable" — NOT a plain auth failure. Fail closed.
    cp.set_resolve_unavailable(true);
    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-i",
                "/root/pin_key",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey,keyboard-interactive",
            ],
            "deploy%web-1",
            "true",
        ),
        vec![
            ("SSH_ASKPASS".to_string(), "/askpass.sh".to_string()),
            ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
            ("SL_OTP".to_string(), String::new()),
        ],
    )
    .await;
    assert_ne!(code, Some(0), "CP-down must not authenticate");
    assert!(
        stderr.contains(SERVICE_UNAVAILABLE),
        "CP-down during resolution must surface service-unavailable, not a plain auth failure; stderr={stderr:?}"
    );

    Ok(())
}

#[tokio::test]
async fn device_flow_instruction_carries_user_code_and_verification_uri() -> anyhow::Result<()> {
    build_client_image().await?;

    let cp = MockCp::start().await;
    let pin_key = generate_key();
    let cert_key = generate_key();
    let cert_line = cp.sign_user_cert(&cert_key.public_line, "unused", &["x"], 300);
    cp.set_device_flow("WDJB-MJHT", "https://cp.example/device/verify", "dave", 1);
    cp.allow("dave", "app-1", "ops");

    let (port, _shutdown) = start_server(&cp, Arc::new(base_config())).await;
    let container = client_container(&pin_key, &cert_key, &cert_line).await;

    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "PreferredAuthentications=keyboard-interactive",
            ],
            "ops%app-1",
            "true",
        ),
        vec![
            ("SSH_ASKPASS".to_string(), "/askpass.sh".to_string()),
            ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
            ("SL_OTP".to_string(), String::new()),
        ],
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "device-flow login: authz ok, node offline; stderr={stderr}"
    );
    assert!(
        stderr.contains("WDJB-MJHT"),
        "the device user-code must be surfaced in the KI instruction field; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("cp.example/device/verify"),
        "the verification URI must be surfaced in the KI instruction field; stderr={stderr:?}"
    );
    assert!(
        stderr.contains(NODE_OFFLINE),
        "device-flow auth+authz succeeded and reached the inner leg; stderr={stderr:?}"
    );
    Ok(())
}

#[tokio::test]
async fn pin_silently_reconnects_within_ttl_and_falls_back_on_source_change() -> anyhow::Result<()>
{
    build_client_image().await?;

    let cp = MockCp::start().await;
    let pin_key = generate_key();
    let cert_key = generate_key();
    let cert_line = cp.sign_user_cert(&cert_key.public_line, "unused", &["x"], 300);
    cp.register_pin(&pin_key.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", "app-1", "deploy");

    let (port, _shutdown) = start_server(&cp, Arc::new(base_config())).await;
    let container = client_container(&pin_key, &cert_key, &cert_line).await;

    for attempt in 0..2 {
        let (code, _stdout, stderr) = ssh_exec(
            &container,
            ssh_args(
                port,
                &[
                    "-i",
                    "/root/pin_key",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "BatchMode=yes",
                ],
                "deploy%app-1",
                "true",
            ),
            vec![],
        )
        .await;
        assert_ne!(code, Some(0), "reconnect {attempt}: authz ok, node offline");
        assert!(
            stderr.contains(NODE_OFFLINE),
            "silent pin reconnect {attempt} must authenticate with no prompt and reach the inner leg; stderr={stderr:?}"
        );
    }

    cp.register_pin_source_bound(&pin_key.fingerprint, "alice", &["deploy"], "10.0.0.1");
    cp.register_otp("otp-fallback-77", "alice", &["deploy"]);
    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-i",
                "/root/pin_key",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey,keyboard-interactive",
            ],
            "deploy%app-1",
            "true",
        ),
        vec![
            ("SSH_ASKPASS".to_string(), "/askpass.sh".to_string()),
            ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
            ("SL_OTP".to_string(), "otp-fallback-77".to_string()),
        ],
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "source-change fallback: authz ok, node offline"
    );
    assert!(
        stderr.contains(NODE_OFFLINE),
        "a source-mismatched pin must fall back to the next method (OTP), not hard-fail; stderr={stderr:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_long_lived_key_offered_as_a_standing_path_is_refused() -> anyhow::Result<()> {
    build_client_image().await?;

    let cp = MockCp::start().await;
    let pin_key = generate_key();
    let cert_key = generate_key();
    let cert_line = cp.sign_user_cert(&cert_key.public_line, "unused", &["x"], 300);
    cp.allow("alice", "app-1", "deploy");

    let (port, _shutdown) = start_server(&cp, Arc::new(base_config())).await;
    let container = client_container(&pin_key, &cert_key, &cert_line).await;

    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-i",
                "/root/pin_key",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ],
            "deploy%app-1",
            "true",
        ),
        vec![],
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "a standing long-lived key must not authenticate"
    );
    assert!(
        stderr.to_lowercase().contains("permission denied"),
        "a long-lived key with no active pin must be refused (no standing key store); stderr={stderr:?}"
    );

    cp.register_pin(&pin_key.fingerprint, "alice", &["deploy"]);
    let (code, _stdout, stderr) = ssh_exec(
        &container,
        ssh_args(
            port,
            &[
                "-i",
                "/root/pin_key",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "BatchMode=yes",
            ],
            "deploy%app-1",
            "true",
        ),
        vec![],
    )
    .await;
    assert_ne!(code, Some(0), "pinned: authz ok, node offline");
    assert!(
        stderr.contains(NODE_OFFLINE),
        "the same key WITH an active pin authenticates (short-TTL, not standing); stderr={stderr:?}"
    );
    Ok(())
}

/// A credential-scope refusal must be a CP DECISION, not a Gateway pre-empt. The client
/// cannot tell the denials apart — that is intended — but the CP is the sole writer of
/// the decision log, so a refusal it never sees is a refusal no auditor can see either.
/// What these assertions pin is that the RPC happened and carried the scope.
#[tokio::test]
async fn a_credential_scope_denial_reaches_the_control_plane() -> anyhow::Result<()> {
    build_client_image().await?;

    let cp = MockCp::start().await;
    let scoped = generate_key();
    let unscoped = generate_key();
    let cert_line = cp.sign_user_cert(&generate_key().public_line, "unused", &["x"], 300);

    cp.register_pin(&scoped.fingerprint, "alice", &["deploy"]);
    cp.register_pin(&unscoped.fingerprint, "bob", &[]);
    // RBAC allows alice BOTH logins, so a `root` denial can only be the credential
    // scope — never the grant evaluation in disguise.
    cp.allow("alice", "web-01", "deploy");
    cp.allow("alice", "web-01", "root");
    cp.allow("bob", "web-01", "root");

    let (port, _shutdown) = start_server(&cp, Arc::new(base_config())).await;
    let container = client_container(&scoped, &unscoped, &cert_line).await;

    // In scope: authorized, and the inner leg then finds no node — NODE_OFFLINE is how
    // this suite spells "authentication and authorization both passed".
    let (_code, _stdout, stderr) = ssh_exec(
        &container,
        pubkey_args(port, "/root/pin_key", "deploy%web-01"),
        vec![],
    )
    .await;
    assert!(
        stderr.contains(NODE_OFFLINE),
        "an in-scope login is unaffected; stderr={stderr:?}"
    );
    let req = cp
        .last_authorize_request()
        .expect("an in-scope connect must call Authorize");
    assert_eq!(
        req.credential_principals,
        vec!["deploy".to_string()],
        "the credential's scope must reach the CP on every call, not only the denials"
    );

    // Out of scope: the same generic denial as before, but now the CP made it.
    let (code, _stdout, stderr) = ssh_exec(
        &container,
        pubkey_args(port, "/root/pin_key", "root%web-01"),
        vec![],
    )
    .await;
    assert_ne!(code, Some(0), "an out-of-scope login must not exit clean");
    assert!(
        stderr.contains(ACCESS_DENIED),
        "the client-facing outcome is unchanged: one generic denial; stderr={stderr:?}"
    );
    let req = cp
        .last_authorize_request()
        .expect("the out-of-scope connect must have called Authorize");
    assert_eq!(req.requested_principal, "root");
    assert_eq!(
        req.credential_principals,
        vec!["deploy".to_string()],
        "the CP cannot write the decision record without the scope that produced it"
    );

    // An unscoped credential is untouched by the reducer.
    let (_code, _stdout, stderr) = ssh_exec(
        &container,
        pubkey_args(port, "/root/cert_key", "root%web-01"),
        vec![],
    )
    .await;
    assert!(
        stderr.contains(NODE_OFFLINE),
        "an unscoped credential authorizes any RBAC-allowed login; stderr={stderr:?}"
    );
    let req = cp.last_authorize_request().expect("Authorize was called");
    assert!(
        req.credential_principals.is_empty(),
        "unscoped must travel as empty, not as a one-element scope; got {:?}",
        req.credential_principals
    );
    Ok(())
}

/// The backstop half. Forwarding the scope is what makes the refusal auditable; keeping
/// the local check is what makes it unforgeable. A CP older than the contract field, or
/// one that ignores it, must still not be able to hand this Gateway an out-of-scope
/// allow.
#[tokio::test]
async fn the_gateway_refuses_an_out_of_scope_login_the_control_plane_allowed() -> anyhow::Result<()>
{
    build_client_image().await?;

    let cp = MockCp::start().await;
    cp.set_ignores_credential_scope();
    let scoped = generate_key();
    let unscoped = generate_key();
    let cert_line = cp.sign_user_cert(&generate_key().public_line, "unused", &["x"], 300);

    cp.register_pin(&scoped.fingerprint, "alice", &["deploy"]);
    cp.register_pin(&unscoped.fingerprint, "bob", &[]);
    cp.allow("alice", "web-01", "root");
    cp.allow("bob", "web-01", "root");

    let (port, _shutdown) = start_server(&cp, Arc::new(base_config())).await;
    let container = client_container(&scoped, &unscoped, &cert_line).await;

    // The control: an unscoped credential on the SAME allow rule reaches the inner leg,
    // so NODE_OFFLINE is what this CP's allow looks like from the client.
    let (_code, _stdout, stderr) = ssh_exec(
        &container,
        pubkey_args(port, "/root/cert_key", "root%web-01"),
        vec![],
    )
    .await;
    assert!(
        stderr.contains(NODE_OFFLINE),
        "the mock must be allowing `root` for the backstop to be under test; stderr={stderr:?}"
    );

    let (code, _stdout, stderr) = ssh_exec(
        &container,
        pubkey_args(port, "/root/pin_key", "root%web-01"),
        vec![],
    )
    .await;
    // Pin what the CP saw before judging the client's outcome: if the scoped credential
    // is not the one that authenticated, the refusal below would prove nothing.
    let req = cp
        .last_authorize_request()
        .expect("the scoped connect must have called Authorize");
    assert_eq!(
        (
            req.identity.as_str(),
            req.requested_principal.as_str(),
            req.credential_principals.clone()
        ),
        ("alice", "root", vec!["deploy".to_string()]),
        "the scoped pin must be the credential under test"
    );
    assert_ne!(code, Some(0), "the backstop must not exit clean");
    assert!(
        stderr.contains(ACCESS_DENIED),
        "a scoped credential must be refused even on an allow; stderr={stderr:?}"
    );

    // The CP really did ALLOW: it took a concurrency lease, which only the ALLOW path
    // mints and which the refused session then released on teardown.
    let session_id = cp
        .last_authorize_request()
        .expect("the refused connect must still have called Authorize")
        .session_id;
    let mut released = false;
    for _ in 0..200 {
        if cp
            .session_end_notifications()
            .iter()
            .any(|n| n.session_id == session_id)
        {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        released,
        "no lease was released for {session_id}, so the CP denied rather than allowed — \
         the refusal under test was the ordinary deny, not the backstop"
    );
    Ok(())
}

/// An unresolvable target is the CP's decision too: it resolves `node_name` server-side
/// and audits its own no-match, so a local pre-empt would leave a user probing for node
/// names with no record anywhere. A MALFORMED username stays local by contrast — it
/// never names a target, so there is no decision to record.
#[tokio::test]
async fn an_unresolvable_target_reaches_the_control_plane() -> anyhow::Result<()> {
    build_client_image().await?;

    let cp = MockCp::start().await;
    let pin_key = generate_key();
    let spare = generate_key();
    let cert_line = cp.sign_user_cert(&generate_key().public_line, "unused", &["x"], 300);

    cp.register_pin(&pin_key.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", "web-01", "deploy");

    let (port, _shutdown) = start_server_with_resolver(
        &cp,
        Arc::new(base_config()),
        Arc::new(KnownNodesOnly(&["web-01"])),
    )
    .await;
    let container = client_container(&pin_key, &spare, &cert_line).await;

    let (code, _stdout, stderr) = ssh_exec(
        &container,
        pubkey_args(port, "/root/pin_key", "deploy%ghost-node"),
        vec![],
    )
    .await;
    assert_ne!(code, Some(0), "an unknown node must not exit clean");
    assert!(
        stderr.contains(ACCESS_DENIED) && !stderr.contains("ghost-node"),
        "the generic denial, with no existence disclosure; stderr={stderr:?}"
    );
    let req = cp
        .last_authorize_request()
        .expect("an unresolvable target must still call Authorize — the CP writes the record");
    assert_eq!(req.node_name, "ghost-node");
    assert!(
        req.node_id.is_empty(),
        "an unresolved id travels empty; node_name is authoritative server-side, got {:?}",
        req.node_id
    );

    // A username with no target in it never reaches the CP: there is nothing to decide.
    let (code, _stdout, stderr) = ssh_exec(
        &container,
        pubkey_args(port, "/root/pin_key", "nodelimiter"),
        vec![],
    )
    .await;
    assert_ne!(code, Some(0), "a malformed username must not exit clean");
    assert!(
        stderr.contains(ACCESS_DENIED),
        "malformed → the same generic denial; stderr={stderr:?}"
    );
    assert_eq!(
        cp.last_authorize_request().map(|r| r.node_name),
        Some("ghost-node".to_string()),
        "a malformed username names no target, so it must NOT produce an Authorize call"
    );
    Ok(())
}
