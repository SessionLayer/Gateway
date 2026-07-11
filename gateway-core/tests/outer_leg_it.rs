//! Outer-leg end-to-end tests driven by a **stock OpenSSH client** in a Debian 13
//! container (never host ssh), against the real russh outer-leg server with an
//! in-process mock CP (real TLS 1.3 + the S4 AuthInterceptor tier). Covers:
//! Part A (transport + reach-auth), Part C/D (pin / user-cert / OTP / device-flow
//! resolution → Authorize), Part E (device-flow heartbeat + approval), Part F
//! (the §7.1 taxonomy rows), and Part G (username-encoding target → Authorize).
//!
//! The client container uses `--network host`, so its `127.0.0.1` is the host
//! loopback where the in-process Gateway binds; the container connects to the
//! Gateway on an ephemeral host port.

mod support;

use std::sync::Arc;
use std::time::Duration;

use gateway_core::config::{DeviceFlowConfig, SshServerConfig};
use gateway_core::ssh;
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use support::MockCp;
use testcontainers::core::ExecCommand;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient";
const CLIENT_TAG: &str = "s7";

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

/// Build the openssh-client image (idempotent; Docker layer-caches).
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

/// A generated OpenSSH keypair (private PEM + public authorized-keys line + the
/// SHA-256 fingerprint the Gateway will compute).
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

/// Bind the outer-leg server on loopback and run it in the background.
async fn start_server(
    cp: &MockCp,
    config: Arc<SshServerConfig>,
) -> (u16, tokio::sync::oneshot::Sender<()>) {
    let deps = support::outer_leg_deps(cp, config.clone()).await;
    let server = ssh::bind(config, deps).await.unwrap();
    let port = server.local_addr().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));
    (port, tx)
}

fn base_config() -> SshServerConfig {
    SshServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        // Short device-flow timing so the heartbeat/approval test is fast.
        device_flow: DeviceFlowConfig {
            heartbeat_interval_secs: 1,
            poll_timeout_secs: 20,
        },
        login_grace_secs: 60,
        ..Default::default()
    }
}

/// Run `ssh` inside the client container and return `(exit_code, stdout, stderr)`.
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

/// A container with the ssh keypair + a cert + an askpass helper copied in.
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
        // askpass echoes $SL_OTP; used for keyboard-interactive (OTP / device flow).
        .with_copy_to(
            CopyTargetOptions::new("/askpass.sh").with_mode(0o755),
            b"#!/bin/sh\necho \"$SL_OTP\"\n".to_vec(),
        )
        .start()
        .await
        .expect("start ssh-client container")
}

const INNER_LEG_PENDING: &str = "inner leg pending";
const ACCESS_DENIED: &str = "access denied by policy";
const SERVICE_UNAVAILABLE: &str = "service temporarily unavailable";

#[tokio::test]
async fn publickey_paths_and_error_taxonomy_e2e() -> anyhow::Result<()> {
    build_client_image().await?;

    let cp = MockCp::start().await;
    let pin_key = generate_key();
    let cert_key = generate_key();

    // Pin resolves alice→[deploy]; alice is granted deploy on web-01.
    cp.register_pin(&pin_key.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", "web-01", "deploy");
    // web-02 exists but alice has no grant there (authorized-but-denied row).
    cp.register_node("web-02");
    // User cert resolves bob→[dba]; bob is granted dba on db-1.
    let cert_line = cp.sign_user_cert(&cert_key.public_line, "bob", &["dba"], 300);
    cp.allow("bob", "db-1", "dba");

    let (port, _shutdown) = start_server(&cp, Arc::new(base_config())).await;
    let container = client_container(&pin_key, &cert_key, &cert_line).await;

    // Part A + C(pin) + D + G: reach auth, resolve the pin, authorize, close at
    // the inner-leg seam ("inner leg pending"), clean exit.
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
    assert_eq!(
        code,
        Some(0),
        "pin happy-path must exit clean\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(INNER_LEG_PENDING),
        "pin happy-path must reach the inner-leg seam; stdout={stdout:?} stderr={stderr:?}"
    );

    // Part C(user cert) + D: resolve a user cert signed by the mock user CA.
    let (code, stdout, stderr) = ssh_exec(
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
    assert_eq!(
        code,
        Some(0),
        "user-cert happy-path must exit clean\nstderr={stderr}"
    );
    assert!(
        stdout.contains(INNER_LEG_PENDING),
        "user-cert happy-path must reach the inner-leg seam; stdout={stdout:?}"
    );

    // Part F: authorized-but-denied (node exists, no grant) → generic denial.
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

    // Part F: unknown node → the SAME generic denial (no existence disclosure).
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

    // Part F: auth failed (unpinned key, publickey only) → standard SSH failure.
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

    // Part F: CP unreachable during the connect-time decision → fail closed.
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
    let pin_key = generate_key(); // an UNPINNED key, to prove degradation
    let cert_key = generate_key();
    let cert_line = cp.sign_user_cert(&cert_key.public_line, "unused", &["x"], 300);

    // OTP resolves carol→[ops]; device flow resolves dave (RBAC decides the login);
    // both are granted ops on app-1.
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

    // Part C(OTP): keyboard-interactive, answer the OTP prompt via askpass.
    let (code, stdout, stderr) = ssh_exec(
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
    assert_eq!(
        code,
        Some(0),
        "OTP happy-path must exit clean\nstderr={stderr}"
    );
    assert!(
        stdout.contains(INNER_LEG_PENDING),
        "OTP → inner-leg seam; stdout={stdout:?}"
    );

    // Part E(device flow): empty OTP falls back to the device flow; the client
    // stays alive across num-prompts=0 heartbeats and completes on APPROVED.
    let (code, stdout, stderr) = ssh_exec(
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
        askpass(""), // empty OTP → device flow
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "device-flow login must complete on approval\nstderr={stderr}"
    );
    assert!(
        stdout.contains(INNER_LEG_PENDING),
        "device flow → inner-leg seam; stdout={stdout:?}"
    );
    // The verification URL + user code were presented in the KI instruction.
    assert!(
        stderr.contains("WDJB-MJHT") && stderr.contains("cp.example/verify"),
        "device-flow URL + code must be presented; stderr={stderr:?}"
    );

    // Part C degradation: an UNPINNED publickey fails, then keyboard-interactive
    // OTP succeeds (the offered method degrades to the next).
    cp.register_otp("otp-degrade-9", "carol", &["ops"]);
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
                "PreferredAuthentications=publickey,keyboard-interactive",
            ],
            "ops%app-1",
            "true",
        ),
        askpass("otp-degrade-9"),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "degradation publickey→OTP must succeed\nstderr={stderr}"
    );
    assert!(
        stdout.contains(INNER_LEG_PENDING),
        "degradation → inner-leg seam; stdout={stdout:?}"
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
    // A device flow that never approves; the short poll deadline fires first.
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

    // Part F: device-flow timeout → the §7.1 "authentication timed out" outcome.
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
        "device-flow timeout must surface the §7.1 message; stderr={stderr:?}"
    );

    Ok(())
}
