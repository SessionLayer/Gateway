//! Session 29 end-to-end: the **port-forwarding + X11 data plane** (FR-SESS-2).
//!
//! A stock OpenSSH client (Debian 13 container, never host ssh) drives real
//! `ssh -L`/`-R`/`-X` through the in-process Gateway against a real Debian sshd
//! node. Each forward is admitted ONLY when the session's (mock-CP-signed) grant
//! carries the matching capability; refused generically otherwise. Proves:
//!
//! - **-L** local forward reaches a target on the NODE's network (the node dials
//!   its own sshd; the client reads the SSH banner back through the tunnel);
//! - **-R** remote forward binds a listener ON THE NODE and relays a connection
//!   back to the client; `ExitOnForwardFailure` makes the ungranted case fail;
//!   `cancel-tcpip-forward` (ssh -O cancel) actually unbinds the node listener;
//! - **-X** X11 request is relayed unchanged to the node (DISPLAY is set on the
//!   node) when granted, refused otherwise;
//! - **agent forwarding is always refused**, even with a maximal grant;
//! - a **nested ProxyJump** direct-tcpip is refused even with a maximal grant
//!   (one MITM hop only — the S16 structural invariant survives S29);
//! - a mid-session **Lock** tears a live forward down like any channel;
//! - the recording posture is **metadata-only** (tunnel open/close markers, no
//!   forwarded byte content in the sealed WORM object).
//!
//! Networking mirrors S8/S9: the client container is `--network host` (its
//! 127.0.0.1 is the host loopback the in-process Gateway + mapped node/MinIO ports
//! live on); the node + MinIO run on the default bridge with mapped ports.

mod support;

use std::sync::Arc;
use std::time::Duration;

use gateway_core::config::{
    DeviceFlowConfig, InnerLegServerConfig, RecorderConfig, SshServerConfig,
};
use gateway_core::pb::{Capability, KeySealAlgorithm, RecordingStatus};
use gateway_core::ssh;
use gateway_core::ssh::recorder::seal;
use p256::pkcs8::EncodePublicKey;
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use support::sigv4::{self, S3Target};
use support::{MockCp, RecorderChoice};
use testcontainers::core::{ExecCommand, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient";
const CLIENT_TAG: &str = "s8";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode";
// Bumped for Session 29 (adds xauth + X11Forwarding to the node fixture).
const NODE_TAG: &str = "s29";
const NODE_ID: &str = "node-e2e";
const MINIO_IMAGE: &str = "minio/minio";
const MINIO_TAG: &str = "RELEASE.2025-04-08T15-41-24Z";
const MINIO_USER: &str = "minioadmin";
const MINIO_PASS: &str = "minioadmin";
const BUCKET: &str = "recordings";

fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("gateway_core=debug")
            .with_test_writer()
            .try_init();
    });
}

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
        fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
    }
}

fn customer_keypair() -> (Vec<u8>, p256::SecretKey) {
    let secret = p256::SecretKey::random(&mut OsRng);
    let der = secret.public_key().to_public_key_der().unwrap();
    (der.as_bytes().to_vec(), secret)
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

async fn start_gateway(
    cp: &MockCp,
    config: Arc<SshServerConfig>,
    recorder: RecorderChoice,
) -> (u16, tokio::sync::oneshot::Sender<()>) {
    let connector = Arc::new(ssh::connector::AgentlessDial::new(Duration::from_secs(
        config.inner.connect_timeout_secs,
    )));
    let deps = support::outer_leg_deps_with(cp, config.clone(), connector, recorder).await;
    let server = ssh::bind(config, deps).await.unwrap();
    let port = server.local_addr().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));
    (port, tx)
}

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
        ..Default::default()
    }
}

async fn client_container(pin_key: &KeyMat) -> ContainerAsync<GenericImage> {
    GenericImage::new(CLIENT_IMAGE, CLIENT_TAG)
        .with_network("host")
        .with_startup_timeout(Duration::from_secs(60))
        .with_copy_to(
            CopyTargetOptions::new("/root/pin_key").with_mode(0o600),
            pin_key.private_openssh.clone().into_bytes(),
        )
        .start()
        .await
        .expect("start ssh-client container")
}

async fn exec(
    container: &ContainerAsync<GenericImage>,
    args: Vec<String>,
) -> (Option<i64>, String, String) {
    let mut res = container.exec(ExecCommand::new(args)).await.expect("exec");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

/// The common ssh options (pin auth, no host-key prompt) plus caller `extra`, then
/// `deploy%node-e2e@127.0.0.1` and an optional command.
fn ssh_cmd(port: u16, extra: &[&str], command: &str) -> Vec<String> {
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
    ];
    a.extend(extra.iter().map(|s| s.to_string()));
    a.push("deploy%node-e2e@127.0.0.1".into());
    if !command.is_empty() {
        a.push(command.into());
    }
    a
}

/// The common ssh option string (pin auth, no host-key prompt) for embedding in a
/// bash script — `deploy%node-e2e@127.0.0.1` is appended by the caller.
fn ssh_opts(port: u16) -> String {
    format!(
        "-p {port} -i /root/pin_key -o IdentitiesOnly=yes \
         -o PreferredAuthentications=publickey -o BatchMode=yes \
         -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30"
    )
}

/// Run `ssh -L` in the background inside ONE shell, wait for it to establish, probe
/// the forwarded local port for the node's SSH banner, then dump the ssh -v log
/// (so a failure is diagnosable). Returns the whole script's stdout.
fn local_forward_script(gw_port: u16, lport: u16, target: &str) -> Vec<String> {
    let opts = ssh_opts(gw_port);
    vec![
        "bash".into(),
        "-c".into(),
        format!(
            "ssh {opts} -v -N -L {lport}:{target} deploy%node-e2e@127.0.0.1 >/tmp/ssh.log 2>&1 & \
             SSHPID=$!; sleep 5; \
             (exec 3<>/dev/tcp/127.0.0.1/{lport}; head -c 15 <&3) 2>/dev/null || true; \
             echo; echo '===SSHLOG==='; tail -20 /tmp/ssh.log; kill $SSHPID 2>/dev/null || true"
        ),
    ]
}

fn grant(cp: &MockCp, pin: &KeyMat) {
    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", NODE_ID, "deploy");
}

fn wire_node(cp: &MockCp, host_key: &KeyMat, node_port: u16) {
    let (_l, cert_wire) = cp.sign_host_cert(&host_key.public_wire, &[NODE_ID], 3600);
    let trust = cp.host_ca_verification(cert_wire, &[NODE_ID]);
    cp.set_node_connection(NODE_ID, &format!("127.0.0.1:{node_port}"), trust);
}

// ── A. Local forward (`ssh -L`) ──────────────────────────────────────────────

#[tokio::test]
async fn local_forward_reaches_node_only_when_granted() -> anyhow::Result<()> {
    init_tracing();
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);
    let (gw_port, _sd) = start_gateway(
        &cp,
        Arc::new(gw_config(RecorderConfig::default())),
        RecorderChoice::Null,
    )
    .await;

    // ── Not granted: shell only → the -L direct-tcpip is refused; the probe reads
    //    nothing back through the closed forward.
    cp.set_capabilities(NODE_ID, &[Capability::Shell]);
    let denied = client_container(&pin).await;
    let (_c, out_denied, _e) = exec(
        &denied,
        local_forward_script(gw_port, 15122, "127.0.0.1:22"),
    )
    .await;
    let banner_denied = out_denied.split("===SSHLOG===").next().unwrap_or("");
    assert!(
        !banner_denied.contains("SSH-2.0"),
        "an ungranted local forward must not reach the node (got {out_denied:?})"
    );

    // ── Granted: the node dials its own sshd; the banner comes back through -L.
    cp.set_capabilities(NODE_ID, &[Capability::Shell, Capability::PortForwardLocal]);
    let ok = client_container(&pin).await;
    let (_c, out_ok, _e) = exec(&ok, local_forward_script(gw_port, 15122, "127.0.0.1:22")).await;
    let banner_ok = out_ok.split("===SSHLOG===").next().unwrap_or("");
    assert!(
        banner_ok.contains("SSH-2.0"),
        "a granted local forward must reach the node's sshd (full output: {out_ok})"
    );

    drop(denied);
    drop(ok);
    drop(node);
    Ok(())
}

// ── B. Remote forward (`ssh -R`) ─────────────────────────────────────────────

#[tokio::test]
async fn remote_forward_binds_on_node_only_when_granted() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);
    let (gw_port, _sd) = start_gateway(
        &cp,
        Arc::new(gw_config(RecorderConfig::default())),
        RecorderChoice::Null,
    )
    .await;

    // ── Not granted: with ExitOnForwardFailure the tcpip_forward refusal makes ssh
    //    exit non-zero (the listener is never bound on the node).
    cp.set_capabilities(NODE_ID, &[Capability::Shell]);
    let denied = client_container(&pin).await;
    let (code_denied, _o, _e) = exec(
        &denied,
        ssh_cmd(
            gw_port,
            &[
                "-o",
                "ExitOnForwardFailure=yes",
                "-f",
                "-N",
                "-R",
                "15222:127.0.0.1:22",
            ],
            "",
        ),
    )
    .await;
    assert_ne!(
        code_denied,
        Some(0),
        "an ungranted remote forward must be refused"
    );

    // ── Granted: the node binds 15222 and forwards a connection back to the client,
    //    which dials the node's own sshd (via host network) — banner returns. A mux
    //    master (-M) keeps a control socket so `-O cancel` can unbind it below.
    cp.set_capabilities(NODE_ID, &[Capability::Shell, Capability::PortForwardRemote]);
    let ok = client_container(&pin).await;
    let fwd = format!("15222:127.0.0.1:{node_port}");
    let (code_ok, _o, _e) = exec(
        &ok,
        ssh_cmd(
            gw_port,
            &[
                "-o",
                "ExitOnForwardFailure=yes",
                "-f",
                "-N",
                "-M",
                "-S",
                "/tmp/cm",
                "-R",
                &fwd,
            ],
            "",
        ),
    )
    .await;
    assert_eq!(
        code_ok,
        Some(0),
        "a granted remote forward must bind on the node"
    );
    // Probe the node-bound listener FROM THE NODE: the connection is relayed back
    // through the Gateway to the client, which dials the node sshd → banner.
    let (_c, out_ok, _e) = exec(
        &node,
        vec![
            "bash".into(),
            "-c".into(),
            "sleep 2; (exec 3<>/dev/tcp/127.0.0.1/15222; head -c 15 <&3) 2>/dev/null || true"
                .into(),
        ],
    )
    .await;
    assert!(
        out_ok.contains("SSH-2.0"),
        "a connection to the node-bound -R listener must relay back to the client (got {out_ok:?})"
    );

    // ── `cancel-tcpip-forward` (RFC 4254 §7.1) actually unbinds the node listener.
    let (code_cancel, _o, cancel_err) = exec(
        &ok,
        ssh_cmd(gw_port, &["-S", "/tmp/cm", "-O", "cancel", "-R", &fwd], ""),
    )
    .await;
    assert_eq!(
        code_cancel,
        Some(0),
        "cancel-tcpip-forward must be honored: {cancel_err}"
    );
    let (_c, out_after, _e) = exec(
        &node,
        vec![
            "bash".into(),
            "-c".into(),
            "sleep 1; (exec 3<>/dev/tcp/127.0.0.1/15222; head -c 15 <&3) 2>/dev/null || true"
                .into(),
        ],
    )
    .await;
    assert!(
        !out_after.contains("SSH-2.0"),
        "a cancelled remote forward must be unbound on the node (got {out_after:?})"
    );

    drop(denied);
    drop(ok);
    drop(node);
    Ok(())
}

// ── C. X11 (`ssh -X`) ────────────────────────────────────────────────────────

#[tokio::test]
async fn x11_request_relayed_to_node_only_when_granted() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);
    let (gw_port, _sd) = start_gateway(
        &cp,
        Arc::new(gw_config(RecorderConfig::default())),
        RecorderChoice::Null,
    )
    .await;
    let _ = node_port;

    // `ssh -Y` (TRUSTED X11) uses the local xauth cookie directly — unlike `-X`
    // (untrusted), which runs `xauth generate` against a live X server (absent
    // here). We set a dummy DISPLAY + cookie so the client actually SENDS the
    // x11-req; the `x11` capability is identical for -X/-Y.
    let x11_script = |gw_port: u16| -> Vec<String> {
        let opts = ssh_opts(gw_port);
        vec![
            "bash".into(),
            "-c".into(),
            format!(
                "export DISPLAY=:99; touch ~/.Xauthority; \
                 xauth add :99 . 0123456789abcdef0123456789abcdef 2>/dev/null; \
                 ssh {opts} -Y deploy%node-e2e@127.0.0.1 'printf DISPLAY=[%s] \"$DISPLAY\"'"
            ),
        ]
    };

    // ── Not granted: the x11-req is refused at the Gateway → DISPLAY stays unset.
    cp.set_capabilities(NODE_ID, &[Capability::Shell, Capability::Exec]);
    let denied = client_container(&pin).await;
    let (_c, out_denied, _e) = exec(&denied, x11_script(gw_port)).await;
    assert!(
        out_denied.contains("DISPLAY=[]"),
        "an ungranted x11 session must not set DISPLAY (got {out_denied:?})"
    );

    // ── Granted: the Gateway relays x11-req unchanged → the node sets DISPLAY.
    cp.set_capabilities(
        NODE_ID,
        &[Capability::Shell, Capability::Exec, Capability::X11],
    );
    let ok = client_container(&pin).await;
    let (_c, out_ok, _e) = exec(&ok, x11_script(gw_port)).await;
    assert!(
        out_ok.contains("DISPLAY=[localhost:") || out_ok.contains("DISPLAY=[:"),
        "a granted x11 session must have DISPLAY set on the node (got {out_ok:?})"
    );

    drop(denied);
    drop(ok);
    drop(node);
    Ok(())
}

// ── D. Regressions ───────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_forwarding_is_always_refused_even_with_full_grant() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);
    let (gw_port, _sd) = start_gateway(
        &cp,
        Arc::new(gw_config(RecorderConfig::default())),
        RecorderChoice::Null,
    )
    .await;

    // A MAXIMAL grant, including every forward capability — agent forwarding must
    // STILL be refused (FR-SESS-2 second clause is a permanent denial).
    cp.set_capabilities(
        NODE_ID,
        &[
            Capability::Shell,
            Capability::Exec,
            Capability::PortForwardLocal,
            Capability::PortForwardRemote,
            Capability::X11,
            Capability::AgentForward,
        ],
    );
    let client = client_container(&pin).await;
    // `-A` requests agent forwarding; the node must NOT get an auth-agent socket.
    let (_c, out, _e) = exec(
        &client,
        ssh_cmd(gw_port, &["-A"], "printf SOCK=[%s] \"$SSH_AUTH_SOCK\""),
    )
    .await;
    assert!(
        out.contains("SOCK=[]"),
        "agent forwarding must never be established, even with a full grant (got {out:?})"
    );

    drop(client);
    drop(node);
    Ok(())
}

async fn write_client_file(container: &ContainerAsync<GenericImage>, path: &str, content: &str) {
    let (code, _o, e) = exec(
        container,
        vec![
            "sh".into(),
            "-c".into(),
            format!("printf '%s' '{content}' > {path}"),
        ],
    )
    .await;
    assert_eq!(code, Some(0), "write {path} failed: {e}");
}

fn cert_authority_line(cp: &MockCp) -> String {
    let ca = ssh_key::PublicKey::from_bytes(&cp.host_ca_public_wire())
        .unwrap()
        .to_openssh()
        .unwrap();
    format!("@cert-authority * {ca}")
}

/// Client ssh_config for the ProxyJump path: `jump` is the Gateway (not the no-TOFU
/// boundary), `node-e2e` is reached via ProxyJump and verified strictly against the
/// `@cert-authority` line (as inner_leg_it's S16 MITM cases).
fn nested_proxyjump_ssh_config(gw_port: u16) -> String {
    format!(
        "Host jump\n\
         \tHostName 127.0.0.1\n\
         \tPort {gw_port}\n\
         \tUser deploy\n\
         \tIdentityFile /root/pin_key\n\
         \tIdentitiesOnly yes\n\
         \tPreferredAuthentications publickey\n\
         \tStrictHostKeyChecking no\n\
         \tUserKnownHostsFile /dev/null\n\
         \tBatchMode yes\n\
         \n\
         Host node-e2e\n\
         \tProxyJump jump\n\
         \tUser deploy\n\
         \tIdentityFile /root/pin_key\n\
         \tIdentitiesOnly yes\n\
         \tPreferredAuthentications publickey\n\
         \tUserKnownHostsFile /root/known_hosts_ca\n\
         \tStrictHostKeyChecking yes\n\
         \tBatchMode yes\n\
         \tConnectTimeout 30\n"
    )
}

/// A `direct-tcpip` from the already-terminated ProxyJump inner hop is refused
/// UNCONDITIONALLY — a maximal grant (incl. `port_forward_local`) must never open a
/// nested forward chain (one MITM hop only; S29 preserves S16's structural invariant).
#[tokio::test]
async fn nested_proxyjump_forward_refused_even_with_full_grant() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    cp.set_capabilities(
        NODE_ID,
        &[
            Capability::Shell,
            Capability::Exec,
            Capability::PortForwardLocal,
            Capability::PortForwardRemote,
            Capability::X11,
        ],
    );
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);
    let mut cfg = gw_config(RecorderConfig::default());
    cfg.proxy_jump = gateway_core::config::ProxyJumpConfig { enabled: true };
    let (gw_port, _sd) = start_gateway(&cp, Arc::new(cfg), RecorderChoice::Null).await;

    let client = client_container(&pin).await;
    write_client_file(&client, "/root/known_hosts_ca", &cert_authority_line(&cp)).await;
    write_client_file(
        &client,
        "/root/ssh_config",
        &nested_proxyjump_ssh_config(gw_port),
    )
    .await;

    // -L on the ProxyJump DESTINATION connection = a direct-tcpip on the terminated
    // inner hop. The session itself runs; the nested forward must carry nothing.
    let (_c, out, _e) = exec(
        &client,
        vec![
            "bash".into(),
            "-c".into(),
            "ssh -F /root/ssh_config -v -L 15622:127.0.0.1:22 node-e2e 'echo NESTED_OK; sleep 8' >/tmp/ssh.log 2>&1 & \
             SSHPID=$!; sleep 5; \
             (exec 3<>/dev/tcp/127.0.0.1/15622; head -c 15 <&3) 2>/dev/null || true; \
             echo; echo '===SSHLOG==='; wait $SSHPID; cat /tmp/ssh.log"
                .to_string(),
        ],
    )
    .await;
    let (probe, log) = out.split_once("===SSHLOG===").unwrap_or((out.as_str(), ""));
    assert!(
        log.contains("NESTED_OK"),
        "the ProxyJump session itself still runs (out: {out})"
    );
    assert!(
        !probe.contains("SSH-2.0"),
        "a nested direct-tcpip must be refused despite a full grant (probe: {probe:?})"
    );

    drop(client);
    drop(node);
    Ok(())
}

// ── E. Recording posture: metadata-only ──────────────────────────────────────

#[tokio::test]
async fn local_forward_records_metadata_only() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let (minio, s3) = start_minio().await?;
    cp.set_s3_target(s3.clone());
    let (cust_pub_der, cust_secret) = customer_keypair();
    cp.set_customer_key(
        "customer-key-1",
        cust_pub_der,
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
    );

    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    cp.set_capabilities(NODE_ID, &[Capability::Shell, Capability::PortForwardLocal]);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);
    let (gw_port, _sd) = start_gateway(
        &cp,
        Arc::new(gw_config(RecorderConfig::default())),
        RecorderChoice::Real,
    )
    .await;

    // Drive a local forward, move some bytes (the node's SSH banner), then close.
    let client = client_container(&pin).await;
    let (_c, out, _e) = exec(
        &client,
        local_forward_script(gw_port, 15322, "127.0.0.1:22"),
    )
    .await;
    let banner = out.split("===SSHLOG===").next().unwrap_or("");
    assert!(
        banner.contains("SSH-2.0"),
        "forward must carry bytes (full output: {out})"
    );
    // End the session so the recording finalizes.
    drop(client);

    let fin = await_finalized(&cp).await;
    assert_eq!(fin.status, RecordingStatus::Finalized as i32);
    let keys = cp.recorded_object_keys();
    assert_eq!(keys.len(), 1, "one WORM object for the session");
    let (status, object) = get_object(&s3, &keys[0]).await?;
    assert_eq!(status, 200);

    // Decrypt with the customer key: the object must carry the tunnel open/close
    // markers and NO forwarded byte content (the SSH banner never appears).
    let header = seal::parse_header(&object).unwrap();
    let key = seal::unseal_data_key(&header, &cust_secret).unwrap();
    let plaintext = seal::decrypt_frames(&object, &header, &key).unwrap();
    let text = String::from_utf8_lossy(&plaintext);
    assert!(
        text.contains("port_forward.opened"),
        "opened marker present"
    );
    assert!(
        text.contains("port_forward.closed"),
        "closed marker present"
    );
    assert!(
        text.contains("127.0.0.1:22"),
        "target recorded in the audit"
    );
    assert!(
        !text.contains("SSH-2.0"),
        "forwarded byte content MUST NOT be captured (metadata-only)"
    );

    // The cleartext CP-side copy (FinalizeRecordingRequest.tunnel_audit, v1.1.0):
    // one entry with the capability/direction/target + byte counters, no content.
    assert_eq!(
        fin.tunnel_audit.len(),
        1,
        "one tunnel audit for the -L channel"
    );
    let ta = &fin.tunnel_audit[0];
    assert_eq!(ta.capability, "port_forward_local");
    assert_eq!(ta.direction, "local");
    assert_eq!(ta.target, "127.0.0.1:22");
    assert!(ta.bytes_out > 0, "the node's banner bytes were counted");

    drop(node);
    drop(minio);
    Ok(())
}

// ── F. Lock teardown of a live forward ───────────────────────────────────────

#[tokio::test]
async fn a_lock_tears_down_a_live_forward() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    cp.set_capabilities(NODE_ID, &[Capability::Shell, Capability::PortForwardLocal]);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);
    let (gw_port, _sd) = start_gateway(
        &cp,
        Arc::new(gw_config(RecorderConfig::default())),
        RecorderChoice::Null,
    )
    .await;

    // A foreground local forward that keeps the connection alive; a lock matching
    // the node must tear the whole session (and its forward) down.
    cp.push_lock_after_recording_begins(gateway_core::pb::Lock {
        lock_id: "lock-fwd-1".into(),
        target: Some(gateway_core::pb::LockTarget {
            node_ids: vec![NODE_ID.to_string()],
            ..Default::default()
        }),
        reason: "incident".into(),
        ..Default::default()
    });

    let client = client_container(&pin).await;
    // -L with a command that idles: the forward opens (recording begins → lock
    // fires), and the session is dropped, so ssh returns non-zero.
    let (code, _o, _e) = exec(
        &client,
        ssh_cmd(
            gw_port,
            &["-L", "15422:127.0.0.1:22"],
            "sh -c 'echo READY; sleep 60'",
        ),
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "a locked session's forward must be torn down"
    );

    drop(client);
    drop(node);
    Ok(())
}

// ── MinIO helpers (only the metadata test needs a WORM store) ─────────────────

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
        if let Ok((200, _)) = sigv4::http_send("GET", &url, &[], Vec::new()).await {
            return Ok(());
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

async fn get_object(s3: &S3Target, object_key: &str) -> anyhow::Result<(u16, Vec<u8>)> {
    let path = format!("/{}/{}", s3.bucket, object_key);
    let (url, _h) = sigv4::presign(s3, "GET", &path, &[], &[], 900);
    sigv4::http_send("GET", &url, &[], Vec::new()).await
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
