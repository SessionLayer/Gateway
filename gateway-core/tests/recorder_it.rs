//! Session Nine end-to-end: the **real session recorder + WORM store**.
//!
//! A stock OpenSSH client (Debian 13 container, never host ssh) runs a session
//! through the Gateway; the Gateway captures it as asciicast v2, **encrypts** it
//! under a customer-held P-256 key, hash-chains it, and PUTs the ciphertext object
//! straight to a **MinIO** WORM bucket via the CP-issued presigned URL. The test
//! then, holding the customer PRIVATE key, decrypts the stored object back to the
//! original terminal bytes — and proves that WITHOUT that private key (all a
//! platform actor holds) the object cannot be read. SFTP transfers yield per-op
//! file-transfer audit; a missing customer key / a broken spool refuses the
//! session (strict, fail closed).
//!
//! Networking mirrors S8: the client container is `--network host` (its
//! `127.0.0.1` is the host loopback the in-process Gateway + the mapped MinIO/node
//! ports live on); the node + MinIO run on the default bridge with mapped ports.

mod support;

use std::sync::Arc;
use std::time::Duration;

use gateway_core::config::{
    DeviceFlowConfig, InnerLegServerConfig, RecorderConfig, SshServerConfig,
};
use gateway_core::pb::{Capability, KeySealAlgorithm, RecordingStatus};
use gateway_core::ssh;
use gateway_core::ssh::recorder::{chain, seal};
use p256::pkcs8::EncodePublicKey;
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use support::sigv4::{self, S3Target};
use support::{MockCp, RecorderChoice};
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient";
const CLIENT_TAG: &str = "s8";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode";
const NODE_TAG: &str = "s8";
const NODE_ID: &str = "node-e2e";
const MINIO_IMAGE: &str = "minio/minio";
const MINIO_TAG: &str = "RELEASE.2025-04-08T15-41-24Z";
const MINIO_USER: &str = "minioadmin";
const MINIO_PASS: &str = "minioadmin";
const BUCKET: &str = "recordings";

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

/// A customer P-256 keypair: the DER SPKI public key configured on the CP, and the
/// secret kept in the test to prove decryptability (the platform holds neither).
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

/// Start MinIO, wait for it to be live, and create the **object-lock-enabled**
/// bucket. Returns the container + the S3 target the CP presigns against.
async fn start_minio() -> anyhow::Result<(ContainerAsync<GenericImage>, S3Target)> {
    ensure_docker_host();
    let container = GenericImage::new(MINIO_IMAGE, MINIO_TAG)
        // MinIO logs its startup banner (incl. "API: http://…") to stderr.
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

/// Fetch a stored object via a presigned GET.
async fn get_object(s3: &S3Target, object_key: &str) -> anyhow::Result<(u16, Vec<u8>)> {
    let path = format!("/{}/{}", s3.bucket, object_key);
    let (url, _h) = sigv4::presign(s3, "GET", &path, &[], &[], 900);
    sigv4::http_send("GET", &url, &[], Vec::new()).await
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

fn gw_config(recorder: RecorderConfig) -> SshServerConfig {
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

async fn ssh_exec(
    container: &ContainerAsync<GenericImage>,
    args: Vec<String>,
) -> (Option<i64>, String, String) {
    use testcontainers::core::ExecCommand;
    let mut res = container.exec(ExecCommand::new(args)).await.expect("exec");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

fn ssh_cmd(port: u16, extra: &[&str], target: &str, command: &str) -> Vec<String> {
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
    a.push(format!("{target}@127.0.0.1"));
    if !command.is_empty() {
        a.push(command.into());
    }
    a
}

fn grant(cp: &MockCp, pin: &KeyMat) {
    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", NODE_ID, "deploy");
}

/// Wire the pinned host-CA node connection for `node_port` (as S8 gate a).
fn wire_node(cp: &MockCp, host_key: &KeyMat, node_port: u16) {
    let (_l, cert_wire) = cp.sign_host_cert(&host_key.public_wire, &[NODE_ID], 3600);
    let trust = cp.host_ca_verification(cert_wire, &[NODE_ID]);
    cp.set_node_connection(NODE_ID, &format!("127.0.0.1:{node_port}"), trust);
}

/// Poll until the Gateway has finalized (uploaded + committed) a recording.
async fn await_finalized(cp: &MockCp) -> gateway_core::pb::FinalizeRecordingRequest {
    for _ in 0..80 {
        let fins = cp.finalized_recordings();
        if let Some(f) = fins.into_iter().next() {
            return f;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("the recording was never finalized");
}

// ── Headline: a terminal session is recorded, encrypted, and WORM-stored ─────

#[tokio::test]
async fn terminal_session_is_recorded_encrypted_and_worm_locked() -> anyhow::Result<()> {
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
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(RecorderConfig::default()))).await;
    let client = client_container(&pin).await;

    // Run a command; its output flows through the recorder tap.
    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(gw_port, &[], "deploy%node-e2e", "echo IT_WORKS_RECORDED"),
    )
    .await;
    assert_eq!(code, Some(0), "session must run; stderr={stderr}");
    assert!(stdout.contains("IT_WORKS_RECORDED"));

    // The recording finalizes off the connection teardown (upload → FinalizeRecording).
    let fin = await_finalized(&cp).await;
    assert_eq!(fin.status, RecordingStatus::Finalized as i32);
    assert!(
        fin.hash_chain_head.starts_with("sha256:"),
        "hash-chain head committed"
    );
    assert!(fin.byte_len > 0);

    // The encrypted object landed in the WORM bucket.
    let object_keys = cp.recorded_object_keys();
    assert_eq!(
        object_keys.len(),
        1,
        "one recording, one object (single-object cred)"
    );
    let (status, object) = get_object(&s3, &object_keys[0]).await?;
    assert_eq!(status, 200, "the object is present in MinIO");
    assert_eq!(
        object.len() as i64,
        fin.byte_len,
        "finalize byte_len matches the object"
    );
    assert_eq!(
        chain::sha256_hex(&object),
        fin.content_digest,
        "finalize content_digest is over the uploaded ciphertext"
    );

    // A platform actor (customer PUBLIC key + object only) cannot decrypt: unsealing
    // with any other private key fails.
    let header = seal::parse_header(&object).unwrap();
    let (_other_pub, other_secret) = customer_keypair();
    assert!(
        seal::unseal_data_key(&header, &other_secret).is_err(),
        "the recording must NOT be decryptable without the customer private key"
    );

    // WITH the customer private key, the object decrypts to the original asciicast.
    let key = seal::unseal_data_key(&header, &cust_secret).unwrap();
    let plaintext = seal::decrypt_frames(&object, &header, &key).unwrap();
    let text = String::from_utf8_lossy(&plaintext);
    assert!(
        text.contains("\"version\":2"),
        "asciicast v2 header present"
    );
    assert!(
        text.contains("IT_WORKS_RECORDED"),
        "the node output is captured in the recording"
    );

    // WORM: the object is under COMPLIANCE object-lock (retention was applied).
    let ret_path = format!("/{}/{}", s3.bucket, object_keys[0]);
    let (ret_url, _h) = sigv4::presign(&s3, "GET", &ret_path, &[("retention", "")], &[], 900);
    let (ret_status, ret_body) = sigv4::http_send("GET", &ret_url, &[], Vec::new()).await?;
    assert_eq!(ret_status, 200, "the object carries a retention config");
    assert!(
        String::from_utf8_lossy(&ret_body).contains("COMPLIANCE"),
        "the object is COMPLIANCE-locked (WORM); body={}",
        String::from_utf8_lossy(&ret_body)
    );

    drop(node);
    drop(minio);
    Ok(())
}

// ── SFTP transfers are protocol-decoded into file-transfer audit ─────────────

#[tokio::test]
async fn sftp_transfer_is_audited() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let (minio, s3) = start_minio().await?;
    cp.set_s3_target(s3);
    let (cust_pub_der, _secret) = customer_keypair();
    cp.set_customer_key(
        "ck",
        cust_pub_der,
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
    );

    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    cp.set_capabilities(
        NODE_ID,
        &[Capability::Shell, Capability::Exec, Capability::Sftp],
    );
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(RecorderConfig::default()))).await;
    let client = client_container(&pin).await;

    // Upload a known file, then download it back, over SFTP.
    let script = format!(
        "set -e; head -c 4096 /dev/urandom > /tmp/upload.bin; \
         printf 'put /tmp/upload.bin /tmp/remote.bin\\nget /tmp/remote.bin /tmp/back.bin\\nquit\\n' | \
         sftp -i /root/pin_key -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null -o BatchMode=yes -P {gw_port} -b - deploy%node-e2e@127.0.0.1"
    );
    let (code, _o, stderr) = ssh_exec(&client, vec!["sh".into(), "-c".into(), script]).await;
    assert_eq!(code, Some(0), "sftp put+get must succeed; stderr={stderr}");

    let fin = await_finalized(&cp).await;
    // Exactly one upload and one download were audited (path/direction/size/sha256).
    let uploads: Vec<_> = fin
        .sftp_audit
        .iter()
        .filter(|a| a.direction == "upload")
        .collect();
    let downloads: Vec<_> = fin
        .sftp_audit
        .iter()
        .filter(|a| a.direction == "download")
        .collect();
    assert!(
        !uploads.is_empty(),
        "an upload was audited; audit={:?}",
        fin.sftp_audit
    );
    assert!(
        !downloads.is_empty(),
        "a download was audited; audit={:?}",
        fin.sftp_audit
    );
    let up = uploads[0];
    assert_eq!(up.size, 4096, "upload size captured");
    assert!(up.sha256.starts_with("sha256:") && up.sha256.len() == "sha256:".len() + 64);
    assert!(
        up.path.contains("remote.bin"),
        "upload path captured: {}",
        up.path
    );
    // The uploaded and downloaded content are the same file → identical SHA-256.
    assert_eq!(up.sha256, downloads[0].sha256, "same content round-trips");

    drop(node);
    drop(minio);
    Ok(())
}

// ── Strict mode: no customer key ⇒ the session is refused (fail closed) ───────

#[tokio::test]
async fn strict_mode_refuses_when_no_customer_key() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let (minio, s3) = start_minio().await?;
    cp.set_s3_target(s3);
    // Deliberately DO NOT configure a customer key (keystroke capture is always on).

    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(RecorderConfig::default()))).await;
    let client = client_container(&pin).await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(gw_port, &[], "deploy%node-e2e", "echo SHOULD_NOT_RUN"),
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "no customer key ⇒ the session must be refused"
    );
    assert!(
        !stdout.contains("SHOULD_NOT_RUN"),
        "the command must NOT run on the node (recording is mandatory)"
    );
    assert!(
        stderr.contains("recording unavailable"),
        "the user sees the strict recording-unavailable outcome; stderr={stderr}"
    );

    drop(node);
    drop(minio);
    Ok(())
}

// ── Strict mode: a broken ciphertext spool ⇒ the session is refused ──────────

#[tokio::test]
async fn strict_mode_refuses_when_spool_is_unwritable() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let (minio, s3) = start_minio().await?;
    cp.set_s3_target(s3);
    let (cust_pub_der, _s) = customer_keypair();
    cp.set_customer_key(
        "ck",
        cust_pub_der,
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
    );

    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_node(&cp, &host_key, node_port);

    // A spool dir that does not exist + threshold 0 ⇒ the first (setup) ciphertext
    // write spills to an unwritable path and fails, refusing the session (strict).
    let recorder = RecorderConfig {
        strict: true,
        spool_dir: Some(std::path::PathBuf::from("/nonexistent/sessionlayer-spool")),
        spool_memory_threshold_bytes: 0,
        ..RecorderConfig::default()
    };
    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config(recorder))).await;
    let client = client_container(&pin).await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(gw_port, &[], "deploy%node-e2e", "echo SHOULD_NOT_RUN"),
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "a broken recording spool must refuse the session"
    );
    assert!(!stdout.contains("SHOULD_NOT_RUN"));
    assert!(
        stderr.contains("recording unavailable"),
        "strict recording failure → refused; stderr={stderr}"
    );

    drop(node);
    drop(minio);
    Ok(())
}
