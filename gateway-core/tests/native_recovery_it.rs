//! FR-ACC-7 end-to-end: the platform's `TrustedUserCAKeys` on a node is **additive**
//! to the node's own sshd — an operator-owned NATIVE SSH login (a plain
//! authorized_keys key) still succeeds ALONGSIDE the platform session-CA cert path.
//! This is the independent recovery path the design promises (agentless = register
//! address only; the platform never replaces the node's native auth). Never host
//! ssh — the client + node are containers.

mod support;

use std::time::Duration;

use gateway_core::{identity, mtls, signing};
use rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use support::docker::build_image;
use support::MockCp;
use testcontainers::core::{ExecCommand, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient:s24acc7";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode:s24acc7";
const CT: Duration = Duration::from_secs(5);
const RT: Duration = Duration::from_secs(10);

struct KeyMat {
    private_openssh: String,
    public_line: String,
}

fn gen_key() -> KeyMat {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    KeyMat {
        private_openssh: key.to_openssh(LineEnding::LF).unwrap().to_string(),
        public_line: key.public_key().to_openssh().unwrap(),
    }
}

async fn build_images() -> anyhow::Result<()> {
    build_image("ssh-client", CLIENT_IMAGE).await?;
    build_image("sshd", NODE_IMAGE).await
}

async fn exec(c: &ContainerAsync<GenericImage>, args: &[&str]) -> (Option<i64>, String, String) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    exec_owned(c, args).await
}

async fn exec_owned(
    c: &ContainerAsync<GenericImage>,
    args: Vec<String>,
) -> (Option<i64>, String, String) {
    let mut res = c.exec(ExecCommand::new(args)).await.expect("exec");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

fn native_login(port: u16, key_path: &str, marker: &str) -> Vec<String> {
    vec![
        "ssh".into(),
        "-p".into(),
        port.to_string(),
        "-i".into(),
        key_path.into(),
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
        "deploy@127.0.0.1".into(),
        "echo".into(),
        marker.into(),
    ]
}

#[tokio::test]
async fn native_ssh_login_works_alongside_the_platform_trusted_user_ca() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;

    // The operator's OWN native key (an authorized_keys entry the node's sshd honors),
    // and an UNAUTHORIZED native key (must be refused — auth is genuine, not open).
    let native = gen_key();
    let stranger = gen_key();

    // Start the node trusting the platform SESSION CA (additive) — exactly the
    // agentless posture. The native authorized_keys is installed afterwards.
    let node = GenericImage::new(
        NODE_IMAGE.split(':').next().unwrap(),
        NODE_IMAGE.split(':').nth(1).unwrap(),
    )
    .with_wait_for(WaitFor::message_on_stderr("Server listening on"))
    .with_startup_timeout(Duration::from_secs(120))
    .with_env_var("TRUSTED_USER_CA", cp.session_ca_public_line())
    .start()
    .await?;
    let node_port = node.get_host_port_ipv4(22).await?;

    // Install the operator's native authorized_keys for `deploy` with correct
    // ownership/permissions (sshd StrictModes) — an independent, node-owned path.
    let setup = format!(
        "mkdir -p /home/deploy/.ssh && printf '%s\\n' '{}' > /home/deploy/.ssh/authorized_keys && chown -R deploy:deploy /home/deploy/.ssh && chmod 700 /home/deploy/.ssh && chmod 600 /home/deploy/.ssh/authorized_keys",
        native.public_line.trim()
    );
    let (code, _o, e) = exec(&node, &["sh", "-c", &setup]).await;
    assert_eq!(
        code,
        Some(0),
        "installing the native authorized_keys must succeed; stderr={e}"
    );

    // A platform SESSION-CA cert for the same login (the platform path), to prove the
    // two auth paths COEXIST on one node.
    let dir = tempfile::tempdir()?;
    let store = identity::IdentityStore::open(dir.path())?;
    let params = cp.channel_params(CT, RT);
    let cred = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-acc7",
    )
    .await?;
    let token = cp.mint_session_token(
        &cred.gateway_id,
        "sess-acc7",
        "node-acc7",
        "deploy",
        Duration::from_secs(120),
    );
    let inner = signing::InnerKeyPair::generate()?;
    let ch = mtls::connect_mtls(&params, &cred.ca_chain_der, &cred.identity).await?;
    let signed = signing::sign_session_certificate(ch, &token, &inner, None, RT).await?;

    // The client container: the native private key, the unauthorized key, and the
    // platform inner key + cert.
    let client = GenericImage::new(
        CLIENT_IMAGE.split(':').next().unwrap(),
        CLIENT_IMAGE.split(':').nth(1).unwrap(),
    )
    .with_network("host")
    .with_startup_timeout(Duration::from_secs(60))
    .with_copy_to(
        CopyTargetOptions::new("/root/native").with_mode(0o600),
        native.private_openssh.clone().into_bytes(),
    )
    .with_copy_to(
        CopyTargetOptions::new("/root/stranger").with_mode(0o600),
        stranger.private_openssh.clone().into_bytes(),
    )
    .with_copy_to(
        CopyTargetOptions::new("/root/inner").with_mode(0o600),
        inner.private_key_openssh_pem()?.as_bytes().to_vec(),
    )
    .with_copy_to(
        CopyTargetOptions::new("/root/inner-cert.pub").with_mode(0o644),
        signed.certificate_line.clone().into_bytes(),
    )
    .start()
    .await?;

    // (1) The operator's NATIVE key logs in — the independent recovery path works
    // even with the platform CA trusted on the node.
    let (code, stdout, stderr) = exec_owned(
        &client,
        native_login(node_port, "/root/native", "NATIVE_RECOVERY_OK"),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "native authorized_keys login must succeed alongside TrustedUserCAKeys; stderr={stderr}"
    );
    assert!(
        stdout.contains("NATIVE_RECOVERY_OK"),
        "native login output; stdout={stdout:?}"
    );

    // (2) The platform SESSION-CA cert path ALSO works on the same node — the two are
    // additive, not mutually exclusive.
    let (code, stdout, stderr) = exec(
        &client,
        &[
            "ssh",
            "-p",
            &node_port.to_string(),
            "-i",
            "/root/inner",
            "-o",
            "CertificateFile=/root/inner-cert.pub",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "deploy@127.0.0.1",
            "echo",
            "PLATFORM_CA_OK",
        ],
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "the platform session-CA cert path must still work on the same node; stderr={stderr}"
    );
    assert!(
        stdout.contains("PLATFORM_CA_OK"),
        "platform cert login output; stdout={stdout:?}"
    );

    // (3) An UNAUTHORIZED native key is refused — the native path is genuine auth,
    // not open access.
    let (code, _o, _e) = exec_owned(
        &client,
        native_login(node_port, "/root/stranger", "SHOULD_NOT_RUN"),
    )
    .await;
    assert_ne!(code, Some(0), "an unauthorized native key must be refused");

    drop(client);
    drop(node);
    Ok(())
}
