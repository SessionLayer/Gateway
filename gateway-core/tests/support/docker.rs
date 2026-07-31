//! Docker harness: image builds, MinIO WORM, rootless endpoint discovery.

#![allow(dead_code)] // shared across several test binaries; not all use every item.

use std::time::Duration;

use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use super::sigv4::{self, S3Target};

pub const MINIO_IMAGE: &str = "minio/minio";
pub const MINIO_TAG: &str = "RELEASE.2025-04-08T15-41-24Z";
pub const MINIO_USER: &str = "minioadmin";
pub const MINIO_PASS: &str = "minioadmin";
pub const BUCKET: &str = "recordings";

pub fn ensure_docker_host() {
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

pub fn container_reachable_host_ip() -> std::net::IpAddr {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("1.1.1.1:80")?;
            s.local_addr()
        })
        .map(|a| a.ip())
        .expect("a routable local address")
}

pub async fn build_image_with_args(
    subdir: &str,
    tag: &str,
    build_args: &[(&str, &str)],
) -> anyhow::Result<()> {
    ensure_docker_host();
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures")
        .join(subdir);
    anyhow::ensure!(dir.is_dir(), "fixture missing: {}", dir.display());

    let tag = tag.to_string();
    let args: Vec<String> = build_args
        .iter()
        .flat_map(|(k, v)| ["--build-arg".to_string(), format!("{k}={v}")])
        .collect();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("docker")
            .args(["build", "-t", &tag])
            .args(&args)
            .arg(&dir)
            .output()
    })
    .await??;
    anyhow::ensure!(
        out.status.success(),
        "docker build of {subdir} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

pub async fn build_image(subdir: &str, tag: &str) -> anyhow::Result<()> {
    build_image_with_args(subdir, tag, &[]).await
}

pub async fn start_minio() -> anyhow::Result<(ContainerAsync<GenericImage>, S3Target)> {
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

pub async fn get_object(s3: &S3Target, object_key: &str) -> anyhow::Result<(u16, Vec<u8>)> {
    let path = format!("/{}/{}", s3.bucket, object_key);
    let (url, _h) = sigv4::presign(s3, "GET", &path, &[], &[], 900);
    sigv4::http_send("GET", &url, &[], Vec::new()).await
}
