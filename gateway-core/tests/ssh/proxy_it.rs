use std::sync::Arc;
use std::time::Duration;

use gateway_core::config::{ProxyProtocolConfig, SshServerConfig};
use gateway_core::ssh;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn v4_proxy_header(src: [u8; 4]) -> Vec<u8> {
    let mut h = vec![
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    h.push(0x21); // v2 | PROXY
    h.push(0x11); // AF_INET | STREAM
    h.extend_from_slice(&12u16.to_be_bytes());
    h.extend_from_slice(&src);
    h.extend_from_slice(&[10, 0, 0, 1]); // dest ip
    h.extend_from_slice(&[0x1F, 0x90, 0x00, 0x16]); // ports
    h
}

fn config(lb: &[&str], gate: &[&str]) -> Arc<SshServerConfig> {
    Arc::new(SshServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        proxy: ProxyProtocolConfig {
            lb_cidrs: lb.iter().map(|s| s.to_string()).collect(),
        },
        source_ip_allowlist: gate.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    })
}

async fn probe(addr: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut sock = TcpStream::connect(addr).await.unwrap();
    if !payload.is_empty() {
        sock.write_all(payload).await.ok();
    }
    let mut buf = vec![0u8; 64];
    match tokio::time::timeout(Duration::from_secs(3), sock.read(&mut buf)).await {
        Ok(Ok(n)) => buf[..n].to_vec(),
        _ => Vec::new(),
    }
}

fn is_banner(bytes: &[u8]) -> bool {
    bytes.starts_with(b"SSH-2.0-")
}

#[tokio::test]
async fn proxy_v2_and_source_ip_gate_matrix() {
    let cp = crate::support::MockCp::start().await;
    let deps = crate::support::outer_leg_deps(&cp, Arc::new(SshServerConfig::default())).await;

    async fn serve(
        cfg: Arc<SshServerConfig>,
        deps: gateway_core::ssh::handler::HandlerDeps,
    ) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
        let server = ssh::bind(cfg, deps).await.unwrap();
        let addr = server.local_addr();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(server.run(async move {
            let _ = rx.await;
        }));
        (addr, tx)
    }

    {
        let (addr, _tx) = serve(config(&["127.0.0.0/8"], &[]), deps.clone()).await;
        let got = probe(addr, &v4_proxy_header([203, 0, 113, 7])).await;
        assert!(
            is_banner(&got),
            "trusted-LB header must reach the SSH banner"
        );
    }

    {
        let (addr, _tx) = serve(config(&["10.0.0.0/8"], &[]), deps.clone()).await;
        let got = probe(addr, &v4_proxy_header([203, 0, 113, 7])).await;
        assert!(
            !is_banner(&got),
            "a header from a non-LB peer must be dropped"
        );
        assert!(got.is_empty(), "no banner bytes must be sent");
    }

    {
        let (addr, _tx) = serve(config(&["127.0.0.0/8"], &[]), deps.clone()).await;
        let got = probe(addr, b"SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n").await;
        assert!(
            !is_banner(&got),
            "a missing PROXY header from the LB must be dropped"
        );
    }

    {
        let (addr, _tx) = serve(config(&["127.0.0.0/8"], &["10.0.0.0/8"]), deps.clone()).await;
        let got = probe(addr, &v4_proxy_header([203, 0, 113, 7])).await;
        assert!(
            !is_banner(&got),
            "a source outside the gate must be dropped pre-banner"
        );
    }

    {
        let (addr, _tx) = serve(config(&["127.0.0.0/8"], &["203.0.113.0/24"]), deps.clone()).await;
        let got = probe(addr, &v4_proxy_header([203, 0, 113, 7])).await;
        assert!(is_banner(&got), "an in-gate source must reach the banner");
    }

    {
        let (addr, _tx) = serve(config(&[], &[]), deps.clone()).await;
        let got = probe(addr, &[]).await;
        assert!(
            is_banner(&got),
            "direct connection must be accepted with PROXY off"
        );
    }

    {
        let (addr, _tx) = serve(config(&[], &["10.0.0.0/8"]), deps.clone()).await;
        let got = probe(addr, &[]).await;
        assert!(
            !is_banner(&got),
            "a direct source outside the gate must be dropped"
        );
    }
}
