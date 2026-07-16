//! ProxyJump host-cert MITM (Session Sixteen, Part C; Design §9.3/§11, FR-ADDR-1).
//!
//! On `ssh -J gw login@node` a stock client opens a `direct-tcpip` channel to the
//! node through the (authenticated) jump connection, then runs a fresh SSH
//! handshake to the node over it. The Gateway **terminates** that inner hop: it
//! runs an SSH server over the forwarded channel presenting a **host-CA-signed host
//! certificate** for the node, so a client that installed one `@cert-authority`
//! line verifies it with **no TOFU** (never a trust-on-first-use prompt). The inner
//! hop then runs the full session seam (auth → authorize → inner leg → recorder →
//! bridge) reused verbatim — only the target node comes from the `direct-tcpip`
//! request instead of the username, and agent forwarding stays refused (FR-SESS-2).
//!
//! Key custody (D2): the Gateway generates the outer host keypair locally and sends
//! only the public key to the CP; the CP returns a certificate only.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// russh vendors ssh-key 0.7-rc; the rest of the Gateway (and keygen below) uses
// ssh-key 0.6. `Certificate`/`PrivateKey` here are russh's types (for the server
// Config); the host key is generated with the 0.6 crate and bridged via an OpenSSH
// PEM round-trip, exactly as the inner leg does (handler.rs).
use russh::keys::{Certificate, PrivateKey};
use russh::server::Config as RusshConfig;
use russh::{MethodKind, MethodSet, SshId};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::cpauth::CpAuthClient;
use crate::ssh::handler::{ConnState, HandlerDeps, SshHandler};
use crate::ssh::target::strip_dns_suffix;

/// Refetch a host cert this many seconds before `valid_before` (skew + reuse).
const CERT_REFRESH_SKEW_SECS: u64 = 60;

/// Hard cap on the per-principal host-cert cache. The principal is the fully
/// client-controlled `direct-tcpip` host, so the cache is bounded (evicting expired
/// entries first, then the soonest-to-expire) to deny a memory-exhaustion path — a
/// jump connection cannot grow it without limit (S16 F-proxyjump-dos, defence in
/// depth with the per-connection channel cap that bounds the mint rate).
const MAX_CACHED_HOST_CERTS: usize = 256;

/// A ProxyJump setup failure. Coarse on purpose: any failure fails the inner hop
/// closed (the channel is dropped → the client sees a connection failure), never a
/// TOFU fallback.
#[derive(Debug, thiserror::Error)]
pub enum ProxyJumpError {
    /// The CP could not sign / return a usable outer host certificate.
    #[error("outer host certificate unavailable")]
    HostCertUnavailable,
    /// The Gateway's outer host keypair could not be generated at startup.
    #[error("outer host key generation failed")]
    KeyGen,
}

struct CachedCert {
    cert: Certificate,
    valid_before: u64,
}

/// Per-server ProxyJump state: the Gateway's outer host keypair (ECDSA P-256,
/// generated once at startup; the private key never leaves) and a per-principal
/// cache of host-CA-signed host certs fetched from the CP. Shared (`Arc`) into
/// [`HandlerDeps`]; present only when ProxyJump is enabled.
pub struct ProxyJumpState {
    host_key: PrivateKey,
    host_public_key_wire: Vec<u8>,
    certs: Mutex<HashMap<String, CachedCert>>,
}

impl std::fmt::Debug for ProxyJumpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the host private key.
        f.debug_struct("ProxyJumpState").finish_non_exhaustive()
    }
}

impl ProxyJumpState {
    /// Generate the Gateway's outer host keypair (ECDSA P-256, matching the P-256
    /// host CA / D6). The private key never leaves the process. Fail-closed: a
    /// keygen failure aborts ProxyJump setup. Generated with the Gateway's ssh-key
    /// 0.6 crate (the public-key wire form is what the CP signs), then bridged into
    /// russh's `PrivateKey` (its ssh-key 0.7-rc) via an OpenSSH PEM round-trip so it
    /// can be placed in the russh server `Config` (same technique as the inner leg).
    pub fn new() -> Result<Self, ProxyJumpError> {
        let generated = ssh_key::PrivateKey::random(
            &mut rand_core::OsRng,
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .map_err(|_| ProxyJumpError::KeyGen)?;
        let host_public_key_wire = generated
            .public_key()
            .to_bytes()
            .map_err(|_| ProxyJumpError::KeyGen)?;
        let pem = generated
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|_| ProxyJumpError::KeyGen)?;
        let host_key = PrivateKey::from_openssh(&pem).map_err(|_| ProxyJumpError::KeyGen)?;
        Ok(Self {
            host_key,
            host_public_key_wire,
            certs: Mutex::new(HashMap::new()),
        })
    }

    /// The host certificate to present for `principal` (the exact hostname the
    /// client dialed): a cached, non-expiring-soon cert, else a fresh one signed by
    /// the CP host CA. Fail-closed on any CP/parse failure.
    async fn cert_for(
        &self,
        cpauth: &CpAuthClient,
        principal: &str,
    ) -> Result<Certificate, ProxyJumpError> {
        let now = now_epoch_secs();
        {
            let cache = self.certs.lock().await;
            if let Some(cached) = cache.get(principal) {
                if cached.valid_before > now.saturating_add(CERT_REFRESH_SKEW_SECS) {
                    return Ok(cached.cert.clone());
                }
            }
        }
        let resp = cpauth
            .sign_gateway_host_certificate(
                self.host_public_key_wire.clone(),
                vec![principal.to_string()],
            )
            .await
            .map_err(|_| ProxyJumpError::HostCertUnavailable)?;
        let cert = Certificate::from_bytes(&resp.certificate_blob)
            .map_err(|_| ProxyJumpError::HostCertUnavailable)?;
        let mut cache = self.certs.lock().await;
        // Bound the cache (the key is attacker-controlled): drop expired entries, then
        // if still at the cap, evict the soonest-to-expire before inserting.
        if cache.len() >= MAX_CACHED_HOST_CERTS && !cache.contains_key(principal) {
            cache.retain(|_, c| c.valid_before > now);
            if cache.len() >= MAX_CACHED_HOST_CERTS {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, c)| c.valid_before)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest);
                }
            }
        }
        cache.insert(
            principal.to_string(),
            CachedCert {
                cert: cert.clone(),
                valid_before: resp.valid_before_epoch_seconds.max(0) as u64,
            },
        );
        Ok(cert)
    }
}

/// Terminate the inner hop of a ProxyJump connection over the forwarded channel
/// `stream`. Presents a host-CA host cert for `host_to_connect`, then runs the full
/// session seam via an inner [`SshHandler`] whose node is fixed by the request. The
/// authorization node is the wildcard-DNS-stripped host; the cert principal is the
/// exact hostname the client dialed (OpenSSH matches the presented cert against it).
pub async fn serve_inner_hop<S>(
    deps: HandlerDeps,
    pj: Arc<ProxyJumpState>,
    source_ip: IpAddr,
    host_to_connect: String,
    stream: S,
    login_grace: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let principal = host_to_connect.clone();
    let node = strip_dns_suffix(&host_to_connect, &deps.config.node_dns_suffixes);

    let cert = match pj.cert_for(&deps.cpauth, &principal).await {
        Ok(cert) => cert,
        Err(_) => {
            // No host cert → we cannot present a verifiable identity; fail closed
            // (drop the channel) rather than TOFU. The client sees a closed inner hop.
            tracing::warn!(source_ip = %source_ip, outcome = "node_unreachable", reason = "host_cert_unavailable", "ProxyJump: outer host cert unavailable; dropping inner hop (no TOFU)");
            return;
        }
    };

    let mut methods = MethodSet::empty();
    methods.push(MethodKind::PublicKey);
    methods.push(MethodKind::KeyboardInteractive);
    let config = Arc::new(RusshConfig {
        server_id: SshId::Standard("SSH-2.0-SessionLayer_Gateway".into()),
        methods,
        keys: vec![pj.host_key.clone()],
        // The host CERTIFICATE presented at KEX (SessionLayer russh patch): the
        // client verifies it against its `@cert-authority` line (no TOFU).
        host_certificates: vec![cert],
        inactivity_timeout: Some(Duration::from_secs(deps.config.inner.max_session_idle_secs)),
        auth_rejection_time: Duration::from_secs(1),
        ..Default::default()
    });

    let conn = Arc::new(ConnState::default());
    let handler = SshHandler::new_proxyjump(deps, source_ip, conn.clone(), node);

    match russh::server::run_stream(config, stream, handler).await {
        Ok(running) => {
            // The outer jump connection already authenticated, so the inner hop needs
            // its own pre-auth deadline (russh's inactivity_timeout resets per packet).
            let handle = running.handle();
            let wd = conn.clone();
            let watchdog = tokio::spawn(async move {
                tokio::time::sleep(login_grace).await;
                if !wd.authenticated.load(Ordering::SeqCst) {
                    let _ = handle
                        .disconnect(
                            russh::Disconnect::ByApplication,
                            "authentication timed out".to_string(),
                            String::new(),
                        )
                        .await;
                }
            });
            if let Err(e) = running.await {
                tracing::debug!(error = ?e, source_ip = %source_ip, "ProxyJump inner session ended");
            }
            watchdog.abort();
        }
        Err(e) => {
            tracing::debug!(error = ?e, source_ip = %source_ip, "ProxyJump inner handshake failed");
        }
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
