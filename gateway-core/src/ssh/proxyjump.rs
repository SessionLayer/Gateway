//! ProxyJump host-cert MITM: client verifies no-TOFU, inner hop runs full seam (the inner
//! private key is generated on the Gateway and never leaves it).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use russh::keys::{Certificate, PrivateKey};
use russh::server::Config as RusshConfig;
use russh::{MethodKind, MethodSet, SshId};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::cpauth::CpAuthClient;
use crate::ssh::handler::{ConnState, HandlerDeps, SshHandler};
use crate::ssh::target::strip_dns_suffix;
use crate::telemetry::metrics::{self, UnreachableReason};

const CERT_REFRESH_SKEW_SECS: u64 = 60;

const MAX_CACHED_HOST_CERTS: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum ProxyJumpError {
    #[error("outer host certificate unavailable")]
    HostCertUnavailable,
    #[error("outer host key generation failed")]
    KeyGen,
}

struct CachedCert {
    cert: Certificate,
    valid_before: u64,
}

pub struct ProxyJumpState {
    host_key: PrivateKey,
    host_public_key_wire: Vec<u8>,
    certs: Mutex<HashMap<String, CachedCert>>,
}

impl std::fmt::Debug for ProxyJumpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyJumpState").finish_non_exhaustive()
    }
}

impl ProxyJumpState {
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
            let m = metrics::node_unreachable(UnreachableReason::HostCertUnavailable);
            tracing::warn!(source_ip = %source_ip, outcome = m.outcome(), reason = m.reason(), "ProxyJump: outer host cert unavailable; dropping inner hop (no TOFU)");
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
        host_certificates: vec![cert],
        inactivity_timeout: Some(Duration::from_secs(deps.config.inner.max_session_idle_secs)),
        auth_rejection_time: Duration::from_secs(1),
        ..Default::default()
    });

    let conn = Arc::new(ConnState::default());
    let handler = SshHandler::new_proxyjump(deps, source_ip, conn.clone(), node);

    match russh::server::run_stream(config, stream, handler).await {
        Ok(running) => {
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
