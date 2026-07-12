//! Outer-leg CP auth/authorize client (Session Seven, Part D).
//!
//! The Gateway is a thin PEP: it verifies nothing it can instead ask the CP to
//! decide. This module is the client half of that delegation — the five
//! `OuterLegAuth` credential-resolution RPCs and the S5 `Authorize` decision,
//! all over the **authenticated mTLS channel** the Gateway already builds
//! (`mtls::connect_mtls`, reusing the `signing.rs` client pattern).
//!
//! Every call is **time-bounded** (fail-closed, §10.3/NFR-2): a hung or
//! unreachable CP never hangs the SSH handshake, and a failure is never a
//! fail-open. CP-supplied status **messages are never rendered** — only the gRPC
//! status code (untrusted wire text; log-injection / terminal-escape guard, same
//! as `SigningError::Rpc`).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex};
use tonic::transport::Channel;

use crate::mtls::{self, ChannelParams, ClientIdentity, MtlsError};
use crate::pb::authorization_client::AuthorizationClient;
use crate::pb::outer_leg_auth_client::OuterLegAuthClient;
use crate::pb::{
    AuthorizeRequest, AuthorizeResponse, BeginDeviceFlowRequest, BeginDeviceFlowResponse,
    PollDeviceFlowRequest, PollDeviceFlowResponse, ResolveOtpRequest, ResolvePinRequest,
    ResolveUserCertRequest, ResolvedIdentity,
};

/// A failure calling the CP. Fail-closed at every variant.
#[derive(Debug, thiserror::Error)]
pub enum CpError {
    /// The mTLS channel to the CP could not be established (CP down, TLS/connect
    /// failure). Fail closed → "service temporarily unavailable".
    #[error("Control Plane unreachable")]
    Unreachable(#[source] MtlsError),

    /// A recent connect failed and the circuit breaker is open — the CP is
    /// treated as down and calls fail fast (no per-call connect storm).
    #[error("Control Plane unreachable (circuit open)")]
    CircuitOpen,

    /// The RPC did not complete within its deadline — a hung CP must never hang
    /// the SSH handshake.
    #[error("Control Plane RPC timed out after {0:?}")]
    Timeout(Duration),

    /// The CP returned an error status. Only the gRPC status **code** is rendered
    /// — never the CP-supplied message (untrusted wire text). The code stays
    /// available via [`CpError::code`].
    #[error("Control Plane RPC failed (gRPC status {:?})", .0.code())]
    Rpc(tonic::Status),
}

impl CpError {
    /// The gRPC status code, when this is an RPC error (for classification).
    pub fn code(&self) -> Option<tonic::Code> {
        match self {
            CpError::Rpc(s) => Some(s.code()),
            _ => None,
        }
    }

    /// Whether this error means the CP could not give an answer — a transport /
    /// timeout / circuit / server-side infrastructure failure — as opposed to a
    /// clean policy outcome. Used to distinguish "CP down → service unavailable"
    /// from an ordinary non-resolution (§7.1, fail closed).
    pub fn is_cp_down(&self) -> bool {
        match self {
            CpError::Unreachable(_) | CpError::CircuitOpen | CpError::Timeout(_) => true,
            CpError::Rpc(s) => matches!(
                s.code(),
                tonic::Code::Unavailable
                    | tonic::Code::Internal
                    | tonic::Code::DeadlineExceeded
                    | tonic::Code::Unknown
                    | tonic::Code::Unauthenticated
                    | tonic::Code::DataLoss
            ),
        }
    }
}

/// A point-in-time snapshot of the Gateway's mTLS client credential used to build
/// CP channels. Refreshed transparently as the identity renews (§8.1).
#[derive(Clone)]
pub struct CredentialSnapshot {
    /// The Gateway's mTLS client identity (leaf + key).
    pub identity: ClientIdentity,
    /// Trust anchors (DER) for verifying the CP server certificate.
    pub ca_chain_der: Vec<Vec<u8>>,
}

/// Builds authenticated mTLS channels to the CP from the current credential.
///
/// Renewal-aware: it reads the latest credential from a `watch` each time it
/// connects, so a rotated identity is picked up without a restart.
pub struct CpChannelFactory {
    params: ChannelParams,
    rx: watch::Receiver<CredentialSnapshot>,
    // Kept alive so the watch stays open for [`Self::fixed`] callers (tests/dev).
    _tx: Option<watch::Sender<CredentialSnapshot>>,
}

impl CpChannelFactory {
    /// A factory over a fixed credential snapshot (tests / a single boot).
    pub fn fixed(
        params: ChannelParams,
        identity: ClientIdentity,
        ca_chain_der: Vec<Vec<u8>>,
    ) -> Self {
        let (tx, rx) = watch::channel(CredentialSnapshot {
            identity,
            ca_chain_der,
        });
        Self {
            params,
            rx,
            _tx: Some(tx),
        }
    }

    /// A factory that tracks a renewing credential (the daemon path).
    pub fn from_watch(params: ChannelParams, rx: watch::Receiver<CredentialSnapshot>) -> Self {
        Self {
            params,
            rx,
            _tx: None,
        }
    }

    async fn connect(&self) -> Result<Channel, MtlsError> {
        let snap = self.rx.borrow().clone();
        mtls::connect_mtls(&self.params, &snap.ca_chain_der, &snap.identity).await
    }
}

/// How long a failed connect keeps the circuit breaker open, so a partitioned CP
/// fails queued calls fast instead of each camping a full connect timeout.
const BREAKER_COOLDOWN: Duration = Duration::from_secs(1);

/// The CP outer-leg auth/authorize client. Cheap to share (`Arc`); caches one
/// mTLS channel and multiplexes RPCs over it, rebuilding on a transport fault.
pub struct CpAuthClient {
    factory: Arc<CpChannelFactory>,
    rpc_timeout: Duration,
    channel: Mutex<Option<Channel>>,
    /// When the last connect failed. While within [`BREAKER_COOLDOWN`], new
    /// calls fail fast (circuit open) rather than each attempting a full connect.
    breaker: Mutex<Option<std::time::Instant>>,
}

impl CpAuthClient {
    /// Build a client over `factory`, bounding every RPC by `rpc_timeout`.
    pub fn new(factory: Arc<CpChannelFactory>, rpc_timeout: Duration) -> Self {
        Self {
            factory,
            rpc_timeout,
            channel: Mutex::new(None),
            breaker: Mutex::new(None),
        }
    }

    /// Obtain a channel to the CP. The connect is performed **without holding the
    /// channel lock** (a partitioned CP must not serialize every connection behind
    /// one full-timeout connect), with a double-check afterwards and a short
    /// circuit breaker so a known-down CP fails fast.
    async fn channel(&self) -> Result<Channel, CpError> {
        // Fast path: a channel is already cached.
        if let Some(ch) = self.channel.lock().await.as_ref() {
            return Ok(ch.clone());
        }
        // Circuit breaker: a very recent connect failed → fail fast.
        if let Some(at) = *self.breaker.lock().await {
            if at.elapsed() < BREAKER_COOLDOWN {
                return Err(CpError::CircuitOpen);
            }
        }
        // Build the channel WITHOUT holding the channel lock.
        match self.factory.connect().await {
            Ok(ch) => {
                *self.breaker.lock().await = None;
                let mut guard = self.channel.lock().await;
                // Double-check: another task may have cached one meanwhile.
                if let Some(existing) = guard.as_ref() {
                    return Ok(existing.clone());
                }
                *guard = Some(ch.clone());
                Ok(ch)
            }
            Err(e) => {
                *self.breaker.lock().await = Some(std::time::Instant::now());
                Err(CpError::Unreachable(e))
            }
        }
    }

    async fn invalidate(&self) {
        *self.channel.lock().await = None;
    }

    /// Run `f` (an RPC future factory over a fresh channel) with the fail-closed
    /// deadline; drop the cached channel on any failure so the next call rebuilds.
    async fn call<T, F, Fut>(&self, f: F) -> Result<T, CpError>
    where
        F: FnOnce(Channel) -> Fut,
        Fut: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        let channel = self.channel().await?;
        let result = match tokio::time::timeout(self.rpc_timeout, f(channel)).await {
            Ok(Ok(resp)) => Ok(resp.into_inner()),
            Ok(Err(status)) => Err(CpError::Rpc(status)),
            Err(_elapsed) => Err(CpError::Timeout(self.rpc_timeout)),
        };
        if result.is_err() {
            self.invalidate().await;
        }
        result
    }

    /// Resolve a presented OpenSSH user certificate → identity (the Vault-user-cert
    /// path). `cert_blob` is the raw OpenSSH wire blob; the CP validates it against
    /// the user-facing CA.
    pub async fn resolve_user_cert(
        &self,
        cert_blob: Vec<u8>,
        source_ip: &str,
    ) -> Result<ResolvedIdentity, CpError> {
        let source_ip = source_ip.to_string();
        let resp = self
            .call(move |ch| {
                let req = ResolveUserCertRequest {
                    certificate_blob: cert_blob,
                    source_ip,
                };
                async move { OuterLegAuthClient::new(ch).resolve_user_cert(req).await }
            })
            .await?;
        Ok(resp.identity.unwrap_or_default())
    }

    /// Resolve a pinned public-key fingerprint (`SHA256:...`) → identity.
    pub async fn resolve_pin(
        &self,
        fingerprint: &str,
        source_ip: &str,
    ) -> Result<ResolvedIdentity, CpError> {
        let fingerprint = fingerprint.to_string();
        let source_ip = source_ip.to_string();
        let resp = self
            .call(move |ch| {
                let req = ResolvePinRequest {
                    public_key_fingerprint: fingerprint,
                    source_ip,
                };
                async move { OuterLegAuthClient::new(ch).resolve_pin(req).await }
            })
            .await?;
        Ok(resp.identity.unwrap_or_default())
    }

    /// Resolve a pre-issued single-use OTP → identity. `otp` is a secret (never
    /// logged); the CP validates it constant-time, single-use, source-bound.
    pub async fn resolve_otp(
        &self,
        otp: &str,
        source_ip: &str,
    ) -> Result<ResolvedIdentity, CpError> {
        let otp = otp.to_string();
        let source_ip = source_ip.to_string();
        let resp = self
            .call(move |ch| {
                let req = ResolveOtpRequest { otp, source_ip };
                async move { OuterLegAuthClient::new(ch).resolve_otp(req).await }
            })
            .await?;
        Ok(resp.identity.unwrap_or_default())
    }

    /// Begin the fallback OIDC device flow bound to `source_ip`.
    pub async fn begin_device_flow(
        &self,
        source_ip: &str,
    ) -> Result<BeginDeviceFlowResponse, CpError> {
        let source_ip = source_ip.to_string();
        self.call(move |ch| {
            let req = BeginDeviceFlowRequest { source_ip };
            async move { OuterLegAuthClient::new(ch).begin_device_flow(req).await }
        })
        .await
    }

    /// Poll the device flow by its secret `device_code`.
    pub async fn poll_device_flow(
        &self,
        device_code: &str,
    ) -> Result<PollDeviceFlowResponse, CpError> {
        let device_code = device_code.to_string();
        self.call(move |ch| {
            let req = PollDeviceFlowRequest { device_code };
            async move { OuterLegAuthClient::new(ch).poll_device_flow(req).await }
        })
        .await
    }

    /// Make the connect-time S5 authorization decision for the resolved identity
    /// against the target node.
    pub async fn authorize(&self, req: AuthorizeRequest) -> Result<AuthorizeResponse, CpError> {
        self.call(move |ch| async move { AuthorizationClient::new(ch).authorize(req).await })
            .await
    }

    /// Mint the inner-leg certificate over the authenticated mTLS channel (Session
    /// Eight, D2/§15): the Gateway sends only the public key + the single-use
    /// session token; the CP returns a cert only. A channel failure maps to
    /// [`SigningError::Unavailable`] (CP-down → fail closed); the cached channel is
    /// dropped on any failure so the next call rebuilds.
    pub async fn sign_session_certificate(
        &self,
        session_token: &str,
        inner: &crate::signing::InnerKeyPair,
        context: Option<crate::pb::SignContext>,
    ) -> Result<crate::signing::SignedInnerCert, crate::signing::SigningError> {
        let channel = self
            .channel()
            .await
            .map_err(|_| crate::signing::SigningError::Unavailable)?;
        let result = crate::signing::sign_session_certificate(
            channel,
            session_token,
            inner,
            context,
            self.rpc_timeout,
        )
        .await;
        if result.is_err() {
            self.invalidate().await;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_error_renders_only_the_status_code() {
        // A hostile CP status message (ANSI + newline) must never reach a log via
        // the error Display — only the gRPC code is rendered.
        let hostile = "evil\n\u{1b}[2Jinjected";
        let err = CpError::Rpc(tonic::Status::permission_denied(hostile));
        let shown = format!("{err}");
        assert!(!shown.contains("evil"), "leaked CP message: {shown}");
        assert!(!shown.contains('\u{1b}'));
        assert!(shown.contains("PermissionDenied"));
        assert_eq!(err.code(), Some(tonic::Code::PermissionDenied));
    }

    #[test]
    fn unreachable_and_timeout_carry_no_cp_text() {
        let t = CpError::Timeout(Duration::from_secs(3));
        assert!(format!("{t}").contains("timed out"));
        assert_eq!(t.code(), None);
    }

    #[test]
    fn cp_down_classifies_transport_and_server_errors() {
        assert!(CpError::CircuitOpen.is_cp_down());
        assert!(CpError::Timeout(Duration::from_secs(1)).is_cp_down());
        assert!(CpError::Rpc(tonic::Status::unavailable("x")).is_cp_down());
        assert!(CpError::Rpc(tonic::Status::internal("x")).is_cp_down());
        assert!(CpError::Rpc(tonic::Status::unauthenticated("x")).is_cp_down());
        // A clean policy-shaped status is NOT CP-down (degrade / deny, not unavailable).
        assert!(!CpError::Rpc(tonic::Status::permission_denied("x")).is_cp_down());
        assert!(!CpError::Rpc(tonic::Status::resource_exhausted("x")).is_cp_down());
    }
}
