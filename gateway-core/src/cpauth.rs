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
use crate::pb::gateway_identity_client::GatewayIdentityClient;
use crate::pb::host_cert_signing_client::HostCertSigningClient;
use crate::pb::outer_leg_auth_client::OuterLegAuthClient;
use crate::pb::presence_client::PresenceClient;
use crate::pb::recording_client::RecordingClient;
use crate::pb::{
    AuthorizeRequest, AuthorizeResponse, BeginDeviceFlowRequest, BeginDeviceFlowResponse,
    BeginRecordingRequest, BeginRecordingResponse, BreakglassResolution, ExtendSessionLeaseRequest,
    ExtendSessionLeaseResponse, FinalizeRecordingRequest, FinalizeRecordingResponse,
    IssueGatewayServerCertificateRequest, IssueGatewayServerCertificateResponse,
    NotifySessionEndRequest, NotifySessionEndResponse, PollDeviceFlowRequest,
    PollDeviceFlowResponse, PresenceHeartbeatRequest, PresenceHeartbeatResponse,
    PresenceReleaseRequest, PresenceReleaseResponse, RequestUploadRequest, RequestUploadResponse,
    ResolveBreakglassCodeRequest, ResolveBreakglassKeyRequest, ResolveOtpRequest,
    ResolvePinRequest, ResolveUserCertRequest, ResolvedIdentity, SessionEndReason,
    SignGatewayHostCertificateRequest, SignGatewayHostCertificateResponse,
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

    /// Build a fresh authenticated mTLS channel (for a long-lived server stream
    /// such as the lock feed, which must not share the unary channel's caching /
    /// circuit-breaker lifecycle).
    pub async fn open_channel(&self) -> Result<Channel, MtlsError> {
        self.connect().await
    }

    /// The pinned internal mTLS CA chain (DER) — the trust root the Gateway already
    /// uses for the CP channel, reused to verify the decision-context signer leaf.
    pub fn current_ca_chain(&self) -> Vec<Vec<u8>> {
        self.rx.borrow().ca_chain_der.clone()
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
    ///
    /// The channel is wrapped so every RPC injects the current span's W3C trace
    /// context into the outbound gRPC metadata (OTEL-CONTRACT §2.1) — inert unless
    /// tracing is active.
    async fn call<T, F, Fut>(&self, f: F) -> Result<T, CpError>
    where
        F: FnOnce(crate::telemetry::TracedChannel) -> Fut,
        Fut: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        let channel = crate::telemetry::trace_channel(self.channel().await?);
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

    /// Resolve a registered break-glass FIDO2 `sk-ecdsa` PUBLIC key (OpenSSH wire
    /// blob) → the break-glass identity + a single-use `breakglass_token` (Design
    /// §7, FR-ACC-6). russh has already verified the FIDO possession signature
    /// before this call; the CP only maps the public key to its registered
    /// break-glass credential (IdP-independent). Non-resolution is generic (§7.1).
    pub async fn resolve_break_glass_key(
        &self,
        sk_public_key_blob: Vec<u8>,
        source_ip: &str,
        node_id: &str,
    ) -> Result<BreakglassResolution, CpError> {
        let source_ip = source_ip.to_string();
        let node_id = node_id.to_string();
        let resp = self
            .call(move |ch| {
                let req = ResolveBreakglassKeyRequest {
                    sk_public_key_blob,
                    source_ip,
                    node_id,
                };
                async move {
                    OuterLegAuthClient::new(ch)
                        .resolve_breakglass_key(req)
                        .await
                }
            })
            .await?;
        Ok(resp.resolution.unwrap_or_default())
    }

    /// Resolve a pre-issued single-use break-glass OFFLINE CODE → the break-glass
    /// identity + a single-use `breakglass_token` (Design §7, FR-ACC-6, the IdP-
    /// independent fallback). `code` is a SECRET (keyboard-interactive, echo off) —
    /// NEVER logged. Non-resolution is generic (§7.1); the code is consumed
    /// single-use at the CP.
    pub async fn resolve_break_glass_code(
        &self,
        code: &str,
        source_ip: &str,
        node_id: &str,
    ) -> Result<BreakglassResolution, CpError> {
        let code = code.to_string();
        let source_ip = source_ip.to_string();
        let node_id = node_id.to_string();
        let resp = self
            .call(move |ch| {
                let req = ResolveBreakglassCodeRequest {
                    code,
                    source_ip,
                    node_id,
                };
                async move {
                    OuterLegAuthClient::new(ch)
                        .resolve_breakglass_code(req)
                        .await
                }
            })
            .await?;
        Ok(resp.resolution.unwrap_or_default())
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

    /// The pinned internal mTLS CA chain (DER), used to verify the decision-context
    /// signer leaf (Session Ten). Delegates to the channel factory so a rotated CA
    /// is picked up.
    pub fn current_ca_chain(&self) -> Vec<Vec<u8>> {
        self.factory.current_ca_chain()
    }

    /// Heartbeat ownership of a node this Gateway holds a live agent control channel
    /// for (Session Fifteen HA write path, §10.2/§10.3, FR-HA-2). The OWNER is the
    /// authenticated mTLS peer — never a field — so this only ever claims/refreshes
    /// ownership for THIS Gateway. A contention/stale-nonce reject surfaces as an RPC
    /// error the caller treats as "not owner" (fail closed, FR-HA-5).
    /// The node is addressed by its stable enrollment NAME (the agent-registry key / the
    /// agent cert's dNSName SAN); the CP resolves the name to the node row keying
    /// `runtime.presence` — the Gateway has no database and knows its owned nodes only by name.
    pub async fn presence_heartbeat(
        &self,
        node_name: &str,
        gateway_addr: &str,
    ) -> Result<PresenceHeartbeatResponse, CpError> {
        let node_name = node_name.to_string();
        let gateway_addr = gateway_addr.to_string();
        self.call(move |ch| {
            let req = PresenceHeartbeatRequest {
                node_name,
                gateway_addr,
            };
            async move { PresenceClient::new(ch).heartbeat(req).await }
        })
        .await
    }

    /// Release ownership of a node on graceful drain or control-channel loss so a
    /// standby claims immediately (Session Fifteen, §10.3). Idempotent server-side: a
    /// no-op unless this Gateway is the recorded owner. Addressed by node NAME.
    pub async fn presence_release(
        &self,
        node_name: &str,
    ) -> Result<PresenceReleaseResponse, CpError> {
        let node_name = node_name.to_string();
        self.call(move |ch| {
            let req = PresenceReleaseRequest { node_name };
            async move { PresenceClient::new(ch).release(req).await }
        })
        .await
    }

    /// Obtain the **serverAuth** leaf for the agent-facing WSS listener (Session
    /// Fourteen, Design §9.2). Authenticated by the Gateway's current mTLS client
    /// certificate; the CP — not the caller — chooses the SANs, so a compromised
    /// Gateway cannot obtain a server certificate for a name it does not own. Only the
    /// CSR is sent: the TLS server key is generated locally and never leaves (D2).
    pub async fn issue_gateway_server_certificate(
        &self,
        pkcs10_csr: Vec<u8>,
    ) -> Result<IssueGatewayServerCertificateResponse, CpError> {
        self.call(move |ch| {
            let req = IssueGatewayServerCertificateRequest {
                pkcs10_csr,
                client: Some(crate::version::component_info()),
            };
            async move {
                GatewayIdentityClient::new(ch)
                    .issue_gateway_server_certificate(req)
                    .await
            }
        })
        .await
    }

    /// Register a session recording (Session Nine, §12/§15): consume the single-use
    /// `recording_token` minted by Authorize ALLOW; receive the WORM object key +
    /// mode, the customer public key to seal the data key to, and a short-lived
    /// single-object upload credential. Fail-closed (a failure → the strict-mode
    /// session refusal); the cached channel is dropped on any error.
    pub async fn begin_recording(
        &self,
        req: BeginRecordingRequest,
    ) -> Result<BeginRecordingResponse, CpError> {
        self.call(move |ch| async move { RecordingClient::new(ch).begin_recording(req).await })
            .await
    }

    /// Obtain the short-lived, single-object WORM upload credential for
    /// `recording_id` at UPLOAD time (Session Nine, §12.2): issued just before the
    /// direct PUT so its TTL need only cover the PUT, never the whole session (no
    /// long-lived upload creds). Fail-closed; the cached channel is dropped on error.
    pub async fn request_upload(
        &self,
        recording_id: &str,
    ) -> Result<RequestUploadResponse, CpError> {
        let recording_id = recording_id.to_string();
        self.call(move |ch| {
            let req = RequestUploadRequest { recording_id };
            async move { RecordingClient::new(ch).request_upload(req).await }
        })
        .await
    }

    /// Commit a recording's tamper-evidence + integrity metadata (hash-chain head,
    /// content digest, byte length, status) and the per-operation SFTP/SCP audit
    /// into the correlated audit stream (Session Nine). Fail-closed.
    pub async fn finalize_recording(
        &self,
        req: FinalizeRecordingRequest,
    ) -> Result<FinalizeRecordingResponse, CpError> {
        self.call(move |ch| async move { RecordingClient::new(ch).finalize_recording(req).await })
            .await
    }

    /// Release this session's concurrency lease promptly at teardown (FR-SESS-3,
    /// Session 25) — the reliable session-end signal, independent of
    /// `FinalizeRecording` so the degraded (unrecorded) paths release too. The
    /// caller is bound by its mTLS identity (the CP acts only for the gateway that
    /// brokered the session); idempotent server-side. Best-effort by contract: the
    /// caller must never block or fail teardown on an error — the CP's lease
    /// expiry/reaper self-heal covers a lost signal.
    pub async fn notify_session_end(
        &self,
        session_id: &str,
        reason: SessionEndReason,
    ) -> Result<NotifySessionEndResponse, CpError> {
        let session_id = session_id.to_string();
        self.call(move |ch| {
            let req = NotifySessionEndRequest {
                session_id,
                reason: reason as i32,
            };
            async move { AuthorizationClient::new(ch).notify_session_end(req).await }
        })
        .await
    }

    /// Re-stamp a live session's concurrency-lease expiry (FR-SESS-3 exact
    /// accounting, Session 25): a RunToTtl session outliving `grant_expiry` must
    /// still occupy its slot. The extension window is SERVER-authoritative (no
    /// duration is sent); the response carries the new expiry the caller schedules
    /// the next extension against. Accounting, never authorization: a failure must
    /// never affect the session itself.
    pub async fn extend_session_lease(
        &self,
        session_id: &str,
    ) -> Result<ExtendSessionLeaseResponse, CpError> {
        let session_id = session_id.to_string();
        self.call(move |ch| {
            let req = ExtendSessionLeaseRequest { session_id };
            async move { AuthorizationClient::new(ch).extend_session_lease(req).await }
        })
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

    /// Obtain the Gateway's OUTER SSH host certificate for the ProxyJump host-cert
    /// MITM path (Session Sixteen, §9.3/§11; FR-ADDR-1). Authenticated purely by
    /// the Gateway's mTLS client certificate (NOT session-bound); the CP signs the
    /// presented host public key with the host CA and returns a cert only — the
    /// host private key never leaves the Gateway (D2). `host_principals` are the
    /// exact client-facing hostname(s) the Gateway will be addressed as.
    pub async fn sign_gateway_host_certificate(
        &self,
        host_public_key: Vec<u8>,
        host_principals: Vec<String>,
    ) -> Result<SignGatewayHostCertificateResponse, CpError> {
        self.call(move |ch| {
            let req = SignGatewayHostCertificateRequest {
                host_public_key,
                host_principals,
            };
            async move {
                HostCertSigningClient::new(ch)
                    .sign_gateway_host_certificate(req)
                    .await
            }
        })
        .await
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
