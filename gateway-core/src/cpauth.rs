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

#[derive(Debug, thiserror::Error)]
pub enum CpError {
    #[error("Control Plane unreachable")]
    Unreachable(#[source] MtlsError),

    #[error("Control Plane unreachable (circuit open)")]
    CircuitOpen,

    #[error("Control Plane RPC timed out after {0:?}")]
    Timeout(Duration),

    /// Only the gRPC status **code** is rendered - never the CP-supplied message (untrusted wire text).
    #[error("Control Plane RPC failed (gRPC status {:?})", .0.code())]
    Rpc(tonic::Status),
}

impl CpError {
    pub fn code(&self) -> Option<tonic::Code> {
        match self {
            CpError::Rpc(s) => Some(s.code()),
            _ => None,
        }
    }

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

#[derive(Clone)]
pub struct CredentialSnapshot {
    pub identity: ClientIdentity,
    pub ca_chain_der: Vec<Vec<u8>>,
}

pub struct CpChannelFactory {
    params: ChannelParams,
    rx: watch::Receiver<CredentialSnapshot>,
    // Kept alive so the watch stays open for [`Self::fixed`] callers (tests/dev).
    _tx: Option<watch::Sender<CredentialSnapshot>>,
}

impl CpChannelFactory {
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

    pub async fn open_channel(&self) -> Result<Channel, MtlsError> {
        self.connect().await
    }

    pub fn current_ca_chain(&self) -> Vec<Vec<u8>> {
        self.rx.borrow().ca_chain_der.clone()
    }
}

const BREAKER_COOLDOWN: Duration = Duration::from_secs(1);

pub struct CpAuthClient {
    factory: Arc<CpChannelFactory>,
    rpc_timeout: Duration,
    channel: Mutex<Option<Channel>>,
    breaker: Mutex<Option<std::time::Instant>>,
}

impl CpAuthClient {
    pub fn new(factory: Arc<CpChannelFactory>, rpc_timeout: Duration) -> Self {
        Self {
            factory,
            rpc_timeout,
            channel: Mutex::new(None),
            breaker: Mutex::new(None),
        }
    }

    /// Connect without holding the channel lock to avoid serializing on a partitioned CP.
    async fn channel(&self) -> Result<Channel, CpError> {
        if let Some(ch) = self.channel.lock().await.as_ref() {
            return Ok(ch.clone());
        }
        if let Some(at) = *self.breaker.lock().await {
            if at.elapsed() < BREAKER_COOLDOWN {
                return Err(CpError::CircuitOpen);
            }
        }
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

    pub async fn authorize(&self, req: AuthorizeRequest) -> Result<AuthorizeResponse, CpError> {
        self.call(move |ch| async move { AuthorizationClient::new(ch).authorize(req).await })
            .await
    }

    pub fn current_ca_chain(&self) -> Vec<Vec<u8>> {
        self.factory.current_ca_chain()
    }

    /// Ownership is authenticated mTLS peer (never a field); this Gateway only.
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

    pub async fn begin_recording(
        &self,
        req: BeginRecordingRequest,
    ) -> Result<BeginRecordingResponse, CpError> {
        self.call(move |ch| async move { RecordingClient::new(ch).begin_recording(req).await })
            .await
    }

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

    pub async fn finalize_recording(
        &self,
        req: FinalizeRecordingRequest,
    ) -> Result<FinalizeRecordingResponse, CpError> {
        self.call(move |ch| async move { RecordingClient::new(ch).finalize_recording(req).await })
            .await
    }

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

    /// Send pubkey + token only. CP-down → fail-closed.
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
        assert!(!CpError::Rpc(tonic::Status::permission_denied("x")).is_cp_down());
        assert!(!CpError::Rpc(tonic::Status::resource_exhausted("x")).is_cp_down());
    }
}
