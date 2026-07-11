//! Shared in-process **mock Control Plane** for the Session Four integration
//! tests. Not compiled as its own test binary (it lives in a subdirectory); each
//! test does `mod support;`.
//!
//! The mock is a *real* peer, not a stub: it stands up an actual internal mTLS CA
//! (rcgen, ECDSA P-256) and SSH session CA (ssh-key), serves the three gRPC
//! services over genuine TLS 1.3 with client-auth-optional (the bootstrap
//! exception), and enforces the Session Four trust model per-RPC:
//!
//! - `EnrollGateway` — consumes a single-use enrollment token, signs the CSR,
//!   issues generation 0.
//! - `RenewGatewayIdentity` — requires the mTLS client cert, resolves the
//!   gateway_identity, refuses a locked identity or a stale generation, issues
//!   `current + 1`.
//! - `SignSessionCertificate` — requires the mTLS client cert + a single-use,
//!   gateway-bound session token; signs the Gateway-presented inner public key
//!   into an OpenSSH cert with the session CA and returns the cert only.
//!
//! This proves the Gateway's client-side flow end-to-end against a real TLS peer
//! and a real cert path, without needing the Java Control Plane in-process.

#![allow(dead_code)] // shared across several test binaries; not all use every item.

use gateway_core::pb::gateway_identity_server::{GatewayIdentity, GatewayIdentityServer};
use gateway_core::pb::handshake_server::{Handshake, HandshakeServer};
use gateway_core::pb::session_signing_server::{SessionSigning, SessionSigningServer};
use gateway_core::pb::{
    ClientHello, ComponentInfo, EnrollGatewayRequest, EnrollGatewayResponse, ProtocolVersion,
    RenewGatewayIdentityRequest, RenewGatewayIdentityResponse, ServerHello,
    SignSessionCertificateRequest, SignSessionCertificateResponse,
};
use gateway_core::{mtls, version};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

/// A self-signed test CA (ECDSA P-256) that can sign CSRs and issue leaf certs.
pub struct TestCa {
    params: rcgen::CertificateParams,
    key_pem: String,
    cert_der: Vec<u8>,
}

impl TestCa {
    /// Generate a fresh CA with the given common name / SAN.
    pub fn generate(cn: &str) -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&key).unwrap();
        Self {
            cert_der: cert.der().to_vec(),
            key_pem: key.serialize_pem(),
            params,
        }
    }

    /// The CA certificate DER (the trust anchor the Gateway pins).
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The CA certificate PEM.
    pub fn cert_pem(&self) -> Vec<u8> {
        mtls::cert_der_to_pem(&self.cert_der)
    }

    fn issuer(&self) -> rcgen::Issuer<'static, rcgen::KeyPair> {
        let key = rcgen::KeyPair::from_pem(&self.key_pem).unwrap();
        rcgen::Issuer::new(self.params.clone(), key)
    }

    /// Sign an externally-generated PKCS#10 CSR (DER), returning the leaf DER.
    pub fn sign_csr(&self, csr_der: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let typed = rustls::pki_types::CertificateSigningRequestDer::from(csr_der.to_vec());
        let csr = rcgen::CertificateSigningRequestParams::from_der(&typed)?;
        let cert = csr.signed_by(&self.issuer())?;
        Ok(cert.der().to_vec())
    }

    /// Issue a leaf certificate (with its own fresh key) valid over `[nb, na]`,
    /// with the given extended key usages.
    pub fn issue_leaf(
        &self,
        san: &str,
        ekus: Vec<rcgen::ExtendedKeyUsagePurpose>,
        nb: time::OffsetDateTime,
        na: time::OffsetDateTime,
    ) -> IssuedLeaf {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        params.not_before = nb;
        params.not_after = na;
        params.extended_key_usages = ekus;
        let cert = params.signed_by(&key, &self.issuer()).unwrap();
        IssuedLeaf {
            cert_der: cert.der().to_vec(),
            key_pem: key.serialize_pem(),
            key_pkcs8_der: key.serialize_der(),
        }
    }
}

/// A leaf certificate + its private key in both PEM and PKCS#8 DER forms.
pub struct IssuedLeaf {
    /// Leaf certificate DER.
    pub cert_der: Vec<u8>,
    /// Private key PEM (for tonic `Identity`).
    pub key_pem: String,
    /// Private key PKCS#8 DER (for a raw rustls `ServerConfig`).
    pub key_pkcs8_der: Vec<u8>,
}

/// Per-gateway registry record.
struct GatewayRecord {
    leaf_der: Vec<u8>,
    generation: u64,
    locked: bool,
    name: String,
}

/// A minted single-use session-signing token, bound to a specific gateway/
/// session/node/principal (Design §15).
struct TokenRecord {
    gateway_id: String,
    session_id: String,
    node_id: String,
    principal: String,
    exp: SystemTime,
    used: bool,
}

/// Mutable + immutable mock CP state shared by the three service handlers.
struct MockState {
    ca: TestCa,
    /// OpenSSH-format session CA private key (PEM).
    session_ca_pem: String,
    /// The session CA public key line (for the node's `TrustedUserCAKeys`).
    session_ca_public_line: String,
    /// Advertised server protocol range for `Handshake.Negotiate`.
    server_range: ((u32, u32), (u32, u32)),
    /// TTL of issued Gateway leaf certificates (drives renew-ahead in tests).
    cert_ttl: Duration,
    enrollment_tokens: Mutex<HashSet<String>>,
    gateways: Mutex<HashMap<String, GatewayRecord>>,
    tokens: Mutex<HashMap<String, TokenRecord>>,
    next_id: Mutex<u64>,
    /// When set, the next renewal returns `current + 2` (a forked-counter
    /// simulation) so the Gateway's generation guard can be exercised.
    force_bad_renew_generation: Mutex<bool>,
    /// When set, `SignSessionCertificate` never responds (a hung CP), to prove
    /// the client's fail-closed RPC timeout.
    hang_sign: Mutex<bool>,
}

impl MockState {
    fn resolve_gateway_id(&self, presented_leaf: &[u8]) -> Result<String, Status> {
        let gws = self.gateways.lock().unwrap();
        gws.iter()
            .find(|(_, rec)| rec.leaf_der == presented_leaf)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| Status::unauthenticated("unknown client certificate"))
    }

    fn sign_inner(
        &self,
        subject_pub_wire: &[u8],
        principal: &str,
        session_id: &str,
    ) -> Result<SignSessionCertificateResponse, Status> {
        let pubkey = ssh_key::PublicKey::from_bytes(subject_pub_wire)
            .map_err(|_| Status::invalid_argument("subject public key is not an SSH public key"))?;
        let ca = ssh_key::PrivateKey::from_openssh(&self.session_ca_pem)
            .map_err(|_| Status::internal("session CA unavailable"))?;

        let now = unix_now();
        let valid_after = now.saturating_sub(60); // backdate for skew (FR-CA-5)
        let valid_before = now + 300; // ~5-minute handshake-scoped TTL
        let key_id = format!("{session_id}+{principal}");

        let mut rng = rand_core::OsRng;
        let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rng,
            pubkey.key_data().clone(),
            valid_after,
            valid_before,
        )
        .map_err(|_| Status::internal("cert builder"))?;
        builder
            .cert_type(ssh_key::certificate::CertType::User)
            .and_then(|b| b.key_id(&key_id))
            .and_then(|b| b.valid_principal(principal))
            .map_err(|_| Status::internal("cert builder fields"))?;
        let cert = builder
            .sign(&ca)
            .map_err(|_| Status::internal("session CA signing failed"))?;

        Ok(SignSessionCertificateResponse {
            certificate_line: cert.to_openssh().map_err(|_| Status::internal("encode"))?,
            certificate_blob: cert.to_bytes().map_err(|_| Status::internal("encode"))?,
            key_id,
            valid_after_epoch_seconds: valid_after as i64,
            valid_before_epoch_seconds: valid_before as i64,
        })
    }
}

/// Local newtype wrapping the shared state so the generated gRPC server traits
/// can be implemented here (orphan rule). Derefs to [`MockState`] so the handler
/// bodies read naturally. Cheap to clone (an `Arc` bump), as tonic requires.
#[derive(Clone)]
struct MockSvc(Arc<MockState>);

impl std::ops::Deref for MockSvc {
    type Target = MockState;
    fn deref(&self) -> &MockState {
        self.0.as_ref()
    }
}

#[tonic::async_trait]
impl Handshake for MockSvc {
    async fn negotiate(
        &self,
        request: Request<ClientHello>,
    ) -> Result<Response<ServerHello>, Status> {
        let client = request.into_inner().client.unwrap_or_default();
        let cmin = client.protocol_min.unwrap_or_default();
        let cmax = client.protocol_max.unwrap_or_default();
        match version::resolve_common_version(
            (cmin.major, cmin.minor),
            (cmax.major, cmax.minor),
            self.server_range.0,
            self.server_range.1,
        ) {
            Some((major, minor)) => Ok(Response::new(ServerHello {
                server: Some(server_info(self.server_range)),
                selected: Some(ProtocolVersion { major, minor }),
            })),
            None => Err(Status::failed_precondition("no common version")),
        }
    }
}

#[tonic::async_trait]
impl GatewayIdentity for MockSvc {
    async fn enroll_gateway(
        &self,
        request: Request<EnrollGatewayRequest>,
    ) -> Result<Response<EnrollGatewayResponse>, Status> {
        let r = request.into_inner();
        // Atomic single-use token consumption.
        {
            let mut toks = self.enrollment_tokens.lock().unwrap();
            if !toks.remove(&r.enrollment_token) {
                return Err(Status::permission_denied("enrollment denied"));
            }
        }
        let leaf_der = self
            .ca
            .sign_csr(&r.pkcs10_csr)
            .map_err(|_| Status::invalid_argument("invalid CSR"))?;

        let gateway_id = {
            let mut id = self.next_id.lock().unwrap();
            *id += 1;
            format!("gw-{id:08}")
        };
        self.gateways.lock().unwrap().insert(
            gateway_id.clone(),
            GatewayRecord {
                leaf_der: leaf_der.clone(),
                generation: 0,
                locked: false,
                name: r.gateway_name,
            },
        );

        let (nb, na) = self.validity_window();
        Ok(Response::new(EnrollGatewayResponse {
            certificate: leaf_der,
            ca_chain: vec![self.ca.cert_der().to_vec()],
            gateway_id,
            generation: 0,
            not_before_epoch_seconds: nb,
            not_after_epoch_seconds: na,
        }))
    }

    async fn renew_gateway_identity(
        &self,
        request: Request<RenewGatewayIdentityRequest>,
    ) -> Result<Response<RenewGatewayIdentityResponse>, Status> {
        // mTLS client cert is REQUIRED for renewal (no bootstrap exception).
        let peer = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let leaf = peer
            .first()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?
            .as_ref()
            .to_vec();
        let gid = self.resolve_gateway_id(&leaf)?;
        let r = request.into_inner();

        let mut gws = self.gateways.lock().unwrap();
        let rec = gws.get_mut(&gid).unwrap();
        if rec.locked {
            return Err(Status::permission_denied("identity locked"));
        }
        if r.current_generation != rec.generation {
            return Err(Status::failed_precondition("stale generation"));
        }

        let new_leaf = self
            .ca
            .sign_csr(&r.pkcs10_csr)
            .map_err(|_| Status::invalid_argument("invalid CSR"))?;

        let bad = {
            let mut b = self.force_bad_renew_generation.lock().unwrap();
            std::mem::replace(&mut *b, false)
        };
        let (nb, na) = self.validity_window();
        if bad {
            // Return an unexpected generation without mutating our record — the
            // Gateway must refuse to adopt (security event) and keep its cert.
            return Ok(Response::new(RenewGatewayIdentityResponse {
                certificate: new_leaf,
                ca_chain: vec![self.ca.cert_der().to_vec()],
                gateway_id: gid,
                generation: rec.generation + 2,
                not_before_epoch_seconds: nb,
                not_after_epoch_seconds: na,
            }));
        }

        rec.generation += 1;
        rec.leaf_der = new_leaf.clone();
        Ok(Response::new(RenewGatewayIdentityResponse {
            certificate: new_leaf,
            ca_chain: vec![self.ca.cert_der().to_vec()],
            gateway_id: gid,
            generation: rec.generation,
            not_before_epoch_seconds: nb,
            not_after_epoch_seconds: na,
        }))
    }
}

#[tonic::async_trait]
impl SessionSigning for MockSvc {
    async fn sign_session_certificate(
        &self,
        request: Request<SignSessionCertificateRequest>,
    ) -> Result<Response<SignSessionCertificateResponse>, Status> {
        // Simulate a hung CP (never respond) to exercise the client's timeout.
        // Read the flag into a local so the (non-Send) guard is not held across
        // the await point.
        let hang = *self.hang_sign.lock().unwrap();
        if hang {
            std::future::pending::<()>().await;
        }
        let peer = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let leaf = peer
            .first()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?
            .as_ref()
            .to_vec();
        let gid = self.resolve_gateway_id(&leaf)?;

        // Locked principal is refused (generic denial — no information leak).
        {
            let gws = self.gateways.lock().unwrap();
            if gws.get(&gid).map(|r| r.locked).unwrap_or(true) {
                return Err(Status::permission_denied("access denied by policy"));
            }
        }

        let r = request.into_inner();
        let (session_id, principal) = {
            let mut toks = self.tokens.lock().unwrap();
            let rec = toks
                .get_mut(&r.session_token)
                .ok_or_else(|| Status::permission_denied("access denied by policy"))?;
            // Single-use, bound-to-this-gateway, unexpired — every failure is the
            // same generic denial (Design §15, §7.1).
            if rec.used || rec.exp <= SystemTime::now() || rec.gateway_id != gid {
                return Err(Status::permission_denied("access denied by policy"));
            }
            // Advisory context must not disagree with the (authoritative) token.
            if let Some(ctx) = &r.context {
                if (!ctx.session_id.is_empty() && ctx.session_id != rec.session_id)
                    || (!ctx.node_id.is_empty() && ctx.node_id != rec.node_id)
                    || (!ctx.requested_principal.is_empty()
                        && ctx.requested_principal != rec.principal)
                {
                    return Err(Status::permission_denied("access denied by policy"));
                }
            }
            rec.used = true; // atomic mark-used
            (rec.session_id.clone(), rec.principal.clone())
        };

        let resp = self.sign_inner(&r.subject_public_key, &principal, &session_id)?;
        Ok(Response::new(resp))
    }
}

impl MockState {
    fn validity_window(&self) -> (i64, i64) {
        let now = unix_now();
        let nb = now.saturating_sub(5); // small backdate for local skew
        let na = now + self.cert_ttl.as_secs();
        (nb as i64, na as i64)
    }
}

/// A running mock Control Plane. Aborts its server task on drop.
pub struct MockCp {
    /// The CP mTLS endpoint (`https://127.0.0.1:port`).
    pub endpoint: String,
    /// The server name / SAN the CP server certificate carries.
    pub server_name: String,
    state: Arc<MockState>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for MockCp {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// Builder for a [`MockCp`] with adjustable server range + cert TTL.
pub struct MockCpBuilder {
    server_range: ((u32, u32), (u32, u32)),
    cert_ttl: Duration,
    server_san: String,
}

impl Default for MockCpBuilder {
    fn default() -> Self {
        Self {
            server_range: ((1, 0), (1, 1)),
            cert_ttl: Duration::from_secs(3600),
            server_san: "cp.internal".to_string(),
        }
    }
}

impl MockCpBuilder {
    /// Override the advertised server protocol range.
    pub fn server_range(mut self, min: (u32, u32), max: (u32, u32)) -> Self {
        self.server_range = (min, max);
        self
    }

    /// Override the issued Gateway leaf-certificate TTL (drives renew-ahead).
    pub fn cert_ttl(mut self, ttl: Duration) -> Self {
        self.cert_ttl = ttl;
        self
    }

    /// Start the mock CP on an ephemeral loopback port over real TLS 1.3.
    pub async fn start(self) -> MockCp {
        gateway_core::tls::install_ring_provider();

        let ca = TestCa::generate("SessionLayer Internal mTLS CA");
        // Long-lived server cert with a serverAuth EKU and the CP SAN.
        let server_leaf = ca.issue_leaf(
            &self.server_san,
            vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth],
            rcgen::date_time_ymd(2020, 1, 1),
            rcgen::date_time_ymd(2100, 1, 1),
        );
        let server_cert_pem = mtls::cert_der_to_pem(&server_leaf.cert_der);
        let server_key_pem = server_leaf.key_pem;

        // Session CA (SSH) for signing inner-leg certs.
        let mut rng = rand_core::OsRng;
        let session_ca = ssh_key::PrivateKey::random(
            &mut rng,
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        let session_ca_public_line = session_ca.public_key().to_openssh().unwrap();
        let session_ca_pem = session_ca
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();

        let ca_pem = ca.cert_pem();
        let state = Arc::new(MockState {
            ca,
            session_ca_pem,
            session_ca_public_line: session_ca_public_line.clone(),
            server_range: self.server_range,
            cert_ttl: self.cert_ttl,
            enrollment_tokens: Mutex::new(HashSet::new()),
            gateways: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
            next_id: Mutex::new(0),
            force_bad_renew_generation: Mutex::new(false),
            hang_sign: Mutex::new(false),
        });

        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                &server_cert_pem,
                server_key_pem.as_bytes(),
            ))
            .client_ca_root(Certificate::from_pem(&ca_pem))
            // Optional: EnrollGateway + Negotiate have no client cert; the
            // authenticated RPCs enforce the cert per-RPC via peer_certs.
            .client_auth_optional(true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        let svc_state = state.clone();
        let server = tokio::spawn(async move {
            let _ = Server::builder()
                .tls_config(tls)
                .expect("server tls config")
                .add_service(HandshakeServer::new(MockSvc(svc_state.clone())))
                .add_service(GatewayIdentityServer::new(MockSvc(svc_state.clone())))
                .add_service(SessionSigningServer::new(MockSvc(svc_state.clone())))
                .serve_with_incoming(incoming)
                .await;
        });

        MockCp {
            endpoint: format!("https://{addr}"),
            server_name: self.server_san,
            state,
            server,
        }
    }
}

impl MockCp {
    /// Start a mock CP with defaults (range 1.0-1.1, 1h cert TTL, SAN cp.internal).
    pub async fn start() -> MockCp {
        MockCpBuilder::default().start().await
    }

    /// A builder for non-default mock CPs.
    pub fn builder() -> MockCpBuilder {
        MockCpBuilder::default()
    }

    /// The bootstrap trust anchor(s) (the internal CA DER) the Gateway pins.
    pub fn bootstrap_anchors(&self) -> Vec<Vec<u8>> {
        vec![self.state.ca.cert_der().to_vec()]
    }

    /// The internal CA certificate PEM (e.g. to write to a bootstrap CA file).
    pub fn ca_pem(&self) -> Vec<u8> {
        self.state.ca.cert_pem()
    }

    /// The session CA public key line, for the node's `TrustedUserCAKeys`.
    pub fn session_ca_public_line(&self) -> &str {
        &self.state.session_ca_public_line
    }

    /// Channel params targeting this mock CP with the given timeouts.
    pub fn channel_params(&self, connect: Duration, rpc: Duration) -> mtls::ChannelParams {
        mtls::ChannelParams {
            endpoint: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            connect_timeout: connect,
            rpc_timeout: rpc,
        }
    }

    /// Mint a single-use enrollment token.
    pub fn mint_enrollment_token(&self) -> String {
        let tok = random_token("enroll");
        self.state
            .enrollment_tokens
            .lock()
            .unwrap()
            .insert(tok.clone());
        tok
    }

    /// Mint a single-use session-signing token bound to `{gateway, session,
    /// node, principal, exp}` (Design §15).
    pub fn mint_session_token(
        &self,
        gateway_id: &str,
        session_id: &str,
        node_id: &str,
        principal: &str,
        ttl: Duration,
    ) -> String {
        let tok = random_token("sess");
        self.state.tokens.lock().unwrap().insert(
            tok.clone(),
            TokenRecord {
                gateway_id: gateway_id.to_string(),
                session_id: session_id.to_string(),
                node_id: node_id.to_string(),
                principal: principal.to_string(),
                exp: SystemTime::now() + ttl,
                used: false,
            },
        );
        tok
    }

    /// Mint an *already-expired* session token (for the expiry pen-test).
    pub fn mint_expired_session_token(
        &self,
        gateway_id: &str,
        session_id: &str,
        node_id: &str,
        principal: &str,
    ) -> String {
        let tok = random_token("sess-exp");
        self.state.tokens.lock().unwrap().insert(
            tok.clone(),
            TokenRecord {
                gateway_id: gateway_id.to_string(),
                session_id: session_id.to_string(),
                node_id: node_id.to_string(),
                principal: principal.to_string(),
                exp: SystemTime::now() - Duration::from_secs(1),
                used: false,
            },
        );
        tok
    }

    /// Lock a gateway_identity (an incident-response lock; §8.3).
    pub fn lock_gateway(&self, gateway_id: &str) {
        if let Some(rec) = self.state.gateways.lock().unwrap().get_mut(gateway_id) {
            rec.locked = true;
        }
    }

    /// Make the next renewal return an unexpected (forked) generation, so the
    /// Gateway's monotonic guard is exercised.
    pub fn force_next_renew_bad_generation(&self) {
        *self.state.force_bad_renew_generation.lock().unwrap() = true;
    }

    /// Make `SignSessionCertificate` hang forever, to exercise the client's
    /// fail-closed RPC timeout.
    pub fn set_sign_hangs(&self) {
        *self.state.hang_sign.lock().unwrap() = true;
    }

    /// The CP-recorded generation for a gateway (test assertions).
    pub fn recorded_generation(&self, gateway_id: &str) -> Option<u64> {
        self.state
            .gateways
            .lock()
            .unwrap()
            .get(gateway_id)
            .map(|r| r.generation)
    }

    /// Issue a server-auth leaf from this CP's internal CA, for building a raw
    /// TLS server the Gateway will still trust (Part A rejection matrix).
    pub fn issue_server_material(
        &self,
        san: &str,
        nb: time::OffsetDateTime,
        na: time::OffsetDateTime,
    ) -> IssuedLeaf {
        self.state.ca.issue_leaf(
            san,
            vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth],
            nb,
            na,
        )
    }
}

/// Spawn a bare TLS listener that presents `server_config` and completes (or
/// fails) exactly one TLS handshake, then hangs — enough for a client `connect()`
/// to observe accept/reject at the TLS layer. Used for the expired-cert and
/// TLS-1.2-only rejection cases (a plaintext peer is tested with a plain TCP
/// listener instead). Returns the `https://` endpoint. Aborts on drop of the
/// returned guard.
pub async fn spawn_raw_tls_server(
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> (String, AbortOnDrop) {
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // Drive the handshake; on success just idle so the client's
                    // own bound governs, on failure the client sees the alert.
                    if let Ok(tls) = acceptor.accept(stream).await {
                        let _ = tls;
                        std::future::pending::<()>().await;
                    }
                });
            }
        }
    });
    (format!("https://{addr}"), AbortOnDrop(handle))
}

/// Spawn a plaintext TCP listener that accepts and idles — a non-TLS peer, to
/// prove the client refuses to fall back to plaintext.
pub async fn spawn_plaintext_server() -> (String, AbortOnDrop) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = stream;
                    std::future::pending::<()>().await;
                });
            }
        }
    });
    (format!("https://{addr}"), AbortOnDrop(handle))
}

/// Spawn a TCP listener that accepts a connection but never speaks — a hung peer.
pub async fn spawn_silent_server() -> (String, AbortOnDrop) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _conn = listener.accept().await;
        std::future::pending::<()>().await;
    });
    (format!("https://{addr}"), AbortOnDrop(handle))
}

/// Build a rustls `ServerConfig` from DER material, optionally pinned to a
/// specific protocol version (e.g. TLS 1.2 only). No client auth.
pub fn raw_server_config(
    cert_der: Vec<u8>,
    key_pkcs8_der: Vec<u8>,
    versions: Option<&[&'static rustls::SupportedProtocolVersion]>,
) -> std::sync::Arc<rustls::ServerConfig> {
    gateway_core::tls::install_ring_provider();
    let certs = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_pkcs8_der,
    ));
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider);
    let mut config = match versions {
        Some(v) => builder
            .with_protocol_versions(v)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
        None => builder
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    std::sync::Arc::new(config)
}

/// A spawned task that is aborted when this guard drops (keeps helper servers
/// alive for the duration of a test).
pub struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn server_info(range: ((u32, u32), (u32, u32))) -> ComponentInfo {
    ComponentInfo {
        name: "SessionLayer Control Plane".to_string(),
        semver: "0.1.0".to_string(),
        protocol_min: Some(ProtocolVersion {
            major: range.0 .0,
            minor: range.0 .1,
        }),
        protocol_max: Some(ProtocolVersion {
            major: range.1 .0,
            minor: range.1 .1,
        }),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn random_token(prefix: &str) -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 24];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}")
}
