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

pub mod docker;
pub mod sigv4;

use gateway_core::config::SshServerConfig;
use gateway_core::cpauth::{CpAuthClient, CpChannelFactory};
use gateway_core::identity;
use gateway_core::pb::authorization_server::{Authorization, AuthorizationServer};
use gateway_core::pb::gateway_identity_server::{GatewayIdentity, GatewayIdentityServer};
use gateway_core::pb::handshake_server::{Handshake, HandshakeServer};
use gateway_core::pb::lock_feed_server::{LockFeed, LockFeedServer};
use gateway_core::pb::outer_leg_auth_server::{OuterLegAuth, OuterLegAuthServer};
use gateway_core::pb::presence_server::{Presence, PresenceServer};
use gateway_core::pb::recording_server::{Recording, RecordingServer};
use gateway_core::pb::session_signing_server::{SessionSigning, SessionSigningServer};
use gateway_core::pb::{
    lock_event, AccessModel, AuthorizeRequest, AuthorizeResponse, BeginDeviceFlowRequest,
    BeginDeviceFlowResponse, BeginRecordingRequest, BeginRecordingResponse, BreakglassResolution,
    Capability, ClientHello, ComponentInfo, ConnectorKind, CustomerKey, Decision, DecisionContext,
    DeviceFlowStatus, EnrollGatewayRequest, EnrollGatewayResponse, FinalizeRecordingRequest,
    FinalizeRecordingResponse, Heartbeat, HostVerification, IssueGatewayServerCertificateRequest,
    IssueGatewayServerCertificateResponse, KeySealAlgorithm, Lock, LockEvent, LockRemoval,
    LockSnapshot, NodeConnection, PollDeviceFlowRequest, PollDeviceFlowResponse,
    PresenceHeartbeatRequest, PresenceHeartbeatResponse, PresenceReleaseRequest,
    PresenceReleaseResponse, ProtocolVersion, RenewGatewayIdentityRequest,
    RenewGatewayIdentityResponse, RequestUploadRequest, RequestUploadResponse,
    ResolveBreakglassCodeRequest, ResolveBreakglassCodeResponse, ResolveBreakglassKeyRequest,
    ResolveBreakglassKeyResponse, ResolveOtpRequest, ResolveOtpResponse, ResolvePinRequest,
    ResolvePinResponse, ResolveUserCertRequest, ResolveUserCertResponse, ResolvedIdentity,
    ServerHello, SignSessionCertificateRequest, SignSessionCertificateResponse, StreamLocksRequest,
    UploadCredential, WormMode,
};
use gateway_core::ssh::bridge::{NullRecorderFactory, RecorderFactory};
use gateway_core::ssh::connector::{AgentlessDial, NodeConnector};
use gateway_core::ssh::handler::HandlerDeps;
use gateway_core::ssh::lockfeed::LockFeedClientTask;
use gateway_core::ssh::locks::{target_matches, LiveSessionRegistry, LockBindings, LockSet};
use gateway_core::ssh::target::IdentityResolver;
use gateway_core::{decisionctx, mtls, version};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use sigv4::S3Target;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
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

    /// Parse a CSR the way the REAL CP does. Its shared PKCS#10 parser (Enroll / Renew /
    /// IssueGatewayServerCertificate) refuses a CSR with a **blank subject CN** — which a
    /// CSR whose names are all chosen by the CA would naturally have — so the mock refuses
    /// one too. A mock that were laxer than the CP would let the Gateway ship a CSR that
    /// the real CP rejects, with every test still green.
    fn parse_csr(csr_der: &[u8]) -> Result<rcgen::CertificateSigningRequestParams, rcgen::Error> {
        let typed = rustls::pki_types::CertificateSigningRequestDer::from(csr_der.to_vec());
        let csr = rcgen::CertificateSigningRequestParams::from_der(&typed)?;
        let has_cn = csr
            .params
            .distinguished_name
            .get(&rcgen::DnType::CommonName)
            .map(|cn| match cn {
                rcgen::DnValue::Utf8String(s) => !s.trim().is_empty(),
                rcgen::DnValue::PrintableString(s) => !s.as_str().trim().is_empty(),
                _ => true,
            })
            .unwrap_or(false);
        if !has_cn {
            return Err(rcgen::Error::CouldNotParseCertificationRequest);
        }
        Ok(csr)
    }

    /// Sign an externally-generated PKCS#10 CSR (DER), returning the leaf DER.
    pub fn sign_csr(&self, csr_der: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let csr = Self::parse_csr(csr_der)?;
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

    /// Sign an externally-generated CSR as a **serverAuth** leaf whose SANs THIS CA
    /// chooses (Session Fourteen `IssueGatewayServerCertificate`): dNSName = the
    /// gateway's enrolled name, plus the `sessionlayer://gateway/<id>` URI SAN. The
    /// CSR contributes only its public key — never its requested names.
    pub fn sign_csr_as_server(
        &self,
        csr_der: &[u8],
        gateway_name: &str,
        gateway_id: &str,
        ttl: Duration,
    ) -> Result<Vec<u8>, rcgen::Error> {
        let mut csr = Self::parse_csr(csr_der)?;
        // The CP discards every name the CSR asks for and stamps its own.
        csr.params.distinguished_name = rcgen::DistinguishedName::new();
        csr.params
            .distinguished_name
            .push(rcgen::DnType::CommonName, gateway_name);
        csr.params.subject_alt_names = vec![
            rcgen::SanType::DnsName(rcgen::string::Ia5String::try_from(gateway_name).unwrap()),
            rcgen::SanType::URI(
                rcgen::string::Ia5String::try_from(format!("sessionlayer://gateway/{gateway_id}"))
                    .unwrap(),
            ),
        ];
        csr.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        csr.params.not_before = offset_now() - time::Duration::minutes(5);
        csr.params.not_after = offset_now() + time::Duration::seconds(ttl.as_secs() as i64);
        Ok(csr.signed_by(&self.issuer())?.der().to_vec())
    }

    /// Sign an enrollment/renewal CSR as a **gateway identity** (clientAuth) leaf whose SANs
    /// THIS CA chooses, mirroring the real CP `EnrollGateway`/`RenewGatewayIdentity`: dNSName =
    /// the gateway's enrolled name (the HA routing key) PLUS the `sessionlayer://gateway/<id>`
    /// URI SAN. The CSR contributes only its public key. Stamping the URI SAN keeps the mock
    /// faithful to production so the peer-relay positive gateway-SAN check (F10a) is exercised.
    pub fn sign_csr_as_gateway_identity(
        &self,
        csr_der: &[u8],
        gateway_name: &str,
        gateway_id: &str,
    ) -> Result<Vec<u8>, rcgen::Error> {
        let mut csr = Self::parse_csr(csr_der)?;
        csr.params.distinguished_name = rcgen::DistinguishedName::new();
        csr.params
            .distinguished_name
            .push(rcgen::DnType::CommonName, gateway_name);
        csr.params.subject_alt_names = vec![
            rcgen::SanType::DnsName(rcgen::string::Ia5String::try_from(gateway_name).unwrap()),
            rcgen::SanType::URI(
                rcgen::string::Ia5String::try_from(format!("sessionlayer://gateway/{gateway_id}"))
                    .unwrap(),
            ),
        ];
        csr.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        Ok(csr.signed_by(&self.issuer())?.der().to_vec())
    }

    /// Issue an **agent identity** leaf: a clientAuth leaf carrying the two SANs the
    /// Gateway resolves an agent peer from (contract §1) — the URI SAN
    /// `sessionlayer://agent/<agent_id>` and the dNSName SAN = the node's name.
    pub fn issue_agent_leaf(&self, agent_id: &str, node_name: &str) -> IssuedLeaf {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.not_before = offset_now() - time::Duration::minutes(5);
        params.not_after = offset_now() + time::Duration::hours(1);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, agent_id);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params.subject_alt_names = vec![
            rcgen::SanType::URI(
                rcgen::string::Ia5String::try_from(format!("sessionlayer://agent/{agent_id}"))
                    .unwrap(),
            ),
            rcgen::SanType::DnsName(rcgen::string::Ia5String::try_from(node_name).unwrap()),
        ];
        let cert = params.signed_by(&key, &self.issuer()).unwrap();
        IssuedLeaf {
            cert_der: cert.der().to_vec(),
            key_pem: key.serialize_pem(),
            key_pkcs8_der: key.serialize_der(),
        }
    }

    /// Issue a CONTEXT_SIGNER leaf (URI SAN marker + codeSigning EKU) that the S10
    /// decision-context verifier accepts. Mirrors the CP `DecisionContextSigner`.
    pub fn issue_context_signer(
        &self,
        nb: time::OffsetDateTime,
        na: time::OffsetDateTime,
    ) -> IssuedLeaf {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.not_before = nb;
        params.not_after = na;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "decision-context-signer");
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
        params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(decisionctx::SIGNER_URI).unwrap(),
        )];
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

/// A credential's resolved {identity, principals, groups} for the outer-leg auth
/// RPCs, with an optional source-IP binding (deny-only reducer).
#[derive(Clone)]
struct ResolvedRecord {
    identity: String,
    principals: Vec<String>,
    groups: Vec<String>,
    source_ip: Option<String>,
}

/// The pre-configured outcome a device flow will produce (Session Seven tests).
/// Matching the real CP, an APPROVED device flow carries only the identity —
/// principals/groups are EMPTY because RBAC decides the device-flow logins.
#[derive(Clone)]
struct DeviceFlowTemplate {
    user_code: String,
    verification_uri: String,
    identity: String,
    /// Polls that report PENDING before the flow flips to APPROVED.
    approve_after_polls: u32,
    /// When set, the flow reports DENIED instead of ever approving.
    deny: bool,
}

/// A live device flow minted by `BeginDeviceFlow`, tracked by device_code.
struct DeviceFlowRecord {
    template: DeviceFlowTemplate,
    polls: u32,
    expires_at: SystemTime,
}

/// A data-plane allow tuple for the mock `Authorize` (a stand-in for a dp_rule).
struct AllowRule {
    identity: String,
    node_id: String,
    principal: String,
}

/// A minted single-use break-glass token (Session Thirteen): the resolution binds
/// {gateway, identity, node, source_ip}; Authorize consumes it once.
struct BreakglassTokenRecord {
    gateway_id: String,
    identity: String,
    principals: Vec<String>,
    node_id: String,
    source_ip: String,
    used: bool,
}

/// A recorded break-glass activation (Session Thirteen): the CP creates it ON USE
/// at Authorize (before the allow/deny is decided) and fires the high-priority
/// alert. Tests assert it happened.
#[derive(Clone, Debug)]
struct BreakglassActivation {
    identity: String,
    node_id: String,
}

/// One HA presence row (Session Fifteen): node → owner. The owner is the gateway NAME
/// (`gateway_identity.name`, the HA routing key), never the caller's id. `nonce` is the
/// monotonic fencing token; `last_seen` drives staleness (a stale owner is taken over).
#[derive(Clone, Debug)]
struct PresenceRow {
    owner: String,
    gateway_addr: String,
    nonce: u64,
    nonce_id: String,
    last_seen: SystemTime,
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

    // ---- Session Seven: outer-leg auth (OuterLegAuth) + Authorize ----------
    /// OpenSSH **user-facing CA** private key (PEM) — signs user certs the
    /// `ResolveUserCert` path validates (Design §3.1).
    user_ca_pem: String,
    /// Registered pins: SHA-256 fingerprint → resolved record.
    pins: Mutex<HashMap<String, ResolvedRecord>>,
    /// Registered OTPs: code → resolved record (single-use; consumed on validate).
    otps: Mutex<HashMap<String, ResolvedRecord>>,
    /// The device-flow outcome the next `BeginDeviceFlow` will mint.
    device_flow_template: Mutex<Option<DeviceFlowTemplate>>,
    /// Live device flows keyed by device_code.
    device_flows: Mutex<HashMap<String, DeviceFlowRecord>>,
    /// Data-plane allow tuples for `Authorize`.
    allow_rules: Mutex<Vec<AllowRule>>,
    /// Nodes the CP inventory "knows" (an unknown node → §7.1 DENY).
    known_nodes: Mutex<HashSet<String>>,
    /// OpenSSH **host CA** private key (PEM) — signs node host certs (§9.3, S8).
    host_ca_pem: String,
    /// The host CA public key, OpenSSH wire-encoded (for `host_ca_keys`).
    host_ca_public_wire: Vec<u8>,
    /// Per-node connection material returned in the `Authorize` ALLOW response
    /// (Part E): dial address + host-verification anchors. Absent → the Gateway
    /// aborts (no connection / never TOFU).
    node_connections: Mutex<HashMap<String, NodeConnection>>,
    /// Per-node granted capability override (default shell+exec); drives the
    /// SFTP-granted-vs-withheld tests (FR-SESS-1/2).
    node_capabilities: Mutex<HashMap<String, Vec<i32>>>,
    /// The `decision_ttl_seconds` baked into every signed decision context. Lets a
    /// test force per-channel re-validate (0) to exercise the break-glass no-replay
    /// re-auth posture on the healthy feed.
    decision_ttl_secs: Mutex<i64>,
    /// F2 attack simulation: on a STANDING allow, SIGN access_model=BREAKGLASS but ship
    /// a DOWNGRADED unsigned `context` (access_model=STANDING). A GW that (wrongly) read
    /// the unsigned copy would drop break-glass enforcement; a correct GW reads the
    /// signed context.
    force_signed_breakglass: Mutex<bool>,
    /// G1: when `Some`, `grant_expiry_epoch_seconds` in the signed context is set to this
    /// exact value (0 exercises the break-glass "must be time-boxed" fail-closed path).
    grant_expiry_override: Mutex<Option<i64>>,
    /// G6: when set, `StreamLocks` returns UNAVAILABLE so the Gateway's lock feed never
    /// becomes healthy (exercises the break-glass unhealthy-feed fail-closed refusal).
    lock_feed_down: Mutex<bool>,
    /// When set, `Authorize` returns UNAVAILABLE (the CP-down fail-closed row).
    authorize_unavailable: Mutex<bool>,
    /// When set, every OuterLegAuth resolve RPC returns UNAVAILABLE (CP-down
    /// during authentication).
    resolve_unavailable: Mutex<bool>,

    // ---- Session Thirteen: break-glass (FIDO2 key / offline code) ------------
    /// Registered break-glass FIDO2 keys: OpenSSH wire blob → resolved record.
    break_glass_keys: Mutex<HashMap<Vec<u8>, ResolvedRecord>>,
    /// Registered single-use break-glass offline codes: code → resolved record
    /// (consumed on validate, single-use).
    offline_codes: Mutex<HashMap<String, ResolvedRecord>>,
    /// Minted break-glass tokens, consumed atomically (single-use) at Authorize.
    breakglass_tokens: Mutex<HashMap<String, BreakglassTokenRecord>>,
    /// Break-glass activations recorded ON USE at Authorize (the alert fires here).
    breakglass_activations: Mutex<Vec<BreakglassActivation>>,

    // ---- Session Nine: recorder (Recording service + WORM presign) ----------
    /// Recording tokens minted on Authorize ALLOW (single-use, gateway/session-
    /// bound), consumed by BeginRecording.
    recording_tokens: Mutex<HashMap<String, TokenRecord>>,
    /// The operator-configured customer PUBLIC key seal params. `None` models an
    /// operator with NO customer key (BeginRecording returns none → strict refuse).
    customer_key: Mutex<Option<CustomerKey>>,
    /// The WORM object store the CP presigns PUTs to (the MinIO container).
    s3: Mutex<Option<S3Target>>,
    /// Registered recordings: recording_id → (gateway_id, object_key).
    recordings: Mutex<HashMap<String, (String, String)>>,
    /// FinalizeRecording payloads, keyed by recording_id (test assertions).
    finalized: Mutex<HashMap<String, FinalizeRecordingRequest>>,
    /// TTL (seconds) baked into each RequestUpload presigned PUT. Short values let
    /// a test prove the credential is issued at UPLOAD time (a long session would
    /// have expired a begin-time credential).
    upload_ttl_secs: Mutex<u64>,
    /// recording_ids RequestUpload was called for (test assertions: the credential
    /// is fetched at session end, not at BeginRecording).
    request_uploads: Mutex<Vec<String>>,

    // ---- Session Ten: decision-context signing + the lock push feed ----------
    /// The CONTEXT_SIGNER leaf (DER) chained to `ca` — returned as
    /// `signer_certificate` so the Gateway verifier accepts the signed context.
    context_signer_der: Vec<u8>,
    /// The ECDSA-P256 signing key for the decision context (matches the leaf).
    context_signer_key: SigningKey,
    /// Per-node inventory labels ("key=value"), signed into the decision context
    /// so node-label locks can be exercised.
    node_labels: Mutex<HashMap<String, Vec<String>>>,
    /// The current lock set (pushed to every `StreamLocks` subscriber as the
    /// snapshot). Tests mutate it via [`MockCp::add_lock`]/[`MockCp::remove_lock`].
    locks: Mutex<Vec<Lock>>,
    /// Session Fourteen: the TTL of an issued agent-facing serverAuth leaf, and the
    /// key-ids of every inner-leg cert signed (the FR-AUD-4 correlation value).
    server_cert_ttl: Mutex<Duration>,
    signed_key_ids: Mutex<Vec<String>>,
    /// Broadcast of incremental lock add/remove events to live `StreamLocks`
    /// subscribers (the fan-out hub).
    lock_events: tokio::sync::broadcast::Sender<LockEvent>,
    /// The lock-feed epoch (monotonic per mock CP).
    feed_epoch: AtomicU64,

    // ---- Session Fifteen: HA presence (node -> owner, monotonic nonce) --------
    /// The presence table, keyed by the node NAME the Gateway heartbeats (the agent-registry
    /// key / the agent cert's dNSName SAN); the real CP resolves the name to the node uuid and
    /// keys `runtime.presence` by that. Authorize keys by the same name (pass-through resolver
    /// this session). Mirrors `runtime.presence`: claim / refresh / standby with a monotonic
    /// fencing nonce.
    presence: Mutex<HashMap<String, PresenceRow>>,
    /// How long an owner may go un-heartbeated before it is considered stale and taken over
    /// (and before its owner fields stop riding on Authorize). Short in tests.
    presence_staleness: Duration,

    // ---- Session Sixteen: name→id resolution (Part A, FR-ADDR-1) --------------
    /// Optional node NAME → CP id mapping. `Authorize` resolves `node_name` through
    /// this (server-side authoritative, ignoring the client-asserted `node_id`);
    /// an unmapped name resolves to itself (pass-through, the S7–S15 test shape). A
    /// distinct mapping lets a test prove the Gateway forwards the NAME and the whole
    /// downstream keys on the CP-resolved id, not the raw parsed string.
    node_name_to_id: Mutex<HashMap<String, String>>,
    /// Every `AuthorizeRequest` the mock received, in order — for Part A assertions
    /// (node_name populated, name resolution authoritative).
    authorize_requests: Mutex<Vec<AuthorizeRequest>>,
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

    /// Sign a decision context exactly as the CP does: the ECDSA-P256/SHA-256
    /// signature over `DOMAIN_PREFIX || canonical(context)`, returning
    /// `(signed_context, signature, signer_cert_der, signer_ca_chain)`.
    fn sign_context(&self, context: &DecisionContext) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<Vec<u8>>) {
        let signed = decisionctx::canonical_bytes(context);
        let mut msg = decisionctx::DOMAIN_PREFIX.to_vec();
        msg.extend_from_slice(&signed);
        let sig: p256::ecdsa::Signature = self.context_signer_key.sign(&msg);
        let sig_der = sig.to_der().as_bytes().to_vec();
        (
            signed,
            sig_der,
            self.context_signer_der.clone(),
            vec![self.ca.cert_der().to_vec()],
        )
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
        let gateway_id = {
            let mut id = self.next_id.lock().unwrap();
            *id += 1;
            format!("gw-{id:08}")
        };
        // Stamp the gateway URI SAN + dNSName exactly as the real CP does (F10a faithfulness).
        let leaf_der = self
            .ca
            .sign_csr_as_gateway_identity(&r.pkcs10_csr, &r.gateway_name, &gateway_id)
            .map_err(|_| Status::invalid_argument("invalid CSR"))?;

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

        let gateway_name = rec.name.clone();
        let new_leaf = self
            .ca
            .sign_csr_as_gateway_identity(&r.pkcs10_csr, &gateway_name, &gid)
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

    /// Session Fourteen: issue the **serverAuth** leaf for the Gateway's agent-facing
    /// WSS listener. Requires the caller's current mTLS client certificate; a locked
    /// identity is refused. The CP — not the caller — chooses the SANs, stamping them
    /// from the gateway_identity row it already holds, so a compromised Gateway cannot
    /// obtain a server certificate for a name it does not own.
    async fn issue_gateway_server_certificate(
        &self,
        request: Request<IssueGatewayServerCertificateRequest>,
    ) -> Result<Response<IssueGatewayServerCertificateResponse>, Status> {
        let peer = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let leaf = peer
            .first()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?
            .as_ref()
            .to_vec();
        let gid = self.resolve_gateway_id(&leaf)?;

        let gateway_name = {
            let gws = self.gateways.lock().unwrap();
            let rec = gws
                .get(&gid)
                .ok_or_else(|| Status::unauthenticated("unknown gateway"))?;
            if rec.locked {
                return Err(Status::permission_denied("identity locked"));
            }
            rec.name.clone()
        };

        let r = request.into_inner();
        let ttl = *self.server_cert_ttl.lock().unwrap();
        let certificate = self
            .ca
            .sign_csr_as_server(&r.pkcs10_csr, &gateway_name, &gid, ttl)
            .map_err(|_| Status::invalid_argument("invalid CSR"))?;

        let now = SystemTime::now();
        Ok(Response::new(IssueGatewayServerCertificateResponse {
            certificate,
            ca_chain: vec![self.ca.cert_der().to_vec()],
            gateway_name,
            not_before_epoch_seconds: epoch_of(now),
            not_after_epoch_seconds: epoch_of(now + ttl),
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
        // FR-AUD-4: the key-id the node's own sshd will log on this certificate — the
        // join between the CP's trail and the node-local one.
        self.signed_key_ids
            .lock()
            .unwrap()
            .push(resp.key_id.clone());
        Ok(Response::new(resp))
    }
}

// ---- Session Seven: outer-leg auth helpers ---------------------------------

fn not_resolved() -> ResolvedIdentity {
    ResolvedIdentity {
        resolved: false,
        identity: String::new(),
        principals: Vec::new(),
        groups: Vec::new(),
    }
}

fn resolved(rec: &ResolvedRecord) -> ResolvedIdentity {
    ResolvedIdentity {
        resolved: true,
        identity: rec.identity.clone(),
        principals: rec.principals.clone(),
        groups: rec.groups.clone(),
    }
}

/// Enforce the mTLS tier: every OuterLegAuth/Authorize RPC requires the caller's
/// Gateway client certificate; resolve it to a known gateway_id.
fn require_gateway<T>(request: &Request<T>, state: &MockState) -> Result<String, Status> {
    let peer = request
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
    let leaf = peer
        .first()
        .ok_or_else(|| Status::unauthenticated("client certificate required"))?
        .as_ref()
        .to_vec();
    state.resolve_gateway_id(&leaf)
}

impl MockState {
    /// Resolve a pin/OTP record honouring the optional deny-only source binding.
    fn resolve_map(&self, rec: Option<&ResolvedRecord>, source_ip: &str) -> ResolvedIdentity {
        match rec {
            Some(r) if r.source_ip.as_deref().is_none_or(|s| s == source_ip) => resolved(r),
            _ => not_resolved(),
        }
    }

    /// Validate a presented OpenSSH user certificate against the user-facing CA
    /// (signature + validity window) and resolve identity from its key-id.
    fn resolve_cert(&self, blob: &[u8], _source_ip: &str) -> ResolvedIdentity {
        let cert = match ssh_key::Certificate::from_bytes(blob) {
            Ok(c) => c,
            Err(_) => return not_resolved(),
        };
        let ca = match ssh_key::PrivateKey::from_openssh(&self.user_ca_pem) {
            Ok(k) => k,
            Err(_) => return not_resolved(),
        };
        let ca_fp = ca.public_key().fingerprint(ssh_key::HashAlg::Sha256);
        if cert.validate_at(unix_now(), [&ca_fp]).is_err() {
            return not_resolved();
        }
        ResolvedIdentity {
            resolved: true,
            identity: cert.key_id().to_string(),
            principals: cert.valid_principals().to_vec(),
            groups: Vec::new(),
        }
    }

    /// Sign an OpenSSH user certificate with the user-facing CA (for the
    /// `ResolveUserCert` happy-path test).
    fn sign_user_cert(
        &self,
        pubkey_openssh_line: &str,
        identity: &str,
        principals: &[String],
        valid_secs: u64,
    ) -> String {
        let pubkey = ssh_key::PublicKey::from_openssh(pubkey_openssh_line).unwrap();
        let ca = ssh_key::PrivateKey::from_openssh(&self.user_ca_pem).unwrap();
        let now = unix_now();
        let mut rng = rand_core::OsRng;
        let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rng,
            pubkey.key_data().clone(),
            now.saturating_sub(60),
            now + valid_secs,
        )
        .unwrap();
        builder
            .cert_type(ssh_key::certificate::CertType::User)
            .unwrap();
        builder.key_id(identity).unwrap();
        for p in principals {
            builder.valid_principal(p).unwrap();
        }
        let cert = builder.sign(&ca).unwrap();
        cert.to_openssh().unwrap()
    }
}

/// Simulate a CP-down during authentication: every resolve RPC returns
/// UNAVAILABLE when the knob is set.
fn resolve_down(state: &MockState) -> Result<(), Status> {
    if *state.resolve_unavailable.lock().unwrap() {
        return Err(Status::unavailable("control plane temporarily unavailable"));
    }
    Ok(())
}

#[tonic::async_trait]
impl OuterLegAuth for MockSvc {
    async fn resolve_user_cert(
        &self,
        request: Request<ResolveUserCertRequest>,
    ) -> Result<Response<ResolveUserCertResponse>, Status> {
        require_gateway(&request, self)?;
        resolve_down(self)?;
        let r = request.into_inner();
        let identity = self.resolve_cert(&r.certificate_blob, &r.source_ip);
        Ok(Response::new(ResolveUserCertResponse {
            identity: Some(identity),
        }))
    }

    async fn resolve_pin(
        &self,
        request: Request<ResolvePinRequest>,
    ) -> Result<Response<ResolvePinResponse>, Status> {
        require_gateway(&request, self)?;
        resolve_down(self)?;
        let r = request.into_inner();
        let identity = {
            let pins = self.pins.lock().unwrap();
            self.resolve_map(pins.get(&r.public_key_fingerprint), &r.source_ip)
        };
        Ok(Response::new(ResolvePinResponse {
            identity: Some(identity),
        }))
    }

    async fn resolve_otp(
        &self,
        request: Request<ResolveOtpRequest>,
    ) -> Result<Response<ResolveOtpResponse>, Status> {
        require_gateway(&request, self)?;
        resolve_down(self)?;
        let r = request.into_inner();
        // Single-use: consume (atomic mark-used) on a source-matched hit.
        let identity = {
            let mut otps = self.otps.lock().unwrap();
            match otps.get(&r.otp) {
                Some(rec) if rec.source_ip.as_deref().is_none_or(|s| s == r.source_ip) => {
                    let rec = otps.remove(&r.otp).unwrap();
                    resolved(&rec)
                }
                _ => not_resolved(),
            }
        };
        Ok(Response::new(ResolveOtpResponse {
            identity: Some(identity),
        }))
    }

    async fn begin_device_flow(
        &self,
        request: Request<BeginDeviceFlowRequest>,
    ) -> Result<Response<BeginDeviceFlowResponse>, Status> {
        require_gateway(&request, self)?;
        resolve_down(self)?;
        let template = self
            .device_flow_template
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Status::failed_precondition("no device flow configured"))?;
        let device_code = random_token("dev");
        let resp = BeginDeviceFlowResponse {
            device_code: device_code.clone(),
            user_code: template.user_code.clone(),
            verification_uri: template.verification_uri.clone(),
            interval_seconds: 1,
            expires_in_seconds: 120,
        };
        self.device_flows.lock().unwrap().insert(
            device_code,
            DeviceFlowRecord {
                template,
                polls: 0,
                expires_at: SystemTime::now() + Duration::from_secs(120),
            },
        );
        Ok(Response::new(resp))
    }

    async fn poll_device_flow(
        &self,
        request: Request<PollDeviceFlowRequest>,
    ) -> Result<Response<PollDeviceFlowResponse>, Status> {
        require_gateway(&request, self)?;
        resolve_down(self)?;
        let r = request.into_inner();
        let mut flows = self.device_flows.lock().unwrap();
        let Some(rec) = flows.get_mut(&r.device_code) else {
            // Unknown device_code → EXPIRED (generic, no existence disclosure).
            return Ok(Response::new(PollDeviceFlowResponse {
                status: DeviceFlowStatus::Expired as i32,
                identity: Some(not_resolved()),
            }));
        };
        if SystemTime::now() >= rec.expires_at {
            return Ok(Response::new(PollDeviceFlowResponse {
                status: DeviceFlowStatus::Expired as i32,
                identity: Some(not_resolved()),
            }));
        }
        rec.polls += 1;
        let (status, identity) = if rec.template.deny {
            (DeviceFlowStatus::Denied, not_resolved())
        } else if rec.polls > rec.template.approve_after_polls {
            (
                DeviceFlowStatus::Approved,
                // Real CP: device-flow APPROVED carries identity only; RBAC
                // decides the logins, so principals/groups are empty.
                ResolvedIdentity {
                    resolved: true,
                    identity: rec.template.identity.clone(),
                    principals: Vec::new(),
                    groups: Vec::new(),
                },
            )
        } else {
            (DeviceFlowStatus::Pending, not_resolved())
        };
        Ok(Response::new(PollDeviceFlowResponse {
            status: status as i32,
            identity: Some(identity),
        }))
    }

    async fn resolve_breakglass_key(
        &self,
        request: Request<ResolveBreakglassKeyRequest>,
    ) -> Result<Response<ResolveBreakglassKeyResponse>, Status> {
        let gid = require_gateway(&request, self)?;
        resolve_down(self)?;
        let r = request.into_inner();
        let resolution = {
            let keys = self.break_glass_keys.lock().unwrap();
            match keys.get(&r.sk_public_key_blob) {
                Some(rec) if rec.source_ip.as_deref().is_none_or(|s| s == r.source_ip) => {
                    self.mint_break_glass(&gid, rec, &r.source_ip, &r.node_id)
                }
                _ => not_resolved_break_glass(),
            }
        };
        Ok(Response::new(ResolveBreakglassKeyResponse {
            resolution: Some(resolution),
        }))
    }

    async fn resolve_breakglass_code(
        &self,
        request: Request<ResolveBreakglassCodeRequest>,
    ) -> Result<Response<ResolveBreakglassCodeResponse>, Status> {
        let gid = require_gateway(&request, self)?;
        resolve_down(self)?;
        let r = request.into_inner();
        // Single-use: consume (atomic mark-used) on a source-matched hit.
        let resolution = {
            let mut codes = self.offline_codes.lock().unwrap();
            match codes.get(&r.code) {
                Some(rec) if rec.source_ip.as_deref().is_none_or(|s| s == r.source_ip) => {
                    let rec = codes.remove(&r.code).unwrap();
                    self.mint_break_glass(&gid, &rec, &r.source_ip, &r.node_id)
                }
                _ => not_resolved_break_glass(),
            }
        };
        Ok(Response::new(ResolveBreakglassCodeResponse {
            resolution: Some(resolution),
        }))
    }
}

/// The generic non-resolution for a break-glass resolve (no identity, no token).
fn not_resolved_break_glass() -> BreakglassResolution {
    BreakglassResolution {
        identity: Some(not_resolved()),
        breakglass_token: String::new(),
    }
}

impl MockState {
    /// Mint a single-use break-glass token bound to {gateway, identity, node,
    /// source_ip} and return the resolution (identity + token).
    fn mint_break_glass(
        &self,
        gid: &str,
        rec: &ResolvedRecord,
        source_ip: &str,
        node_id: &str,
    ) -> BreakglassResolution {
        let token = random_token("bg");
        self.breakglass_tokens.lock().unwrap().insert(
            token.clone(),
            BreakglassTokenRecord {
                gateway_id: gid.to_string(),
                identity: rec.identity.clone(),
                principals: rec.principals.clone(),
                node_id: node_id.to_string(),
                source_ip: source_ip.to_string(),
                used: false,
            },
        );
        BreakglassResolution {
            identity: Some(resolved(rec)),
            breakglass_token: token,
        }
    }

    /// Build the decision context for a resolved, authorized target (shared by the
    /// standing and break-glass ALLOW paths). `access_model` is signed into it.
    fn context_for(
        &self,
        gid: &str,
        r: &AuthorizeRequest,
        access_model: AccessModel,
    ) -> DecisionContext {
        let now = unix_now() as i64;
        let capabilities = self
            .node_capabilities
            .lock()
            .unwrap()
            .get(&r.node_id)
            .cloned()
            .unwrap_or_else(|| vec![Capability::Shell as i32, Capability::Exec as i32]);
        let node_labels = self
            .node_labels
            .lock()
            .unwrap()
            .get(&r.node_id)
            .cloned()
            .unwrap_or_default();
        DecisionContext {
            node_id: r.node_id.clone(),
            node_name: r.node_id.clone(),
            allowed_logins: vec![r.requested_principal.clone()],
            capabilities,
            principal: r.requested_principal.clone(),
            grant_expiry_epoch_seconds: self
                .grant_expiry_override
                .lock()
                .unwrap()
                .unwrap_or(now + 3600),
            policy_epoch: 1,
            decision_ttl_seconds: *self.decision_ttl_secs.lock().unwrap(),
            gateway_id: gid.to_string(),
            session_id: r.session_id.clone(),
            source_address: r.source_ip.clone(),
            issued_at_epoch_seconds: now,
            identity: r.identity.clone(),
            identity_groups: r.identity_groups.clone(),
            node_labels,
            access_model: access_model as i32,
        }
    }

    /// Build an ALLOW response for a pre-built context: mint the single-use session
    /// and recording tokens (gateway/session-bound), attach the node connection, and
    /// sign the context (the Gateway verifies it before caching).
    fn allow_response_with_context(
        &self,
        gid: &str,
        r: &AuthorizeRequest,
        context: DecisionContext,
    ) -> AuthorizeResponse {
        let token = random_token("sess");
        self.tokens.lock().unwrap().insert(
            token.clone(),
            TokenRecord {
                gateway_id: gid.to_string(),
                session_id: r.session_id.clone(),
                node_id: r.node_id.clone(),
                principal: r.requested_principal.clone(),
                exp: SystemTime::now() + Duration::from_secs(120),
                used: false,
            },
        );
        let recording_token = random_token("rec");
        self.recording_tokens.lock().unwrap().insert(
            recording_token.clone(),
            TokenRecord {
                gateway_id: gid.to_string(),
                session_id: r.session_id.clone(),
                node_id: r.node_id.clone(),
                principal: r.requested_principal.clone(),
                exp: SystemTime::now() + Duration::from_secs(120),
                used: false,
            },
        );
        // Fold the FRESH presence owner into the node connection (Session Fifteen HA read
        // path): the owner fields ride only when a live Gateway heartbeated ownership, so an
        // OUTBOUND_AGENT node with no fresh owner comes back empty ⇒ "node offline".
        let node_connection = self
            .node_connections
            .lock()
            .unwrap()
            .get(&r.node_id)
            .cloned()
            .map(|mut nc| {
                if let Some(row) = self.fresh_presence(&r.node_id) {
                    nc.owning_gateway_id = row.owner;
                    nc.owning_gateway_addr = row.gateway_addr;
                    nc.owner_nonce = row.nonce;
                    nc.owner_nonce_id = row.nonce_id;
                }
                nc
            });
        let (signed_context, signature, signer_certificate, signer_ca_chain) =
            self.sign_context(&context);
        AuthorizeResponse {
            decision: Decision::Allow as i32,
            context: Some(context),
            signed_context,
            signature,
            signer_certificate,
            signer_ca_chain,
            session_token: token,
            node_connection,
            recording_token,
        }
    }

    fn allow_response(
        &self,
        gid: &str,
        r: &AuthorizeRequest,
        access_model: AccessModel,
    ) -> AuthorizeResponse {
        // F2: optionally SIGN a stronger access_model than the unsigned copy carries.
        let signed_model = if access_model == AccessModel::Standing
            && *self.force_signed_breakglass.lock().unwrap()
        {
            AccessModel::Breakglass
        } else {
            access_model
        };
        let signed_context = self.context_for(gid, r, signed_model);
        let mut resp = self.allow_response_with_context(gid, r, signed_context);
        // Ship a DOWNGRADED unsigned convenience copy (access_model = the requested,
        // weaker model). A GW reading the unsigned `context` would be fooled; a correct
        // GW ignores it and enforces the SIGNED access_model.
        if signed_model != access_model {
            resp.context = Some(self.context_for(gid, r, access_model));
        }
        resp
    }

    /// Whether any active lock matches this context's bindings — deny wins even in
    /// break-glass (Design §8.4, FR-ACC-6: a locked target refuses break-glass).
    fn lock_denies(&self, context: &DecisionContext) -> bool {
        let bindings = LockBindings::from_context(context);
        self.locks.lock().unwrap().iter().any(|l| {
            l.target
                .as_ref()
                .map(|t| target_matches(t, &bindings))
                .unwrap_or(false)
        })
    }

    /// The break-glass Authorize path (Session Thirteen): consume the single-use
    /// token (replay → fail closed), record the activation + fire the alert ON USE,
    /// force access_model = BREAKGLASS, and evaluate the always-available break-glass
    /// allow SUBJECT TO the top-tier Lock (a matching Lock still denies — deny wins).
    fn authorize_break_glass(&self, gid: &str, r: &AuthorizeRequest) -> AuthorizeResponse {
        let consumed = {
            let mut toks = self.breakglass_tokens.lock().unwrap();
            match toks.get_mut(&r.breakglass_token) {
                Some(t) if !t.used && t.gateway_id == gid => {
                    t.used = true;
                    true
                }
                _ => false,
            }
        };
        if !consumed {
            // Replay / unknown / wrong-gateway token → generic DENY (fail closed).
            return deny_response();
        }
        // The activation + high-priority alert happen ON USE, before the decision.
        self.breakglass_activations
            .lock()
            .unwrap()
            .push(BreakglassActivation {
                identity: r.identity.clone(),
                node_id: r.node_id.clone(),
            });
        if !self.known_nodes.lock().unwrap().contains(&r.node_id) {
            return deny_response();
        }
        let context = self.context_for(gid, r, AccessModel::Breakglass);
        // Deny wins: a top-tier Lock refuses break-glass on a locked target.
        if self.lock_denies(&context) {
            return deny_response();
        }
        // Break-glass BYPASSES the standing dp_rule deny (always-available path).
        self.allow_response_with_context(gid, r, context)
    }
}

#[tonic::async_trait]
impl Authorization for MockSvc {
    async fn authorize(
        &self,
        request: Request<AuthorizeRequest>,
    ) -> Result<Response<AuthorizeResponse>, Status> {
        let gid = require_gateway(&request, self)?;
        if *self.authorize_unavailable.lock().unwrap() {
            return Err(Status::unavailable("control plane temporarily unavailable"));
        }
        let mut r = request.into_inner();
        self.authorize_requests.lock().unwrap().push(r.clone());
        // Name resolution is server-side authoritative (§11, FR-ADDR-1): resolve
        // node_name to the node's id/key and IGNORE the client-asserted node_id, so a
        // client cannot smuggle an id past the resolved name. Empty node_name falls
        // back to node_id (a direct-id caller). Everything below keys on the resolved
        // r.node_id.
        if !r.node_name.is_empty() {
            r.node_id = self.resolve_node_name(&r.node_name);
        }

        // Break-glass connect (Session Thirteen): a present token routes to the
        // always-available break-glass path (consume token + activation/alert + force
        // BREAKGLASS + Lock-checked allow). Empty ⇒ the standing/JIT path below.
        if !r.breakglass_token.is_empty() {
            return Ok(Response::new(self.authorize_break_glass(&gid, &r)));
        }

        // Unknown node → generic DENY (§7.1, no existence disclosure).
        if !self.known_nodes.lock().unwrap().contains(&r.node_id) {
            return Ok(Response::new(deny_response()));
        }
        let allowed = self.allow_rules.lock().unwrap().iter().any(|rule| {
            rule.identity == r.identity
                && rule.node_id == r.node_id
                && rule.principal == r.requested_principal
        });
        if !allowed {
            return Ok(Response::new(deny_response()));
        }

        // ALLOW (standing): mint the single-use session + recording tokens + the
        // SIGNED decision context (Part E node connection attached if registered).
        Ok(Response::new(self.allow_response(
            &gid,
            &r,
            AccessModel::Standing,
        )))
    }
}

impl MockState {
    /// Resolve a node NAME to its CP id (Session Sixteen, Part A). A mapped name
    /// returns the mapped id; an unmapped name resolves to itself (pass-through, the
    /// S7–S15 shape where the mock inventory is keyed by name).
    fn resolve_node_name(&self, name: &str) -> String {
        self.node_name_to_id
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string())
    }

    /// The owner NAME for a caller gateway id (the HA routing key), or `None` if unknown.
    fn gateway_name_of(&self, gid: &str) -> Option<String> {
        self.gateways
            .lock()
            .unwrap()
            .get(gid)
            .map(|r| r.name.clone())
    }

    /// The presence row for `node_id` iff it is FRESH (heartbeated within the staleness TTL).
    /// This is what the Authorize read path folds into `NodeConnection` (owner fields ride
    /// only when a fresh owner exists — else the node is offline).
    fn fresh_presence(&self, node_id: &str) -> Option<PresenceRow> {
        let now = SystemTime::now();
        self.presence
            .lock()
            .unwrap()
            .get(node_id)
            .filter(|row| {
                now.duration_since(row.last_seen)
                    .map(|d| d < self.presence_staleness)
                    .unwrap_or(false)
            })
            .cloned()
    }
}

#[tonic::async_trait]
impl Presence for MockSvc {
    async fn heartbeat(
        &self,
        request: Request<PresenceHeartbeatRequest>,
    ) -> Result<Response<PresenceHeartbeatResponse>, Status> {
        // The OWNER is the authenticated mTLS peer (its gateway_identity.name) — never a
        // request field (the HA trust rule, exactly like the real CP).
        let gid = require_gateway(&request, self)?;
        let owner = self
            .gateway_name_of(&gid)
            .ok_or_else(|| Status::unauthenticated("unknown gateway"))?;
        let r = request.into_inner();
        if r.node_name.is_empty() {
            return Err(Status::invalid_argument("node name required"));
        }
        if r.gateway_addr.is_empty() {
            return Err(Status::invalid_argument("gateway address required"));
        }

        let now = SystemTime::now();
        let mut map = self.presence.lock().unwrap();
        let row = match map.get(&r.node_name) {
            // Refresh: we are the owner → bump last_seen (nonce unchanged).
            Some(existing) if existing.owner == owner => PresenceRow {
                gateway_addr: r.gateway_addr.clone(),
                last_seen: now,
                ..existing.clone()
            },
            // Takeover: the owner is stale → claim with nonce+1 and a new nonce_id.
            Some(existing)
                if now
                    .duration_since(existing.last_seen)
                    .map(|d| d >= self.presence_staleness)
                    .unwrap_or(true) =>
            {
                PresenceRow {
                    owner: owner.clone(),
                    gateway_addr: r.gateway_addr.clone(),
                    nonce: existing.nonce + 1,
                    nonce_id: random_token("nonce"),
                    last_seen: now,
                }
            }
            // Standby: a fresh owner that is not us → NO write; return the authoritative owner.
            Some(existing) => existing.clone(),
            // Claim a node with no current owner (nonce 1).
            None => PresenceRow {
                owner: owner.clone(),
                gateway_addr: r.gateway_addr.clone(),
                nonce: 1,
                nonce_id: random_token("nonce"),
                last_seen: now,
            },
        };
        map.insert(r.node_name.clone(), row.clone());

        Ok(Response::new(PresenceHeartbeatResponse {
            owning_gateway_id: row.owner.clone(),
            gateway_addr: row.gateway_addr,
            nonce: row.nonce,
            nonce_id: row.nonce_id,
            last_seen_epoch_ms: epoch_ms(row.last_seen),
            is_self_owner: row.owner == owner,
        }))
    }

    async fn release(
        &self,
        request: Request<PresenceReleaseRequest>,
    ) -> Result<Response<PresenceReleaseResponse>, Status> {
        let gid = require_gateway(&request, self)?;
        let owner = self
            .gateway_name_of(&gid)
            .ok_or_else(|| Status::unauthenticated("unknown gateway"))?;
        let r = request.into_inner();
        let mut map = self.presence.lock().unwrap();
        let released = match map.get(&r.node_name) {
            Some(existing) if existing.owner == owner => {
                // Age last_seen far into the past so a standby claims immediately (the nonce
                // chain is preserved), closing the planned-drain failover window.
                let relinquished = PresenceRow {
                    last_seen: UNIX_EPOCH,
                    ..existing.clone()
                };
                map.insert(r.node_name.clone(), relinquished);
                true
            }
            _ => false, // idempotent: not the recorded owner
        };
        Ok(Response::new(PresenceReleaseResponse { released }))
    }
}

#[tonic::async_trait]
impl LockFeed for MockSvc {
    type StreamLocksStream = Pin<Box<dyn Stream<Item = Result<LockEvent, Status>> + Send>>;

    async fn stream_locks(
        &self,
        request: Request<StreamLocksRequest>,
    ) -> Result<Response<Self::StreamLocksStream>, Status> {
        require_gateway(&request, self)?;
        // G6: simulate an unhealthy lock feed — refuse the stream so the Gateway's feed
        // never delivers a snapshot and stays !healthy (no connection).
        if *self.lock_feed_down.lock().unwrap() {
            return Err(Status::unavailable("lock feed unavailable"));
        }
        // Subscribe to live events BEFORE snapshotting, so an add/remove that races
        // the snapshot is never lost (a duplicate is harmless — the Gateway dedups).
        let mut events = self.lock_events.subscribe();
        let snapshot = self.locks.lock().unwrap().clone();
        let feed_epoch = self.feed_epoch.load(Ordering::SeqCst);
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<LockEvent, Status>>(64);
        tokio::spawn(async move {
            let snap = LockEvent {
                event: Some(lock_event::Event::Snapshot(LockSnapshot {
                    locks: snapshot,
                    feed_epoch,
                })),
            };
            if tx.send(Ok(snap)).await.is_err() {
                return;
            }
            let mut hb = tokio::time::interval(Duration::from_secs(1));
            hb.tick().await; // consume the immediate first tick
            loop {
                tokio::select! {
                    ev = events.recv() => match ev {
                        Ok(e) => { if tx.send(Ok(e)).await.is_err() { return; } }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(_) => return,
                    },
                    _ = hb.tick() => {
                        let beat = LockEvent {
                            event: Some(lock_event::Event::Heartbeat(Heartbeat {
                                sent_at_epoch_seconds: unix_now() as i64,
                            })),
                        };
                        if tx.send(Ok(beat)).await.is_err() { return; }
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

#[tonic::async_trait]
impl Recording for MockSvc {
    async fn begin_recording(
        &self,
        request: Request<BeginRecordingRequest>,
    ) -> Result<Response<BeginRecordingResponse>, Status> {
        let gid = require_gateway(&request, self)?;
        let r = request.into_inner();

        // Consume the single-use recording token (bound to this gateway; unexpired).
        {
            let mut toks = self.recording_tokens.lock().unwrap();
            let rec = toks
                .get_mut(&r.recording_token)
                .ok_or_else(|| Status::permission_denied("access denied by policy"))?;
            if rec.used || rec.exp <= SystemTime::now() || rec.gateway_id != gid {
                return Err(Status::permission_denied("access denied by policy"));
            }
            rec.used = true;
        }

        // The customer key is mandatory: if the operator configured none, return a
        // response WITHOUT a customer key so the Gateway refuses (strict).
        let customer_key = self.customer_key.lock().unwrap().clone();

        let recording_id = random_token("recid");
        let object_key = format!("recordings/{recording_id}");
        self.recordings
            .lock()
            .unwrap()
            .insert(recording_id.clone(), (gid, object_key.clone()));

        // BeginRecording does NOT return an upload credential — that is issued
        // short-lived at upload time via RequestUpload (§12.2).
        Ok(Response::new(BeginRecordingResponse {
            recording_id,
            object_key,
            worm_mode: WormMode::Compliance as i32,
            customer_key,
        }))
    }

    async fn request_upload(
        &self,
        request: Request<RequestUploadRequest>,
    ) -> Result<Response<RequestUploadResponse>, Status> {
        let gid = require_gateway(&request, self)?;
        let r = request.into_inner();
        // Ownership check + resolve the object key registered at BeginRecording.
        let object_key = {
            let recs = self.recordings.lock().unwrap();
            match recs.get(&r.recording_id) {
                Some((owner, key)) if *owner == gid => key.clone(),
                _ => return Err(Status::permission_denied("access denied by policy")),
            }
        };
        self.request_uploads.lock().unwrap().push(r.recording_id);

        // Presign a FRESH single-object PUT under COMPLIANCE object-lock (the
        // object-lock headers are SIGNED, so the uploader cannot strip the WORM
        // lock). The TTL covers only the PUT.
        let ttl = *self.upload_ttl_secs.lock().unwrap();
        let upload = self.s3.lock().unwrap().as_ref().map(|s3| {
            let retain = sigv4::retain_until_days(1);
            let path = format!("/{}/{}", s3.bucket, object_key);
            let (url, headers) = sigv4::presign(
                s3,
                "PUT",
                &path,
                &[],
                &[
                    ("x-amz-object-lock-mode", "COMPLIANCE"),
                    ("x-amz-object-lock-retain-until-date", &retain),
                ],
                ttl,
            );
            UploadCredential {
                url,
                method: "PUT".to_string(),
                required_headers: headers.into_iter().collect(),
                expires_at_epoch_seconds: (unix_now() + ttl) as i64,
            }
        });
        Ok(Response::new(RequestUploadResponse { upload }))
    }

    async fn finalize_recording(
        &self,
        request: Request<FinalizeRecordingRequest>,
    ) -> Result<Response<FinalizeRecordingResponse>, Status> {
        let gid = require_gateway(&request, self)?;
        let r = request.into_inner();
        // Ownership check: the recording must have been created by this caller.
        {
            let recs = self.recordings.lock().unwrap();
            match recs.get(&r.recording_id) {
                Some((owner, _)) if *owner == gid => {}
                _ => return Err(Status::permission_denied("access denied by policy")),
            }
        }
        let status = r.status;
        self.finalized
            .lock()
            .unwrap()
            .insert(r.recording_id.clone(), r);
        Ok(Response::new(FinalizeRecordingResponse { status }))
    }
}

/// The generic DENY: no context, no token, no connection (fail closed).
fn deny_response() -> AuthorizeResponse {
    AuthorizeResponse {
        decision: Decision::Deny as i32,
        context: None,
        signed_context: Vec::new(),
        signature: Vec::new(),
        signer_certificate: Vec::new(),
        signer_ca_chain: Vec::new(),
        session_token: String::new(),
        node_connection: None,
        recording_token: String::new(),
    }
}

/// `time::OffsetDateTime::now_utc()`, for rcgen validity windows.
fn offset_now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

fn epoch_of(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn epoch_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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
    presence_staleness: Duration,
}

impl Default for MockCpBuilder {
    fn default() -> Self {
        Self {
            server_range: ((1, 0), (1, 1)),
            cert_ttl: Duration::from_secs(3600),
            server_san: "cp.internal".to_string(),
            presence_staleness: Duration::from_secs(30),
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

    /// Override the HA presence staleness TTL (an owner un-heartbeated this long is taken
    /// over; short values let a failover test observe re-ownership quickly).
    pub fn presence_staleness(mut self, ttl: Duration) -> Self {
        self.presence_staleness = ttl;
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

        // Session Ten: the CONTEXT_SIGNER leaf (chained to `ca`) + its P-256 key,
        // used to sign decision contexts the Gateway verifier accepts.
        let context_signer_leaf = ca.issue_context_signer(
            rcgen::date_time_ymd(2020, 1, 1),
            rcgen::date_time_ymd(2100, 1, 1),
        );
        let context_signer_der = context_signer_leaf.cert_der.clone();
        let context_signer_key =
            SigningKey::from_pkcs8_der(&context_signer_leaf.key_pkcs8_der).unwrap();

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

        // User-facing CA (SSH) for signing / validating outer-leg user certs (S7).
        let user_ca = ssh_key::PrivateKey::random(
            &mut rng,
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        let user_ca_pem = user_ca
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();

        // Host CA (SSH) for signing node host certs (Design §9.3, Session Eight).
        let host_ca = ssh_key::PrivateKey::random(
            &mut rng,
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        let host_ca_pem = host_ca
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let host_ca_public_wire = host_ca.public_key().to_bytes().unwrap();

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
            user_ca_pem,
            pins: Mutex::new(HashMap::new()),
            otps: Mutex::new(HashMap::new()),
            device_flow_template: Mutex::new(None),
            device_flows: Mutex::new(HashMap::new()),
            allow_rules: Mutex::new(Vec::new()),
            known_nodes: Mutex::new(HashSet::new()),
            host_ca_pem,
            host_ca_public_wire,
            node_connections: Mutex::new(HashMap::new()),
            node_capabilities: Mutex::new(HashMap::new()),
            decision_ttl_secs: Mutex::new(45),
            force_signed_breakglass: Mutex::new(false),
            grant_expiry_override: Mutex::new(None),
            lock_feed_down: Mutex::new(false),
            authorize_unavailable: Mutex::new(false),
            resolve_unavailable: Mutex::new(false),
            break_glass_keys: Mutex::new(HashMap::new()),
            offline_codes: Mutex::new(HashMap::new()),
            breakglass_tokens: Mutex::new(HashMap::new()),
            breakglass_activations: Mutex::new(Vec::new()),
            recording_tokens: Mutex::new(HashMap::new()),
            customer_key: Mutex::new(None),
            s3: Mutex::new(None),
            recordings: Mutex::new(HashMap::new()),
            finalized: Mutex::new(HashMap::new()),
            upload_ttl_secs: Mutex::new(900),
            request_uploads: Mutex::new(Vec::new()),
            context_signer_der,
            context_signer_key,
            node_labels: Mutex::new(HashMap::new()),
            locks: Mutex::new(Vec::new()),
            server_cert_ttl: Mutex::new(Duration::from_secs(3600)),
            signed_key_ids: Mutex::new(Vec::new()),
            lock_events: tokio::sync::broadcast::channel(64).0,
            feed_epoch: AtomicU64::new(1),
            presence: Mutex::new(HashMap::new()),
            presence_staleness: self.presence_staleness,
            node_name_to_id: Mutex::new(HashMap::new()),
            authorize_requests: Mutex::new(Vec::new()),
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
                .add_service(OuterLegAuthServer::new(MockSvc(svc_state.clone())))
                .add_service(AuthorizationServer::new(MockSvc(svc_state.clone())))
                .add_service(RecordingServer::new(MockSvc(svc_state.clone())))
                .add_service(LockFeedServer::new(MockSvc(svc_state.clone())))
                .add_service(PresenceServer::new(MockSvc(svc_state.clone())))
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

    // ---- Session Seven outer-leg knobs -------------------------------------

    /// Register a pin: a public-key fingerprint resolves to `{identity,
    /// principals}` (no source binding).
    pub fn register_pin(&self, fingerprint: &str, identity: &str, principals: &[&str]) {
        self.state.pins.lock().unwrap().insert(
            fingerprint.to_string(),
            ResolvedRecord {
                identity: identity.to_string(),
                principals: principals.iter().map(|s| s.to_string()).collect(),
                groups: Vec::new(),
                source_ip: None,
            },
        );
    }

    /// Register a single-use OTP resolving to `{identity, principals}`.
    pub fn register_otp(&self, otp: &str, identity: &str, principals: &[&str]) {
        self.state.otps.lock().unwrap().insert(
            otp.to_string(),
            ResolvedRecord {
                identity: identity.to_string(),
                principals: principals.iter().map(|s| s.to_string()).collect(),
                groups: Vec::new(),
                source_ip: None,
            },
        );
    }

    /// Configure the outcome the next device flow(s) will produce: PENDING for
    /// `approve_after_polls` polls, then APPROVED resolving to `identity` (with
    /// empty principals/groups, as the real CP does — RBAC decides the logins).
    pub fn set_device_flow(
        &self,
        user_code: &str,
        verification_uri: &str,
        identity: &str,
        approve_after_polls: u32,
    ) {
        *self.state.device_flow_template.lock().unwrap() = Some(DeviceFlowTemplate {
            user_code: user_code.to_string(),
            verification_uri: verification_uri.to_string(),
            identity: identity.to_string(),
            approve_after_polls,
            deny: false,
        });
    }

    /// Configure the next device flow to be DENIED.
    pub fn set_device_flow_denied(&self, user_code: &str, verification_uri: &str) {
        *self.state.device_flow_template.lock().unwrap() = Some(DeviceFlowTemplate {
            user_code: user_code.to_string(),
            verification_uri: verification_uri.to_string(),
            identity: String::new(),
            approve_after_polls: u32::MAX,
            deny: true,
        });
    }

    /// Mark a node as existing in inventory (so `Authorize` doesn't §7.1-DENY it
    /// for non-existence) without granting any access.
    pub fn register_node(&self, node_id: &str) {
        self.state
            .known_nodes
            .lock()
            .unwrap()
            .insert(node_id.to_string());
    }

    /// Map a node NAME to a DISTINCT CP id (Session Sixteen, Part A). Without a mapping
    /// the mock resolves a name to itself (pass-through). A distinct mapping lets a test
    /// address by human name yet configure the inventory (`allow`, `set_node_connection`,
    /// locks) by the id — proving the Gateway forwards the NAME and the whole downstream
    /// keys on the CP-resolved id, not the raw parsed string.
    pub fn map_node_name(&self, name: &str, id: &str) {
        self.state
            .node_name_to_id
            .lock()
            .unwrap()
            .insert(name.to_string(), id.to_string());
    }

    /// The most recent `AuthorizeRequest` the mock received (Part A assertions:
    /// node_name populated). `None` if none arrived yet.
    pub fn last_authorize_request(&self) -> Option<AuthorizeRequest> {
        self.state
            .authorize_requests
            .lock()
            .unwrap()
            .last()
            .cloned()
    }

    /// Grant `{identity, node, principal}` (also registers the node as existing).
    pub fn allow(&self, identity: &str, node_id: &str, principal: &str) {
        self.register_node(node_id);
        self.state.allow_rules.lock().unwrap().push(AllowRule {
            identity: identity.to_string(),
            node_id: node_id.to_string(),
            principal: principal.to_string(),
        });
    }

    /// Register the agentless node connection (dial address + host trust) the
    /// `Authorize` ALLOW returns for `node_id` (Part E). Without this, an
    /// authorized node has no connection → the Gateway fails closed.
    pub fn set_node_connection(&self, node_id: &str, dial_address: &str, host: HostVerification) {
        self.state.node_connections.lock().unwrap().insert(
            node_id.to_string(),
            NodeConnection {
                connector_kind: ConnectorKind::Agentless as i32,
                dial_address: dial_address.to_string(),
                host_verification: Some(host),
                node_name: node_id.to_string(),
                ..Default::default()
            },
        );
    }

    /// Declare `node_id` an **outbound-agent** node (Session Fourteen, FR-CONN-3):
    /// no dial address, and the enrollment `node_name` the Gateway joins to the
    /// agent's control channel by (its certificate's dNSName SAN).
    pub fn set_agent_node_connection(
        &self,
        node_id: &str,
        node_name: &str,
        host: HostVerification,
    ) {
        self.state.node_connections.lock().unwrap().insert(
            node_id.to_string(),
            NodeConnection {
                connector_kind: ConnectorKind::OutboundAgent as i32,
                dial_address: String::new(),
                host_verification: Some(host),
                node_name: node_name.to_string(),
                ..Default::default()
            },
        );
    }

    /// The current HA presence owner NAME for `node_id` (for failover assertions), if any.
    pub fn presence_owner(&self, node_id: &str) -> Option<String> {
        self.state
            .presence
            .lock()
            .unwrap()
            .get(node_id)
            .map(|r| r.owner.clone())
    }

    /// Issue an **agent identity** leaf from this CP's internal mTLS CA: the S12
    /// credential an Agent presents on both wire roles (URI SAN
    /// `sessionlayer://agent/<agent_id>` + dNSName SAN = the node's enrollment name).
    pub fn issue_agent_identity(&self, agent_id: &str, node_name: &str) -> IssuedLeaf {
        self.state.ca.issue_agent_leaf(agent_id, node_name)
    }

    /// The key-ids (`session_id + principal`) of every inner-leg certificate this CP
    /// has signed. The node's own `sshd` VERBOSE log records the same value on every
    /// accepted certificate, which is what makes the node-local trail an independent
    /// second record (FR-AUD-4).
    pub fn signed_key_ids(&self) -> Vec<String> {
        self.state.signed_key_ids.lock().unwrap().clone()
    }

    /// Override the granted capabilities for `node_id` (default shell+exec).
    pub fn set_capabilities(&self, node_id: &str, caps: &[Capability]) {
        self.state.node_capabilities.lock().unwrap().insert(
            node_id.to_string(),
            caps.iter().map(|c| *c as i32).collect(),
        );
    }

    /// Set a node's inventory labels ("key=value"), signed into the decision
    /// context (so node-label locks can be exercised).
    pub fn set_node_labels(&self, node_id: &str, labels: &[&str]) {
        self.state.node_labels.lock().unwrap().insert(
            node_id.to_string(),
            labels.iter().map(|l| l.to_string()).collect(),
        );
    }

    /// Push a lock onto the deny-list feed (create): it lands in the snapshot AND
    /// is broadcast to live `StreamLocks` subscribers (which tear down matches).
    pub fn add_lock(&self, lock: Lock) {
        {
            let mut locks = self.state.locks.lock().unwrap();
            locks.retain(|l| l.lock_id != lock.lock_id);
            locks.push(lock.clone());
        }
        self.state.feed_epoch.fetch_add(1, Ordering::SeqCst);
        let _ = self.state.lock_events.send(LockEvent {
            event: Some(lock_event::Event::Added(lock)),
        });
    }

    /// For the teardown E2E: push `lock` onto the feed as soon as a recording has
    /// begun (i.e. the session is live), from a background task. Lets the test call
    /// a blocking `ssh_exec` and still deliver the lock mid-session.
    pub fn push_lock_after_recording_begins(&self, lock: Lock) {
        let state = self.state.clone();
        tokio::spawn(async move {
            for _ in 0..400 {
                if !state.recordings.lock().unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            {
                let mut locks = state.locks.lock().unwrap();
                locks.retain(|l| l.lock_id != lock.lock_id);
                locks.push(lock.clone());
            }
            state.feed_epoch.fetch_add(1, Ordering::SeqCst);
            let _ = state.lock_events.send(LockEvent {
                event: Some(lock_event::Event::Added(lock)),
            });
        });
    }

    /// The number of recordings that have begun (test synchronization).
    pub fn began_recording_count(&self) -> usize {
        self.state.recordings.lock().unwrap().len()
    }

    /// Release a lock (delete): drop it from the snapshot + broadcast a removal.
    pub fn remove_lock(&self, lock_id: &str) {
        self.state
            .locks
            .lock()
            .unwrap()
            .retain(|l| l.lock_id != lock_id);
        self.state.feed_epoch.fetch_add(1, Ordering::SeqCst);
        let _ = self.state.lock_events.send(LockEvent {
            event: Some(lock_event::Event::Removed(LockRemoval {
                lock_id: lock_id.to_string(),
            })),
        });
    }

    /// The host CA public key (OpenSSH wire): a node host cert signed by this CA
    /// verifies against it.
    pub fn host_ca_public_wire(&self) -> Vec<u8> {
        self.state.host_ca_public_wire.clone()
    }

    /// Sign a node **host** certificate over `host_pubkey_wire` with the host CA
    /// (Design §9.3), carrying `principals`. Returns `(cert_line, cert_wire)`.
    pub fn sign_host_cert(
        &self,
        host_pubkey_wire: &[u8],
        principals: &[&str],
        valid_secs: u64,
    ) -> (String, Vec<u8>) {
        let pubkey = ssh_key::PublicKey::from_bytes(host_pubkey_wire).unwrap();
        let ca = ssh_key::PrivateKey::from_openssh(&self.state.host_ca_pem).unwrap();
        let now = unix_now();
        let mut rng = rand_core::OsRng;
        let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rng,
            pubkey.key_data().clone(),
            now.saturating_sub(60),
            now + valid_secs,
        )
        .unwrap();
        builder
            .cert_type(ssh_key::certificate::CertType::Host)
            .unwrap();
        for p in principals {
            builder.valid_principal(*p).unwrap();
        }
        builder.key_id("sessionlayer-host-cert").unwrap();
        let cert = builder.sign(&ca).unwrap();
        (cert.to_openssh().unwrap(), cert.to_bytes().unwrap())
    }

    /// A host-CA `HostVerification`: the node's host cert + the trusted host CA +
    /// the expected principal(s).
    pub fn host_ca_verification(
        &self,
        host_cert_wire: Vec<u8>,
        principals: &[&str],
    ) -> HostVerification {
        HostVerification {
            host_ca_keys: vec![self.host_ca_public_wire()],
            expected_host_principals: principals.iter().map(|s| s.to_string()).collect(),
            pinned_host_keys: Vec::new(),
            host_certificates: vec![host_cert_wire],
        }
    }

    /// A pinned-key `HostVerification` (the fallback path).
    pub fn pinned_verification(&self, host_pubkey_wire: Vec<u8>) -> HostVerification {
        HostVerification {
            host_ca_keys: Vec::new(),
            expected_host_principals: Vec::new(),
            pinned_host_keys: vec![host_pubkey_wire],
            host_certificates: Vec::new(),
        }
    }

    /// Toggle the CP-unreachable simulation for `Authorize` (returns UNAVAILABLE).
    pub fn set_authorize_unavailable(&self, on: bool) {
        *self.state.authorize_unavailable.lock().unwrap() = on;
    }

    /// Toggle the CP-unreachable simulation for the OuterLegAuth **resolve** RPCs
    /// (they return UNAVAILABLE) — CP-down during authentication.
    pub fn set_resolve_unavailable(&self, on: bool) {
        *self.state.resolve_unavailable.lock().unwrap() = on;
    }

    // ---- Session Thirteen break-glass knobs ---------------------------------

    /// Register a break-glass FIDO2 key: the OpenSSH wire blob of an `sk-ecdsa`/
    /// `sk-ed25519` public key resolves to `{identity, principals}` (no source
    /// binding). The key is public; the CP maps it to a break-glass credential.
    pub fn register_break_glass_key(
        &self,
        sk_public_key_blob: Vec<u8>,
        identity: &str,
        principals: &[&str],
    ) {
        self.state.break_glass_keys.lock().unwrap().insert(
            sk_public_key_blob,
            ResolvedRecord {
                identity: identity.to_string(),
                principals: principals.iter().map(|s| s.to_string()).collect(),
                groups: Vec::new(),
                source_ip: None,
            },
        );
    }

    /// Register a single-use break-glass OFFLINE CODE resolving to `{identity,
    /// principals}` (consumed on validate, single-use).
    pub fn register_offline_code(&self, code: &str, identity: &str, principals: &[&str]) {
        self.state.offline_codes.lock().unwrap().insert(
            code.to_string(),
            ResolvedRecord {
                identity: identity.to_string(),
                principals: principals.iter().map(|s| s.to_string()).collect(),
                groups: Vec::new(),
                source_ip: None,
            },
        );
    }

    /// Set the `decision_ttl_seconds` baked into signed contexts. `0` forces the
    /// Gateway to re-validate every channel-open (exercises the break-glass
    /// no-replay re-auth posture).
    pub fn set_decision_ttl(&self, secs: i64) {
        *self.state.decision_ttl_secs.lock().unwrap() = secs;
    }

    /// F2: on a STANDING allow, SIGN access_model=BREAKGLASS while shipping a
    /// downgraded unsigned `context` (STANDING). Proves the Gateway enforces the
    /// SIGNED access_model, never the unsigned convenience copy.
    pub fn set_force_signed_breakglass(&self, on: bool) {
        *self.state.force_signed_breakglass.lock().unwrap() = on;
    }

    /// G1: force the exact `grant_expiry_epoch_seconds` signed into contexts (0 makes a
    /// break-glass ALLOW un-time-boxed → the GW must fail closed).
    pub fn set_grant_expiry(&self, epoch_seconds: i64) {
        *self.state.grant_expiry_override.lock().unwrap() = Some(epoch_seconds);
    }

    /// G6: make the lock feed unavailable so the Gateway's feed never becomes healthy.
    pub fn set_lock_feed_down(&self, on: bool) {
        *self.state.lock_feed_down.lock().unwrap() = on;
    }

    /// The number of break-glass tokens minted by a resolve (test assertion for the
    /// FIDO2/offline-code resolution path).
    pub fn breakglass_token_count(&self) -> usize {
        self.state.breakglass_tokens.lock().unwrap().len()
    }

    /// The number of break-glass activations recorded at Authorize (the alert fires
    /// once per activation, ON USE).
    pub fn breakglass_activation_count(&self) -> usize {
        self.state.breakglass_activations.lock().unwrap().len()
    }

    /// The {identity, node_id} pairs of the recorded break-glass activations.
    pub fn breakglass_activations(&self) -> Vec<(String, String)> {
        self.state
            .breakglass_activations
            .lock()
            .unwrap()
            .iter()
            .map(|a| (a.identity.clone(), a.node_id.clone()))
            .collect()
    }

    // ---- Session Nine recorder knobs ----------------------------------------

    /// Configure the operator's customer PUBLIC key (DER SPKI) the Gateway seals
    /// the recording data key to. Without this, BeginRecording returns no customer
    /// key and the Gateway refuses the session (strict).
    pub fn set_customer_key(
        &self,
        key_ref: &str,
        public_key_der: Vec<u8>,
        algorithm: KeySealAlgorithm,
    ) {
        *self.state.customer_key.lock().unwrap() = Some(CustomerKey {
            key_ref: key_ref.to_string(),
            public_key: public_key_der,
            algorithm: algorithm as i32,
        });
    }

    /// Point the WORM upload credential at a MinIO/S3 target (the container).
    pub fn set_s3_target(&self, target: S3Target) {
        *self.state.s3.lock().unwrap() = Some(target);
    }

    /// The object keys of recordings BeginRecording has registered.
    pub fn recorded_object_keys(&self) -> Vec<String> {
        self.state
            .recordings
            .lock()
            .unwrap()
            .values()
            .map(|(_, k)| k.clone())
            .collect()
    }

    /// The FinalizeRecording payloads the Gateway has committed (test assertions).
    pub fn finalized_recordings(&self) -> Vec<FinalizeRecordingRequest> {
        self.state
            .finalized
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Set the TTL (seconds) baked into each RequestUpload presigned PUT. A short
    /// value proves the credential is issued at upload time (a long session would
    /// have expired a begin-time credential).
    pub fn set_upload_ttl_secs(&self, ttl: u64) {
        *self.state.upload_ttl_secs.lock().unwrap() = ttl;
    }

    /// How many times RequestUpload has been called (the credential is fetched at
    /// session end, not at BeginRecording).
    pub fn request_upload_count(&self) -> usize {
        self.state.request_uploads.lock().unwrap().len()
    }

    /// Sign an OpenSSH user certificate with the user-facing CA (for the
    /// `ResolveUserCert` happy path). `pubkey_openssh_line` is an authorized-keys
    /// line; returns the cert as an authorized-keys line.
    pub fn sign_user_cert(
        &self,
        pubkey_openssh_line: &str,
        identity: &str,
        principals: &[&str],
        valid_secs: u64,
    ) -> String {
        let principals: Vec<String> = principals.iter().map(|s| s.to_string()).collect();
        self.state
            .sign_user_cert(pubkey_openssh_line, identity, &principals, valid_secs)
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

/// Enroll a Gateway against `cp` and assemble outer-leg [`HandlerDeps`] (a
/// CP-delegating auth client + the Session-Seven `PendingInnerLeg` connector +
/// the pass-through target resolver) for the given SSH server `config`. The
/// enrolled credential is snapshotted into the channel factory, so the temp
/// data-dir can be dropped immediately.
/// Which recorder a set of [`HandlerDeps`] wires in.
pub enum RecorderChoice {
    /// No recording (the S8 E2E cases; no MinIO needed).
    Null,
    /// The real recorder (asciicast + customer-key seal + WORM upload), built over
    /// the same enrolled CP client and `config.recorder`.
    Real,
}

pub async fn outer_leg_deps(cp: &MockCp, config: Arc<SshServerConfig>) -> HandlerDeps {
    let connector = Arc::new(AgentlessDial::new(Duration::from_secs(
        config.inner.connect_timeout_secs,
    )));
    outer_leg_deps_with(cp, config, connector, RecorderChoice::Null).await
}

/// Like [`outer_leg_deps`] but with an explicit connector + recorder choice, for
/// the inner-leg E2E (a real agentless dial to the Docker node) and the recorder
/// E2E (asciicast/WORM).
pub async fn outer_leg_deps_with(
    cp: &MockCp,
    config: Arc<SshServerConfig>,
    connector: Arc<dyn NodeConnector>,
    recorder: RecorderChoice,
) -> HandlerDeps {
    outer_leg_deps_named(cp, config, connector, recorder, "gw-s8")
        .await
        .0
}

/// Like [`outer_leg_deps_with`], but enrolls under an explicit Gateway **name** and also
/// returns the credential — the agent transport needs both (its serverAuth leaf carries
/// the name, and every dial-back token is bound to the gateway id).
pub async fn outer_leg_deps_named(
    cp: &MockCp,
    config: Arc<SshServerConfig>,
    connector: Arc<dyn NodeConnector>,
    recorder: RecorderChoice,
    gateway_name: &str,
) -> (HandlerDeps, identity::Credential) {
    let dir = tempfile::tempdir().unwrap();
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    let params = cp.channel_params(Duration::from_secs(5), Duration::from_secs(10));
    let cred = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        gateway_name,
    )
    .await
    .unwrap();
    let credential = cred.clone();

    let factory = Arc::new(CpChannelFactory::fixed(
        cp.channel_params(Duration::from_secs(5), Duration::from_secs(10)),
        cred.identity.clone(),
        cred.ca_chain_der.clone(),
    ));
    let cpauth = Arc::new(CpAuthClient::new(
        factory.clone(),
        Duration::from_secs(config.cp_rpc_timeout_secs),
    ));
    let recorder_factory: Arc<dyn RecorderFactory> = match recorder {
        RecorderChoice::Null => Arc::new(NullRecorderFactory),
        RecorderChoice::Real => Arc::new(
            gateway_core::ssh::recorder::RecorderFactoryImpl::new(
                cpauth.clone(),
                config.recorder.clone(),
            )
            .expect("build recorder factory"),
        ),
    };

    // Session Ten: the lock deny-set + live-session registry, plus the background
    // lock-feed client streaming from the mock CP's LockFeed. The feed keeps the
    // set healthy (so per-channel checks serve cached allows within decision_ttl)
    // and pushes locks that tear down matching live sessions.
    let lock_set = Arc::new(LockSet::new(
        config.reeval.lock_feed_unhealthy_after_secs,
        config.reeval.lock_expiry_skew_secs,
    ));
    let live_sessions = Arc::new(LiveSessionRegistry::default());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    std::mem::forget(shutdown_tx); // test-only: keep the feed alive for the test.
    LockFeedClientTask::new(
        factory,
        lock_set.clone(),
        live_sessions.clone(),
        Duration::from_secs(config.reeval.lock_feed_connect_timeout_secs),
    )
    .spawn(shutdown_rx);
    // Wait for the first snapshot so the feed is healthy before the test drives
    // SSH — deterministic (no spurious first-channel re-authorize).
    for _ in 0..200 {
        if lock_set.healthy() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    (
        HandlerDeps {
            cpauth,
            connector,
            resolver: Arc::new(IdentityResolver),
            recorder_factory,
            finalize_tracker: gateway_core::ssh::recorder::FinalizeTracker::default(),
            lock_set,
            live_sessions,
            config,
        },
        credential,
    )
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
