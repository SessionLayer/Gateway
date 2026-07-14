//! Gateway runtime configuration.
//!
//! Session One carried only the async-I/O backend and the dev-plaintext CP
//! endpoint. Session Four adds the mTLS control plane: the CP's mTLS endpoint,
//! the credential data-dir, the operator-provided bootstrap credential, and the
//! renew-ahead knobs (§8.1). It grows as subsystems land.

use crate::asyncio::IoBackend;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Gateway configuration.
///
/// `deny_unknown_fields` makes misconfiguration fail closed: a misspelled or
/// unrecognised key is an error, not a silently-ignored setting that leaves a
/// (possibly security-relevant) default in place.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayConfig {
    /// Which async-I/O reactor to request for the byte-copy hot path. A `uring`
    /// request degrades to epoll when io_uring is unavailable (deny-safe).
    pub io_backend: IoBackend,
    /// Legacy CP gRPC endpoint (plaintext, dev-only) used by the Session One
    /// handshake smoke. The production plane is [`Self::cp_mtls_endpoint`].
    pub cp_endpoint: String,
    /// CP mTLS gRPC endpoint (`https://host:port`, TLS 1.3). All authenticated
    /// RPCs — renew + sign — go here; enroll + negotiate use the same endpoint
    /// with server-auth-only TLS (the bootstrap exception, VERSIONING §7).
    pub cp_mtls_endpoint: String,
    /// Directory that holds the persisted mTLS credential (leaf + key + CA chain
    /// + generation) and the single-writer lock. Created on first enrollment.
    pub data_dir: PathBuf,
    /// Bootstrap credential. `None` leaves the Gateway un-enrolled (the Session
    /// One scaffold behaviour — no CP calls). `Some` drives enroll-on-start.
    pub bootstrap: Option<BootstrapConfig>,
    /// mTLS identity lifecycle knobs (renew-ahead + bounded RPC timeouts).
    pub identity: IdentityConfig,
    /// Outer SSH-leg server (Session Seven). A blank `listen_addr` leaves it
    /// disabled (scaffold mode); set it to run the SSH front door.
    pub ssh: SshServerConfig,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            io_backend: IoBackend::Epoll,
            cp_endpoint: "http://127.0.0.1:9090".to_string(),
            cp_mtls_endpoint: "https://127.0.0.1:9443".to_string(),
            data_dir: PathBuf::from("/var/lib/sessionlayer-gateway"),
            bootstrap: None,
            identity: IdentityConfig::default(),
            ssh: SshServerConfig::default(),
        }
    }
}

/// Outer SSH-leg server configuration (Session Seven).
///
/// The Gateway's SSH front door: the listener, host key, source-IP controls
/// (PROXY v2 + the global CIDR gate), auth/device-flow timing, the target
/// separator, and the fail-closed CP RPC bounds. All knobs are set here (no
/// deferrals) with security-relevant defaults; misconfiguration fails closed
/// (`deny_unknown_fields`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshServerConfig {
    /// TCP listen address (`host:port`). **Empty disables the SSH server** (the
    /// scaffold default). Behind an L4 LB, bind `0.0.0.0:22` and set
    /// [`Self::proxy`]`.lb_cidrs`.
    pub listen_addr: String,
    /// Path to the persisted OpenSSH host key (ed25519). When empty, an ephemeral
    /// host key is generated at startup (fine for tests; a fixed key avoids
    /// client host-key churn in production).
    pub host_key_path: PathBuf,
    /// Generous login grace / inactivity bound (seconds) covering the whole outer
    /// handshake **including a slow OIDC device flow** (Design §5.2). Maps to
    /// russh's `inactivity_timeout`. Must exceed [`DeviceFlowConfig::poll_timeout_secs`].
    pub login_grace_secs: u64,
    /// Tier-0 bound (seconds) on reading the PROXY v2 header before the SSH
    /// banner, so a peer that connects and stalls cannot hold an accept slot.
    pub handshake_timeout_secs: u64,
    /// Tier-0 bound on concurrently-handshaking connections. A connection over
    /// the cap is dropped at accept (bounded resource use on the accept path).
    pub max_connections: usize,
    /// Per-connection cap on credential-**resolution** attempts (pin/cert/OTP),
    /// each of which is one CP RPC. Bounds the CP-RPC amplification a single
    /// unauthenticated connection can drive (russh does not enforce its own
    /// `max_auth_attempts`). After the cap the connection is hard-rejected.
    pub max_auth_attempts: usize,
    /// PROXY protocol v2 / LB trust (FR-AUTH-14).
    pub proxy: ProxyProtocolConfig,
    /// Global source-IP allow-list gate (FR-AUTH-13), evaluated at TCP accept
    /// against the PROXY-derived real client IP, **before any SSH banner**. Empty
    /// = gate disabled (allow all); a non-empty list drops any source outside it.
    /// CIDRs, e.g. `["10.0.0.0/8", "2001:db8::/32"]`.
    pub source_ip_allowlist: Vec<String>,
    /// The username-encoding target separator (`login%node`, Design §11). `%` by
    /// default; wildcard-DNS and ProxyJump host-cert modes are Session Sixteen.
    pub target_separator: char,
    /// OIDC device-flow presentation + polling knobs (FR-AUTH-4).
    pub device_flow: DeviceFlowConfig,
    /// Bound (seconds) on establishing the CP mTLS transport for an auth/authorize
    /// RPC (fail-closed, §10.3/NFR-2).
    pub cp_connect_timeout_secs: u64,
    /// Per-RPC deadline (seconds) on every OuterLegAuth/Authorize call
    /// (fail-closed): a hung CP never hangs the SSH handshake.
    pub cp_rpc_timeout_secs: u64,
    /// Inner leg (Session Eight): the agentless dial + SSH-client-to-node bounds.
    pub inner: InnerLegServerConfig,
    /// Session recorder (Session Nine): capture + customer-key encryption + the
    /// WORM upload. Strict by default (recording is mandatory; a failure fails the
    /// session closed).
    pub recorder: RecorderConfig,
    /// Per-channel re-evaluation, the actively-pushed lock deny-list, and
    /// mid-session identity-expiry policy (Session Ten, Design §6.3/§8.4).
    pub reeval: ReevalConfig,
    /// Break-glass access model (Session Thirteen, Design §7, FR-ACC-6/8): the
    /// always-available, IdP-independent override path (FIDO2 `sk-ecdsa` primary,
    /// offline codes fallback) and its per-model mid-session-expiry behaviour.
    pub break_glass: BreakGlassConfig,
    /// Outbound-agent transport (Session Fourteen, Design §9.2/§10.2): the
    /// agent-facing WebSocket listener, the dial-back token/timeout bounds, and the
    /// liveness cadence. A blank `listen_addr` leaves the transport OFF (agentless
    /// only) — mirroring the [`SshServerConfig::listen_addr`] convention.
    pub agent: AgentTransportConfig,
}

/// The agent-facing WebSocket transport (Session Fourteen; contract
/// `agent-gateway-v1.md`). The Agent dials **out** to this listener over TLS 1.3 with
/// mutual TLS and registers a control channel; the Gateway signals it to dial back for
/// each session. All bounds are fail-closed and validated at startup
/// (`ssh::validate_config`); `deny_unknown_fields` fails misconfiguration closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentTransportConfig {
    /// TCP listen address (`host:port`) for the agent WSS transport. **Empty
    /// disables it** (the default): an `OUTBOUND_AGENT` node is then simply offline.
    /// Dev port is `9444` (the CP mTLS gRPC plane is `9443`).
    pub listen_addr: String,
    /// The `wss://` URL the Gateway tells an Agent to dial back to (contract §5:
    /// the address rides in the signal, so no service discovery is needed). When
    /// empty it is derived from [`Self::listen_addr`].
    pub advertise_url: String,
    /// PING cadence (seconds) on the control channel. **Two missed intervals ⇒ the
    /// peer is dead**: the Gateway deregisters the agent and its node becomes
    /// unreachable (§7.1).
    pub heartbeat_interval_secs: u64,
    /// The maximum frame payload either peer may send (DoS bound, negotiated in
    /// `HELLO_ACK`). MUST exceed [`InnerLegServerConfig::max_packet_bytes`] so a
    /// full inner-leg SSH packet always fits in one frame.
    pub max_frame_bytes: usize,
    /// TTL (seconds) of a minted dial-back token. MUST exceed
    /// [`Self::dial_back_timeout_secs`]: the token has to outlive the window in
    /// which it may legitimately be redeemed.
    pub dial_back_token_ttl_secs: i64,
    /// How long (seconds) the connector waits for the signalled Agent to reach
    /// `STREAM_OPEN` before failing closed to "node offline" (FR-SESS-5).
    pub dial_back_timeout_secs: u64,
    /// Bound (seconds) on the whole TLS + WebSocket + preface handshake, so a peer
    /// that connects and stalls cannot hold a slot.
    pub handshake_timeout_secs: u64,
    /// Cap on live agent control channels (bounded resource use).
    pub max_agents: usize,
}

impl Default for AgentTransportConfig {
    fn default() -> Self {
        Self {
            listen_addr: String::new(),
            advertise_url: String::new(),
            heartbeat_interval_secs: 20,
            max_frame_bytes: 64 * 1024,
            dial_back_token_ttl_secs: 30,
            dial_back_timeout_secs: 10,
            handshake_timeout_secs: 10,
            max_agents: 1024,
        }
    }
}

/// Break-glass access-model policy (Session Thirteen; Design §7, FR-ACC-6/8). The
/// break-glass auth is resolved by the CP (FIDO2 key / offline code); this block
/// only governs whether the Gateway offers the path and how a live break-glass
/// session behaves at grant expiry. Strict recording is ALWAYS forced for a
/// break-glass session regardless of these knobs. `deny_unknown_fields` fails
/// misconfiguration closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BreakGlassConfig {
    /// Whether this Gateway offers the break-glass auth paths at all. Default
    /// `true` (break-glass is always-available by design, FR-ACC-6); an operator
    /// can hard-disable it, in which case a break-glass credential simply does not
    /// resolve and the connection degrades like any other unresolved credential.
    pub enabled: bool,
    /// Mid-session identity-expiry behaviour for a break-glass session (FR-ACC-8),
    /// selected per access model separately from [`ReevalConfig::mid_session_expiry`]
    /// (which governs standing/JIT). Defaults to `grace_then_kill`: a break-glass
    /// session is time-boxed and cut a grace window after its grant expires rather
    /// than running to the idle timeout. A Lock ALWAYS overrides with immediate
    /// teardown regardless of this.
    pub mid_session_expiry: MidSessionExpiryMode,
}

impl Default for BreakGlassConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mid_session_expiry: MidSessionExpiryMode::GraceThenKill,
        }
    }
}

/// Per-channel-open re-evaluation, lock-feed health, and mid-session-expiry policy
/// (Session Ten; Design §6.3/§8.3/§8.4; FR-CHAN-2/3/4, FR-ACC-8, FR-LOCK-1/2). All
/// fail-closed; misconfiguration is rejected (`deny_unknown_fields`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReevalConfig {
    /// Hard ceiling (seconds) on the CP-supplied `decision_ttl` a cached allow may
    /// be served for before a forced re-authorize — defense against a CP that
    /// hands out an over-long TTL. The effective TTL is `min(context.decision_ttl,
    /// this)`, and `0` when the lock feed is unhealthy (forces per-channel
    /// re-validate, FR-CHAN-4).
    pub max_decision_ttl_secs: i64,
    /// Conservative clock-skew margin (seconds) applied to `grant_expiry`: a grant
    /// expires EARLY (`now + skew >= grant_expiry` refuses new privileged channels),
    /// per FR-BOOT-4.
    pub grant_expiry_skew_secs: i64,
    /// Conservative clock-skew margin (seconds) applied to a LOCK's expiry: a deny
    /// expires LATE (the lock keeps denying until clearly past its TTL) — the
    /// opposite direction, because deny must fail closed (§8.4).
    pub lock_expiry_skew_secs: i64,
    /// The lock feed is marked unhealthy if idle (no event or heartbeat) longer
    /// than this. Unhealthy → per-channel re-validate is forced (`decision_ttl` is
    /// treated as 0). Should be a small multiple of the CP heartbeat interval.
    pub lock_feed_unhealthy_after_secs: u64,
    /// Bound (seconds) on establishing the lock-feed mTLS stream (fail-closed dial).
    pub lock_feed_connect_timeout_secs: u64,
    /// What happens to a LIVE session when its `grant_expiry` passes. A Lock ALWAYS
    /// overrides this with immediate teardown (FR-ACC-8).
    pub mid_session_expiry: MidSessionExpiryMode,
    /// Grace window (seconds) for [`MidSessionExpiryMode::GraceThenKill`] between
    /// `grant_expiry` and teardown.
    pub mid_session_grace_secs: u64,
}

/// Mid-session identity-expiry behaviour per access model (FR-ACC-8). In all modes
/// a NEW privileged channel-open is refused once `grant_expiry` passes; the modes
/// differ only in what happens to already-open channels. A Lock always overrides
/// with immediate teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MidSessionExpiryMode {
    /// Let in-flight channels run to their natural close; only refuse new channels
    /// after expiry. The least-disruptive default for a stable STANDING identity.
    RunToTtl,
    /// At `grant_expiry`, wait [`ReevalConfig::mid_session_grace_secs`], then tear
    /// the session down.
    GraceThenKill,
    /// Tear the session down immediately at `grant_expiry`.
    HardKill,
}

impl Default for ReevalConfig {
    fn default() -> Self {
        Self {
            max_decision_ttl_secs: 60,
            grant_expiry_skew_secs: 30,
            lock_expiry_skew_secs: 30,
            lock_feed_unhealthy_after_secs: 30,
            lock_feed_connect_timeout_secs: 5,
            mid_session_expiry: MidSessionExpiryMode::RunToTtl,
            mid_session_grace_secs: 30,
        }
    }
}

/// Session-recorder configuration (Session Nine, Design §12/§12A/§15).
///
/// Every session is captured (keystrokes + output), encrypted under a
/// customer-held key, hash-chained, and uploaded to a WORM store. Recording is
/// **mandatory** (FR-AUD-1/2): in [`Self::strict`] mode (the default) a
/// recording setup/continuation/upload failure refuses or tears down the session
/// (fail closed). `deny_unknown_fields` makes misconfiguration fail closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecorderConfig {
    /// Strict mode (default `true`): a recording setup/continuation failure
    /// refuses the session ([`SshOutcome::RecordingUnavailable`]) rather than
    /// running it unrecorded. Non-strict proceeds in a documented degraded mode
    /// (logs loudly; never silently drops). Break-glass forcing strict is S11.
    ///
    /// [`SshOutcome::RecordingUnavailable`]: crate::ssh::outcome::SshOutcome::RecordingUnavailable
    pub strict: bool,
    /// Directory for the **ciphertext** spool file (used once a recording exceeds
    /// [`Self::spool_memory_threshold_bytes`]). `None` uses the system temp dir.
    /// Plaintext is NEVER written here — only sealed frames (§3/§15).
    pub spool_dir: Option<PathBuf>,
    /// Ciphertext bytes held in memory before spilling to a temp file. Enforced
    /// ALWAYS (a large recording spills even with no `spool_dir`), bounding Gateway
    /// RAM per session.
    pub spool_memory_threshold_bytes: usize,
    /// Hard cap on a single recording's ciphertext object. Exceeding it fails
    /// closed (strict: tear the session down; non-strict: stop recording loudly) —
    /// an unbounded session can never OOM the Gateway.
    pub max_object_bytes: u64,
    /// Plaintext bytes buffered before a frame is sealed + flushed. Larger frames
    /// mean less per-frame AEAD overhead; smaller frames bound the plaintext held
    /// in memory on the hot path.
    pub frame_plaintext_bytes: usize,
    /// Bound (seconds) on the whole ciphertext PUT to the presigned WORM URL
    /// (fail-closed): a hung object store never hangs finalize forever.
    pub upload_timeout_secs: u64,
    /// Max attempts (incl. the first) for the end-of-session RequestUpload + PUT.
    /// A transient store fault is retried with exponential backoff; the recording
    /// is marked failed only after these are exhausted (fail-closed, never silent).
    pub upload_max_attempts: u32,
    /// Require the WORM store URL to be **https** in production. Set `false` only
    /// for the plain-http MinIO E2E; a plain-http upload is otherwise refused.
    pub require_https: bool,
    /// Optional PEM trust anchor for an **https** WORM store (prod). When the
    /// presigned URL is https and this is empty, the upload fails closed (no
    /// implicit web-PKI roots — supply-chain policy). Plain-http upload (the E2E
    /// MinIO) ignores it.
    pub upload_ca_pem_path: Option<PathBuf>,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            strict: true,
            spool_dir: None,
            spool_memory_threshold_bytes: 8 * 1024 * 1024,
            max_object_bytes: 4 * 1024 * 1024 * 1024,
            frame_plaintext_bytes: 16 * 1024,
            upload_timeout_secs: 30,
            upload_max_attempts: 4,
            require_https: true,
            upload_ca_pem_path: None,
        }
    }
}

/// Inner-leg (node-facing) bounds — the agentless dial, the inner SSH handshake,
/// flow-control sizing, and the Tier-0 post-auth idle bound (Session Eight,
/// Design §9). All fail-closed; misconfiguration is rejected (`deny_unknown_fields`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InnerLegServerConfig {
    /// Bound (seconds) on the agentless TCP dial to `node:22`. An unreachable
    /// node fails closed as "node offline" (§7.1 post-authz).
    pub connect_timeout_secs: u64,
    /// Bound (seconds), applied per step, on the inner SSH transport handshake,
    /// **userauth** (cert auth), and **channel-open + replay** to the node — each
    /// node round-trip after the dial. Fail-closed: a node that stalls at any step
    /// aborts to "node offline" rather than parking on the idle timer.
    pub handshake_timeout_secs: u64,
    /// Inner-channel initial window (bytes) — flow control / bridge backpressure.
    pub window_bytes: u32,
    /// Inner-channel maximum packet size (bytes).
    pub max_packet_bytes: u32,
    /// Tier-0 idle bound (seconds) on a live bridged session (russh
    /// `inactivity_timeout`, both legs). Must be ≥ [`SshServerConfig::login_grace_secs`]
    /// so the pre-auth deadline (a separate watchdog) governs the unauthenticated
    /// window and this governs the authenticated one.
    pub max_session_idle_secs: u64,
    /// Tier-0 cap on the number of session channels one connection may open
    /// (bounds pump tasks + node channels + flow-control buffers). A local
    /// resource bound, distinct from the S10 concurrent-session policy limit.
    pub max_channels_per_connection: usize,
}

impl Default for InnerLegServerConfig {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 5,
            handshake_timeout_secs: 10,
            window_bytes: 2 * 1024 * 1024,
            max_packet_bytes: 32 * 1024,
            max_session_idle_secs: 900,
            max_channels_per_connection: 16,
        }
    }
}

impl Default for SshServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: String::new(),
            host_key_path: PathBuf::new(),
            // Generous: covers a human completing an OIDC device flow in a browser.
            login_grace_secs: 300,
            handshake_timeout_secs: 10,
            max_connections: 512,
            max_auth_attempts: 6,
            proxy: ProxyProtocolConfig::default(),
            source_ip_allowlist: Vec::new(),
            target_separator: '%',
            device_flow: DeviceFlowConfig::default(),
            cp_connect_timeout_secs: 5,
            cp_rpc_timeout_secs: 10,
            inner: InnerLegServerConfig::default(),
            recorder: RecorderConfig::default(),
            reeval: ReevalConfig::default(),
            break_glass: BreakGlassConfig::default(),
            agent: AgentTransportConfig::default(),
        }
    }
}

/// PROXY protocol v2 trust (FR-AUTH-14): the real client IP is taken from a
/// PROXY v2 header, trusted **only** when the immediate TCP peer is inside a
/// configured LB CIDR. Fail-closed both ways.
///
/// - `lb_cidrs` **empty** — PROXY protocol is OFF; the immediate TCP peer IP is
///   the source (single-instance / dev, FR-HA-1; no LB in front).
/// - `lb_cidrs` **non-empty** — PROXY protocol is REQUIRED. A connection from an
///   LB peer must carry a valid PROXY v2 header (missing/malformed → rejected);
///   a connection from a non-LB peer is rejected (a header from it would be a
///   spoof, its absence a bypass of the LB). Both directions fail closed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyProtocolConfig {
    /// Trusted load-balancer CIDRs. See the type docs for the fail-closed matrix.
    pub lb_cidrs: Vec<String>,
}

/// OIDC device-flow presentation + polling (FR-AUTH-4, Design §5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceFlowConfig {
    /// Heartbeat interval (seconds) between `num-prompts=0` keyboard-interactive
    /// info-requests while polling the CP — below the tightest stock-client idle
    /// timeout so the connection stays alive (FR-AUTH-4). ~10 s.
    pub heartbeat_interval_secs: u64,
    /// Overall device-flow poll deadline (seconds). On expiry the user gets the
    /// §7.1 "authentication timed out, please reconnect" outcome. Must be less
    /// than [`SshServerConfig::login_grace_secs`].
    pub poll_timeout_secs: u64,
}

impl Default for DeviceFlowConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 10,
            poll_timeout_secs: 180,
        }
    }
}

/// Operator-provided bootstrap credential (§2A "Gateway↔CP trust", §4.B).
///
/// The Gateway has no CP-issued client certificate before enrollment, so it
/// authenticates `EnrollGateway` with a single-use token and trusts the CP's
/// server certificate against an operator-provided anchor (the bootstrap CA /
/// server-CA pin). Both are secrets/roots supplied out-of-band (env / file);
/// never commit them.
/// Deliberately NOT `#[derive(Debug)]`: it holds the bearer enrollment token, so
/// [`Debug`] is implemented manually to **redact** it (no accidental secret in a
/// config dump / log). The token lives in a [`Zeroizing`] buffer, scrubbed on
/// drop.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BootstrapConfig {
    /// The single-use, short-TTL enrollment token (bearer, `EnrollGateway`
    /// only). Sourced from the environment in real deployments. Held in a
    /// scrub-on-drop buffer; never logged.
    #[serde(with = "crate::secret::serde_zeroizing_string")]
    pub enrollment_token: Zeroizing<String>,
    /// Path to a PEM file with the CA (or exact server cert) the Gateway pins to
    /// verify the CP's server certificate pre-enrollment. This is the sole trust
    /// anchor for the bootstrap channel; a wrong-CA / unpinned server is refused.
    pub ca_cert_path: PathBuf,
    /// The stable Gateway name the token was provisioned for. Bound into the CSR
    /// subject + the issued cert SAN; a mismatch fails closed.
    pub gateway_name: String,
    /// Server name (SNI / SAN) to verify the CP server certificate against. When
    /// empty, the host of [`GatewayConfig::cp_mtls_endpoint`] is used.
    pub server_name: String,
}

impl std::fmt::Debug for BootstrapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the bearer token.
        f.debug_struct("BootstrapConfig")
            .field("enrollment_token", &"<redacted>")
            .field("ca_cert_path", &self.ca_cert_path)
            .field("gateway_name", &self.gateway_name)
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            enrollment_token: Zeroizing::new(String::new()),
            ca_cert_path: PathBuf::new(),
            gateway_name: String::new(),
            server_name: String::new(),
        }
    }
}

/// mTLS identity lifecycle configuration (§8.1 renew-ahead).
///
/// The renew-ahead trigger fires when a configurable fraction of the certificate
/// TTL has elapsed, jittered to de-synchronise a fleet, so renewal completes
/// well before expiry. Defaults renew at 2/3 elapsed (≈1/3 remaining) with ±10%
/// jitter. Made fully configurable so tests drive a short TTL / manual trigger
/// rather than sleeping for real hours.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityConfig {
    /// Fraction of the cert TTL that must elapse before renew-ahead fires
    /// (`0.0..1.0`). Default `0.667` → renew when ~1/3 of the TTL remains.
    pub renew_ahead_fraction: f64,
    /// Jitter as a fraction of the TTL applied to the trigger (`±`), to spread a
    /// fleet's renewals. Default `0.1` (±10%).
    pub renew_jitter_fraction: f64,
    /// On startup, renew immediately if the remaining TTL fraction is at or below
    /// this. Default `0.5` — an identity loaded near expiry refreshes at once.
    pub startup_renew_below_fraction: f64,
    /// Bound on establishing the gRPC transport to the CP (fail-closed, §10.3).
    pub connect_timeout_secs: u64,
    /// Per-RPC deadline (fail-closed): a hung CP never hangs the Gateway.
    pub rpc_timeout_secs: u64,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            renew_ahead_fraction: 2.0 / 3.0,
            renew_jitter_fraction: 0.1,
            startup_renew_below_fraction: 0.5,
            connect_timeout_secs: 5,
            rpc_timeout_secs: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_epoll_on_dev_endpoint_unenrolled() {
        let cfg = GatewayConfig::default();
        assert_eq!(cfg.io_backend, IoBackend::Epoll);
        assert_eq!(cfg.cp_endpoint, "http://127.0.0.1:9090");
        assert_eq!(cfg.cp_mtls_endpoint, "https://127.0.0.1:9443");
        assert!(cfg.bootstrap.is_none(), "un-enrolled by default");
        assert!((cfg.identity.renew_ahead_fraction - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!(cfg.identity.connect_timeout_secs, 5);
    }

    #[test]
    fn deserialises_partial_config_with_defaults() {
        // Only io_backend given; the rest fall back to defaults.
        let cfg: GatewayConfig = serde_json::from_str(r#"{"io_backend":"uring"}"#).unwrap();
        assert_eq!(cfg.io_backend, IoBackend::Uring);
        assert_eq!(cfg.cp_mtls_endpoint, "https://127.0.0.1:9443");
    }

    #[test]
    fn deserialises_bootstrap_block() {
        let cfg: GatewayConfig = serde_json::from_str(
            r#"{"bootstrap":{"enrollment_token":"t","ca_cert_path":"/etc/cp-ca.pem","gateway_name":"gw-1","server_name":"cp.internal"}}"#,
        )
        .unwrap();
        let b = cfg.bootstrap.expect("bootstrap present");
        assert_eq!(b.gateway_name, "gw-1");
        assert_eq!(b.server_name, "cp.internal");
    }

    #[test]
    fn unknown_key_fails_closed() {
        // A misspelled key must error, not be silently dropped.
        let result: Result<GatewayConfig, _> = serde_json::from_str(r#"{"io_back_end":"uring"}"#);
        assert!(result.is_err(), "unknown config key must be rejected");
    }

    #[test]
    fn unknown_nested_key_fails_closed() {
        let result: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"identity":{"renew_ahead":0.5}}"#);
        assert!(result.is_err(), "unknown nested key must be rejected");
    }

    #[test]
    fn ssh_defaults_are_disabled_with_safe_bounds() {
        let cfg = GatewayConfig::default();
        assert!(cfg.ssh.listen_addr.is_empty(), "SSH server off by default");
        assert_eq!(cfg.ssh.target_separator, '%');
        assert!(cfg.ssh.proxy.lb_cidrs.is_empty(), "PROXY off by default");
        assert!(
            cfg.ssh.source_ip_allowlist.is_empty(),
            "gate off by default"
        );
        // The device flow must fit inside the login grace window.
        assert!(cfg.ssh.device_flow.poll_timeout_secs < cfg.ssh.login_grace_secs);
        assert_eq!(cfg.ssh.device_flow.heartbeat_interval_secs, 10);
    }

    #[test]
    fn ssh_unknown_key_fails_closed() {
        let result: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"ssh":{"listen_port":22}}"#);
        assert!(result.is_err(), "unknown ssh key must be rejected");
    }

    #[test]
    fn recorder_defaults_are_strict() {
        // Recording is mandatory: the recorder defaults to strict (fail closed) and
        // to an in-memory ciphertext spool (no plaintext ever touches disk).
        let cfg = GatewayConfig::default();
        assert!(cfg.ssh.recorder.strict, "recording must default to strict");
        assert!(cfg.ssh.recorder.spool_dir.is_none());
        assert!(cfg.ssh.recorder.upload_ca_pem_path.is_none());
        assert!(cfg.ssh.recorder.frame_plaintext_bytes > 0);
        assert!(cfg.ssh.recorder.upload_timeout_secs > 0);
    }

    #[test]
    fn recorder_unknown_key_fails_closed() {
        // A misspelled recorder key must error (fail closed), not leave the default
        // (possibly security-relevant, e.g. `strict`) silently in place.
        let result: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"ssh":{"recorder":{"strickt":false}}}"#);
        assert!(result.is_err(), "unknown recorder key must be rejected");
    }

    #[test]
    fn break_glass_defaults_enabled_grace_then_kill() {
        let cfg = GatewayConfig::default();
        assert!(cfg.ssh.break_glass.enabled, "break-glass on by default");
        assert_eq!(
            cfg.ssh.break_glass.mid_session_expiry,
            MidSessionExpiryMode::GraceThenKill
        );
    }

    #[test]
    fn break_glass_unknown_key_fails_closed() {
        let result: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"ssh":{"break_glass":{"enable":false}}}"#);
        assert!(result.is_err(), "unknown break_glass key must be rejected");
    }

    #[test]
    fn agent_transport_is_off_by_default_with_fail_closed_bounds() {
        let a = GatewayConfig::default().ssh.agent;
        assert!(a.listen_addr.is_empty(), "agent transport off by default");
        assert_eq!(a.heartbeat_interval_secs, 20);
        assert_eq!(a.max_frame_bytes, 64 * 1024);
        assert_eq!(a.dial_back_token_ttl_secs, 30);
        assert_eq!(a.dial_back_timeout_secs, 10);
        assert_eq!(a.max_agents, 1024);
        // The two ordering invariants validate_config enforces hold at the defaults.
        assert!((a.dial_back_timeout_secs as i64) < a.dial_back_token_ttl_secs);
        assert!(a.max_frame_bytes > InnerLegServerConfig::default().max_packet_bytes as usize);
    }

    #[test]
    fn agent_unknown_key_fails_closed() {
        let result: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"ssh":{"agent":{"listen_address":"0.0.0.0:9444"}}}"#);
        assert!(result.is_err(), "unknown agent key must be rejected");
    }

    #[test]
    fn recorder_strict_can_be_disabled_explicitly() {
        let cfg: GatewayConfig =
            serde_json::from_str(r#"{"ssh":{"recorder":{"strict":false}}}"#).unwrap();
        assert!(!cfg.ssh.recorder.strict);
        // The rest of the recorder block keeps its (strict-adjacent) defaults.
        assert!(cfg.ssh.recorder.spool_dir.is_none());
    }
}
