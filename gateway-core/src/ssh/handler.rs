//! The outer-leg russh [`Handler`] (Session Seven, Parts C/E/F/G).
//!
//! One instance per SSH connection. It advertises `publickey` +
//! `keyboard-interactive` and negotiates authentication **by delegating every
//! decision to the CP** (the Gateway is a thin PEP):
//!
//! - a presented **publickey certificate** → `ResolveUserCert` (Vault-user-cert),
//! - a plain **publickey** → `ResolvePin` (by SHA-256 fingerprint),
//! - **keyboard-interactive** → prompt for a pre-issued **OTP** → `ResolveOtp`,
//!   then fall back to the **OIDC device flow** (`Begin`/`PollDeviceFlow`),
//!   presented as the URL + code in the `instruction` field with `num-prompts=0`
//!   heartbeats (FR-AUTH-3/4).
//!
//! The offered method selects the path; an unresolved credential **degrades to
//! the next method** (FR-AUTH-1/2). On a resolved identity the Gateway parses the
//! target (`login%node`, Part G), applies the credential-principal reducer
//! (deny-only), then calls S5 **`Authorize`**. On ALLOW (Session Eight) it dials
//! the node via the [`NodeConnector`], mints the inner cert, verifies the node
//! host identity (no TOFU), and **bridges** the two legs per channel (shell / exec
//! / SFTP) under the granted capability set; a denial or node fault closes the
//! channel with the §7.1 outcome. Every SSH-surface outcome follows the §7.1
//! taxonomy ([`SshOutcome`]); no secret/OTP/token/plaintext is ever logged.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use russh::keys::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};
use russh::server::{Auth, Handler, Response, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty};
use zeroize::Zeroizing;

use crate::config::MidSessionExpiryMode;
use crate::config::SshServerConfig;
use crate::cpauth::{CpAuthClient, CpError};
use crate::decisionctx;
use crate::pb::{
    AccessModel, AuthorizeRequest, Capability, ConnectorKind, Decision, DecisionContext,
    DeviceFlowStatus, ResolvedIdentity, SignContext,
};
use crate::signing::InnerKeyPair;
use crate::ssh::bridge::{
    self, RecChannelKind, RecorderFactory, RecorderTap, RecordingParams, SessionRecorder,
    TapDirection,
};
use crate::ssh::connector::{NodeConnector, NodeDial, NodeTarget, SessionGrant};
use crate::ssh::hostverify::{HostTrust, HostVerifier};
use crate::ssh::innerleg::{
    ChannelKind, InnerClient, InnerLegConfig, InnerLegError, InnerWriteHalf, PtyParams,
};
use crate::ssh::locks::{LiveSessionRegistry, LockBindings, LockSet, SessionControl, SessionGuard};
use crate::ssh::outcome::{SshOutcome, DEVICE_FLOW_TIMEOUT, SERVICE_UNAVAILABLE};
use crate::ssh::target::{parse_username, strip_dns_suffix, Target, TargetResolver};
use crate::version;

/// Per-connection state shared with the accept loop: whether authentication
/// completed (arms/disarms the pre-auth deadline), whether the CP was seen down,
/// and the coarse methods tried (for one consolidated auth-failed record). The
/// accept loop reads it after the session ends; the handler writes it.
#[derive(Default)]
pub struct ConnState {
    /// Set in `auth_succeeded`; disarms the pre-auth deadline watchdog.
    pub authenticated: AtomicBool,
    /// Set when any CP call failed as CP-down (§7.1 fail-closed).
    pub cp_unavailable: AtomicBool,
    /// Coarse method labels attempted (no secrets), for the auth-failed record.
    pub methods_tried: Mutex<Vec<&'static str>>,
}

impl ConnState {
    fn record_method(&self, m: &'static str) {
        let mut v = self.methods_tried.lock().unwrap();
        if !v.contains(&m) {
            v.push(m);
        }
    }
}

/// Which method authenticated the connection (for the decision log).
#[derive(Debug, Clone, Copy)]
enum AuthMethod {
    UserCert,
    Pin,
    Otp,
    DeviceFlow,
    /// Break-glass (Design §7, FR-ACC-6): a FIDO2 `sk-ecdsa` key or a single-use
    /// offline code, resolved by the CP independent of the primary OIDC IdP.
    BreakGlass,
}

/// The CP-resolved authenticated identity (authentication only; authorization is
/// a separate CP call at channel time).
struct Authenticated {
    identity: String,
    /// Credential-scoped logins (deny-only reducer applied at authorize time).
    principals: Vec<String>,
    groups: Vec<String>,
    method: AuthMethod,
}

/// The keyboard-interactive state machine: OTP first, then the device flow.
enum KiState {
    Start,
    AwaitingOtp,
    Device {
        device_code: String,
        deadline: Instant,
    },
    TimedOut,
}

/// Shared, per-server dependencies cloned into each connection handler.
#[derive(Clone)]
pub struct HandlerDeps {
    /// The CP auth/authorize client (Part D) + the inner-cert signer (Part B).
    pub cpauth: Arc<CpAuthClient>,
    /// The inner-leg connector seam (Session Eight: [`AgentlessDial`]).
    ///
    /// [`AgentlessDial`]: crate::ssh::connector::AgentlessDial
    pub connector: Arc<dyn NodeConnector>,
    /// The target `node`-name → node-id resolver (Session-Sixteen seam).
    pub resolver: Arc<dyn TargetResolver>,
    /// The per-session recorder factory (Session Nine): builds ONE recorder per
    /// authorized session (holding its data key, asciicast stream, SFTP decoder,
    /// hash-chain, ciphertext spool, uploader).
    pub recorder_factory: Arc<dyn RecorderFactory>,
    /// Tracks in-flight recording finalizes so a graceful shutdown can await them
    /// (Session Nine, #3). Cheap to clone (an `Arc`).
    pub finalize_tracker: crate::ssh::recorder::FinalizeTracker,
    /// The actively-pushed lock deny-set (Session Ten): consulted per channel-open
    /// (deny wins, datastore-independent) and carrying the feed-health signal.
    pub lock_set: Arc<LockSet>,
    /// Registry of live sessions so a pushed lock tears down matching ones
    /// (Session Ten, FR-LOCK-1).
    pub live_sessions: Arc<LiveSessionRegistry>,
    /// SSH server configuration (target separator, device-flow timing, inner-leg
    /// bounds, recorder policy, …).
    pub config: Arc<SshServerConfig>,
    /// ProxyJump host-cert MITM state (Session Sixteen, Part C): the Gateway's outer
    /// host key + per-node host-cert cache. `Some` only when `ssh.proxy_jump.enabled`;
    /// `None` ⇒ a `direct-tcpip` forward is refused (the pre-S16 behaviour).
    pub proxy_jump: Option<Arc<crate::ssh::proxyjump::ProxyJumpState>>,
}

/// A single SSH connection's handler. Not `Clone`: it owns per-connection state.
pub struct SshHandler {
    deps: HandlerDeps,
    /// The real client source IP (PROXY-derived, gate-checked before this exists).
    source_ip: IpAddr,
    /// The SessionLayer session id allocated for this connect.
    session_id: String,
    /// The root OTel span for this connection (`gateway.session`, OTEL-CONTRACT §3).
    /// Every CP RPC on this connection injects its W3C context; child spans
    /// (`gateway.node.connect`/`host_verify`/`bridge_setup`) parent to it. Carries
    /// IDs/enums/outcomes only — never plaintext/keys/tokens (OTEL-CONTRACT §5).
    session_span: tracing::Span,
    /// The SSH username (client-supplied; parsed as `login%node`, never trusted
    /// as a principal, sanitized before logging).
    username: Option<String>,
    /// Set on the INNER hop of a ProxyJump connection (Session Sixteen, Part C):
    /// the target node comes from the `direct-tcpip` request (already wildcard-DNS
    /// normalized), not the username, and the whole username is the login (no `%`
    /// parse). `None` on the normal outer leg (username-encoding / wildcard DNS).
    proxyjump_node: Option<String>,
    authenticated: Option<Authenticated>,
    /// True once a break-glass credential (FIDO2 key / offline code) authenticated
    /// this connection (Session Thirteen). Drives the break-glass Authorize + forced
    /// strict recording + the break-glass mid-session-expiry policy.
    break_glass: bool,
    /// The single-use break-glass token minted by the CP resolution, presented once
    /// as `AuthorizeRequest.breakglass_token`. Not a long-lived secret; never logged.
    breakglass_token: Option<String>,
    ki: KiState,
    /// The connect-time authorization result, decided once on the first channel
    /// request: either the allow (with the node connection + grant) or a cached
    /// denial outcome. `None` until the first channel request runs `decide`.
    authz: Option<Arc<Authorized>>,
    authz_denied: Option<SshOutcome>,
    /// The inner-leg client, established lazily once on the first authorized
    /// channel and shared by every channel on this connection.
    inner: Option<InnerClient>,
    /// A cached inner-leg failure outcome (so a second channel after a failed
    /// establish fails the same way without re-dialing).
    inner_failed: Option<SshOutcome>,
    /// The per-session recorder (Session Nine), created once when the session is
    /// authorized and shared by every channel. `None` until the first authorized
    /// channel runs; captures + encrypts + uploads the session recording.
    recorder: Option<Arc<dyn SessionRecorder>>,
    /// A cached strict-mode recording-setup failure (so a second channel fails the
    /// same way without re-attempting BeginRecording).
    recorder_failed: Option<SshOutcome>,
    /// PTY parameters stashed per channel (replayed to the node at channel start).
    pty: HashMap<ChannelId, PtyParams>,
    /// Retained outer channel objects (kept from `channel_open_session` so their
    /// write half can drive the backpressured node→client direction). The read
    /// half is dropped — outer→inner still flows via the `data` callback.
    pending_channels: HashMap<ChannelId, Channel<russh::server::Msg>>,
    /// Per-bridged-channel inner write half — the outer `data`/`eof`/window-change
    /// callbacks forward to it (outer → inner direction).
    writers: HashMap<ChannelId, InnerWriteHalf>,
    /// Per-bridged-channel inner→outer pump task, aborted on channel/connection
    /// close for deterministic teardown (no leak-until-disconnect).
    pumps: HashMap<ChannelId, tokio::task::JoinHandle<()>>,
    /// Count of session channels opened on this connection (Tier-0 cap, russh
    /// enforces none).
    channels_opened: usize,
    /// Count of credential-resolution attempts (bounds the CP-RPC amplification
    /// per connection — russh does NOT enforce its own `max_auth_attempts`).
    auth_attempts: usize,
    /// The shared session-abort flag (Session Ten): flipped by a lock/expiry
    /// teardown so the bridge + recorder stop plaintext at once. Shared into the
    /// recorder and the [`SessionControl`].
    session_abort: Option<Arc<AtomicBool>>,
    /// Deregisters this session from the live registry on connection end.
    live_guard: Option<SessionGuard>,
    /// This session's out-of-band teardown control (registered once).
    session_control: Option<SessionControl>,
    /// The mid-session identity-expiry timer (Part F), rearmed on re-authorize.
    expiry_task: Option<tokio::task::JoinHandle<()>>,
    /// Shared with the accept loop (pre-auth deadline + auth-failed record).
    conn: Arc<ConnState>,
}

/// A successful connect-time authorization: the node connection + host trust to
/// verify + the single-use grant to mint the inner cert + the granted capability
/// set. Built once in [`SshHandler::decide`], shared across channels.
struct Authorized {
    node: NodeTarget,
    dial: NodeDial,
    trust: HostTrust,
    grant: SessionGrant,
    /// The granted SSH capabilities (proto `Capability` values); default
    /// shell+exec if the decision context declares none (Design §6.1).
    capabilities: Vec<i32>,
    /// The single-use Recording.BeginRecording token minted alongside the session
    /// token (Session Nine, §12/§15). Empty when the CP predates S9.
    recording_token: String,
    /// The **signature-verified** decision context (Session Ten, Part A). The
    /// per-channel local checks run against this — never an unverified copy.
    context: DecisionContext,
    /// When the context was verified (Gateway clock). Bounds how long a cached
    /// allow is served before a forced re-authorize (`decision_ttl`).
    verified_at: Instant,
    /// The lock-matchable facts derived from `context` (Session Ten).
    bindings: LockBindings,
}

impl SshHandler {
    /// Construct a handler for a freshly-accepted, gate-passed connection.
    pub fn new(deps: HandlerDeps, source_ip: IpAddr, conn: Arc<ConnState>) -> Self {
        Self::with_proxyjump_node(deps, source_ip, conn, None)
    }

    /// Construct the handler for the INNER hop of a ProxyJump connection (Part C):
    /// the node is fixed by the `direct-tcpip` target, and the source IP + a fresh
    /// `ConnState` are inherited from the terminated outer jump connection.
    pub fn new_proxyjump(
        deps: HandlerDeps,
        source_ip: IpAddr,
        conn: Arc<ConnState>,
        node: String,
    ) -> Self {
        Self::with_proxyjump_node(deps, source_ip, conn, Some(node))
    }

    fn with_proxyjump_node(
        deps: HandlerDeps,
        source_ip: IpAddr,
        conn: Arc<ConnState>,
        proxyjump_node: Option<String>,
    ) -> Self {
        let session_id = new_session_id();
        // The trace root. `correlation_id` defaults to `session_id` (OTEL-CONTRACT
        // §1: the jit/break-glass ids that refine it are CP-side); `node_id`,
        // `access_model` and `outcome` are recorded once known. NO secret fields.
        let session_span = tracing::info_span!(
            "gateway.session",
            sessionlayer.session_id = %session_id,
            sessionlayer.correlation_id = %session_id,
            sessionlayer.node_id = tracing::field::Empty,
            sessionlayer.access_model = tracing::field::Empty,
            sessionlayer.outcome = tracing::field::Empty,
        );
        Self {
            deps,
            source_ip,
            session_id,
            session_span,
            username: None,
            proxyjump_node,
            authenticated: None,
            break_glass: false,
            breakglass_token: None,
            ki: KiState::Start,
            authz: None,
            authz_denied: None,
            inner: None,
            inner_failed: None,
            recorder: None,
            recorder_failed: None,
            pty: HashMap::new(),
            pending_channels: HashMap::new(),
            writers: HashMap::new(),
            pumps: HashMap::new(),
            channels_opened: 0,
            auth_attempts: 0,
            session_abort: None,
            live_guard: None,
            session_control: None,
            expiry_task: None,
            conn,
        }
    }

    fn remember_user(&mut self, user: &str) {
        self.username = Some(user.to_string());
    }

    /// The `gateway.session` trace root (OTEL-CONTRACT §3), so the accept loop can
    /// instrument the whole connection future with it — every callback + CP RPC then
    /// runs inside this span and joins the one trace.
    pub fn trace_span(&self) -> tracing::Span {
        self.session_span.clone()
    }

    fn source_ip(&self) -> String {
        self.source_ip.to_string()
    }

    /// Count a credential-resolution attempt and report whether the per-connection
    /// cap is now exceeded (bounds CP-RPC amplification, F-preauth-grace).
    fn attempt_cap_exceeded(&mut self) -> bool {
        self.auth_attempts += 1;
        self.auth_attempts > self.deps.config.max_auth_attempts
    }

    /// A hard rejection offering NO further methods, so the client stops (russh
    /// won't stop on its own). Used when the auth-attempt cap is exceeded.
    fn hard_reject(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(MethodSet::empty()),
            partial_success: false,
        }
    }

    /// Record a CP-down observation (fail-closed): flag it for the auth-failed
    /// record and the KI service-unavailable message, and log the outcome.
    fn note_cp_down(&self, method: &str) {
        self.conn.cp_unavailable.store(true, Ordering::SeqCst);
        tracing::warn!(source_ip = %self.source_ip, outcome = "cp_unavailable", method, "CP unreachable during resolution; failing closed");
    }

    fn set_authenticated(&mut self, id: ResolvedIdentity, method: AuthMethod) {
        tracing::info!(
            outcome = "authenticated",
            method = ?method,
            identity = %sanitize(&id.identity),
            source_ip = %self.source_ip,
            session_id = %self.session_id,
            "outer-leg authentication resolved"
        );
        self.authenticated = Some(Authenticated {
            identity: id.identity,
            principals: id.principals,
            groups: id.groups,
            method,
        });
    }

    /// Mark the connection break-glass authenticated: store the single-use token,
    /// flip the break-glass flag (forces strict recording + the break-glass Authorize
    /// + the break-glass mid-session-expiry policy), then record the identity.
    fn set_break_glass_authenticated(&mut self, id: ResolvedIdentity, token: String) {
        self.break_glass = true;
        self.breakglass_token = Some(token);
        self.set_authenticated(id, AuthMethod::BreakGlass);
    }

    /// Best-effort target node id for a break-glass credential's scope + token
    /// binding, derived from the SSH username (`login%node`) at auth time. The
    /// AUTHORITATIVE node binding is enforced at Authorize (where the token is
    /// consumed against the real node); an unparseable/unknown target yields an
    /// empty node id (tolerated by the CP for a fleet-scoped break-glass credential).
    fn break_glass_node_id(&self) -> String {
        let username = self.username.as_deref().unwrap_or_default();
        parse_username(username, self.deps.config.target_separator)
            .ok()
            .map(|mut t| {
                // Wildcard DNS (Part B): strip the configured suffix so a break-glass session
                // addressed as `user@web-01.ssh.corp` scopes to the same node as `user%web-01`.
                t.node = strip_dns_suffix(&t.node, &self.deps.config.node_dns_suffixes);
                t
            })
            .and_then(|t| self.deps.resolver.resolve_node_id(&t))
            .unwrap_or_default()
    }

    /// Try an offered sk-ecdsa security key as a break-glass credential (Design §7,
    /// FR-ACC-6, the PRIMARY break-glass path). russh has already verified the FIDO
    /// POSSESSION signature (possession only — the UP/touch bit is authenticator-
    /// enforced, not server-asserted; F-gw-breakglass-userpresence-1). The CP maps the
    /// PUBLIC key to a registered break-glass credential and mints a single-use token.
    /// Returns `Some(Auth::Accept)` on a
    /// resolved credential; `None` when the key is NOT a registered break-glass
    /// credential (or the CP could not answer) so the caller falls through to the
    /// ordinary pin path — a normal sk-ecdsa user is not break-glass and rides the
    /// pin path. CP-down is noted (the pin fall-through surfaces §7.1 fail-closed).
    async fn try_break_glass_publickey(&mut self, public_key: &PublicKey) -> Option<Auth> {
        let blob = public_key.to_bytes().ok()?;
        let node_id = self.break_glass_node_id();
        match self
            .deps
            .cpauth
            .resolve_break_glass_key(blob, &self.source_ip(), &node_id)
            .await
        {
            Ok(res) if break_glass_resolved(&res) => {
                let id = res.identity.expect("resolved implies identity present");
                self.set_break_glass_authenticated(id, res.breakglass_token);
                Some(Auth::Accept)
            }
            Ok(_) => {
                tracing::info!(source_ip = %self.source_ip, "offered security key is not a registered break-glass credential; trying the pin path");
                None
            }
            Err(e) if e.is_cp_down() => {
                self.note_cp_down("publickey-breakglass");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, source_ip = %self.source_ip, "break-glass key resolution failed; trying the pin path");
                None
            }
        }
    }

    /// Try the typed keyboard-interactive secret as a single-use break-glass OFFLINE
    /// CODE (Design §7, FR-ACC-6 — the IdP-independent fallback). Returns `Some(Auth)`
    /// on a terminal outcome (resolved → Accept; CP-down → service-unavailable) and
    /// `None` to fall through to the device flow. The `code` is a SECRET — NEVER
    /// logged.
    async fn try_break_glass_code(&mut self, code: &str) -> Option<Auth> {
        // Record the attempt so a failed break-glass-code login is represented in the
        // auth-failed record (not just "otp"), at parity with the sk path (G5). The
        // code itself is a secret and is NEVER recorded — only the coarse method label.
        self.conn.record_method("breakglass-code");
        let node_id = self.break_glass_node_id();
        match self
            .deps
            .cpauth
            .resolve_break_glass_code(code, &self.source_ip(), &node_id)
            .await
        {
            Ok(res) if break_glass_resolved(&res) => {
                let id = res.identity.expect("resolved implies identity present");
                self.set_break_glass_authenticated(id, res.breakglass_token);
                Some(Auth::Accept)
            }
            Ok(_) => None,
            Err(e) if e.is_cp_down() => {
                self.note_cp_down("breakglass-code");
                self.ki = KiState::TimedOut;
                Some(partial_message(SERVICE_UNAVAILABLE))
            }
            Err(e) => {
                tracing::warn!(error = %e, source_ip = %self.source_ip, "break-glass code resolution failed; falling back to device flow");
                None
            }
        }
    }

    /// The mid-session identity-expiry mode for THIS session, selected per access
    /// model (FR-ACC-8): a break-glass session uses the break-glass policy; standing
    /// and JIT use the default reeval policy. Uses BOTH the Gateway's local
    /// break-glass flag and the SIGNED `access_model` (belt-and-suspenders). A Lock
    /// always overrides with immediate teardown regardless of this.
    fn mid_session_expiry_mode(&self) -> MidSessionExpiryMode {
        if self.session_is_break_glass() {
            self.deps.config.break_glass.mid_session_expiry
        } else {
            self.deps.config.reeval.mid_session_expiry
        }
    }

    /// Whether this session is break-glass, from the local auth flag OR the SIGNED
    /// decision-context `access_model` (the CP forces BREAKGLASS on a break-glass
    /// token) — either signal forces the break-glass treatment (strict recording,
    /// expiry policy).
    fn session_is_break_glass(&self) -> bool {
        self.break_glass
            || self
                .authz
                .as_ref()
                .is_some_and(|a| a.context.access_model == AccessModel::Breakglass as i32)
    }

    /// A rejection that keeps `publickey` + `keyboard-interactive` on the table so
    /// the client degrades to its next key/method (FR-AUTH-2).
    fn reject_and_degrade(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(
                &[MethodKind::PublicKey, MethodKind::KeyboardInteractive][..],
            )),
            partial_success: false,
        }
    }

    async fn ki_step(&mut self, response: Option<Response<'_>>) -> Auth {
        match std::mem::replace(&mut self.ki, KiState::Start) {
            KiState::Start => {
                // If a prior (publickey) resolution already saw the CP down, surface
                // the §7.1 service-unavailable message here rather than prompting.
                if self.conn.cp_unavailable.load(Ordering::SeqCst) {
                    self.ki = KiState::TimedOut;
                    return partial_message(SERVICE_UNAVAILABLE);
                }
                // First info-request: prompt for the OTP (echo off, FR-AUTH-9).
                self.ki = KiState::AwaitingOtp;
                Auth::Partial {
                    name: Cow::Borrowed("SessionLayer"),
                    instructions: Cow::Borrowed(
                        "Enter a one-time passcode, or press Enter to log in via your browser.",
                    ),
                    prompts: Cow::Owned(vec![(Cow::Borrowed("One-time passcode: "), false)]),
                }
            }
            KiState::AwaitingOtp => {
                // The OTP is a secret: held in a scrub-on-drop buffer, never logged.
                let otp = first_response(response);
                if let Some(otp) = otp.as_ref().map(|z| z.as_str()).filter(|s| !s.is_empty()) {
                    self.conn.record_method("otp");
                    if self.attempt_cap_exceeded() {
                        return self.hard_reject();
                    }
                    match self.deps.cpauth.resolve_otp(otp, &self.source_ip()).await {
                        Ok(id) if id.resolved => {
                            self.set_authenticated(id, AuthMethod::Otp);
                            return Auth::Accept;
                        }
                        Ok(_) => {
                            // Not an OTP: before the device flow, try the same typed
                            // secret as a single-use break-glass OFFLINE CODE (IdP-
                            // independent, FR-ACC-6) so break-glass works even when the
                            // primary IdP / device flow is unavailable.
                            if self.deps.config.break_glass.enabled {
                                if let Some(auth) = self.try_break_glass_code(otp).await {
                                    return auth;
                                }
                            }
                            tracing::info!(source_ip = %self.source_ip, "OTP did not resolve; falling back to device flow")
                        }
                        // CP down during OTP resolution → surface service-unavailable
                        // (do NOT silently degrade to the device flow).
                        Err(e) if e.is_cp_down() => {
                            self.note_cp_down("otp");
                            self.ki = KiState::TimedOut;
                            return partial_message(SERVICE_UNAVAILABLE);
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, source_ip = %self.source_ip, "OTP resolution failed; falling back to device flow")
                        }
                    }
                }
                self.begin_device_flow().await
            }
            KiState::Device {
                device_code,
                deadline,
            } => self.device_flow_step(device_code, deadline).await,
            KiState::TimedOut => Auth::reject(),
        }
    }

    async fn begin_device_flow(&mut self) -> Auth {
        match self.deps.cpauth.begin_device_flow(&self.source_ip()).await {
            Ok(resp) => {
                let cap = self.deps.config.device_flow.poll_timeout_secs;
                let expires = if resp.expires_in_seconds > 0 {
                    (resp.expires_in_seconds as u64).min(cap)
                } else {
                    cap
                };
                let deadline = Instant::now() + Duration::from_secs(expires);
                let instructions = format!(
                    "To authenticate, open {} in a browser and enter code: {}",
                    sanitize(&resp.verification_uri),
                    sanitize(&resp.user_code)
                );
                tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, "device flow started; presenting verification URL + code");
                self.ki = KiState::Device {
                    device_code: resp.device_code,
                    deadline,
                };
                // num-prompts=0: the URL+code is in `instructions`; no input needed.
                Auth::Partial {
                    name: Cow::Borrowed("SessionLayer browser login"),
                    instructions: Cow::Owned(instructions),
                    prompts: Cow::Owned(Vec::new()),
                }
            }
            // CP unreachable/errored during begin → fail closed. Surface the §7.1
            // service-unavailable message on the keyboard-interactive path.
            Err(e) if e.is_cp_down() => {
                self.note_cp_down("device_flow");
                self.ki = KiState::TimedOut;
                partial_message(SERVICE_UNAVAILABLE)
            }
            Err(e) => {
                tracing::warn!(error = %e, source_ip = %self.source_ip, "could not begin device flow; failing auth closed");
                Auth::reject()
            }
        }
    }

    async fn device_flow_step(&mut self, device_code: String, deadline: Instant) -> Auth {
        if Instant::now() >= deadline {
            tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "device_flow_timeout", "device flow poll deadline elapsed");
            self.ki = KiState::TimedOut;
            return timed_out_partial();
        }

        // Decouple the client-visible heartbeat cadence from CP-poll latency
        // (FR-AUTH-4): bound the poll by the heartbeat interval, then sleep only
        // the remainder of that interval, so the next num-prompts=0 info-request
        // is emitted ~every heartbeat_interval regardless of poll latency.
        let interval = Duration::from_secs(self.deps.config.device_flow.heartbeat_interval_secs);
        let started = Instant::now();
        let poll = self.deps.cpauth.poll_device_flow(&device_code);
        let polled = match tokio::time::timeout(interval, poll).await {
            Ok(inner) => inner,
            Err(_) => Err(CpError::Timeout(interval)),
        };

        match polled {
            Ok(resp) => {
                let status = DeviceFlowStatus::try_from(resp.status)
                    .unwrap_or(DeviceFlowStatus::Unspecified);
                match status {
                    DeviceFlowStatus::Approved => {
                        let id = resp.identity.unwrap_or_default();
                        if id.resolved {
                            self.set_authenticated(id, AuthMethod::DeviceFlow);
                            return Auth::Accept;
                        }
                        tracing::info!(source_ip = %self.source_ip, "device flow approved without an identity; denying (generic)");
                        return Auth::reject();
                    }
                    DeviceFlowStatus::Denied => {
                        tracing::info!(source_ip = %self.source_ip, "device flow denied");
                        return Auth::reject();
                    }
                    DeviceFlowStatus::Expired => {
                        tracing::info!(source_ip = %self.source_ip, outcome = "device_flow_timeout", "device flow expired");
                        self.ki = KiState::TimedOut;
                        return timed_out_partial();
                    }
                    DeviceFlowStatus::Pending | DeviceFlowStatus::Unspecified => {}
                }
            }
            Err(e) => {
                // Throttled or a transient CP fault: keep the connection alive with
                // a heartbeat until the deadline (which fails closed). Never grants.
                if e.code() != Some(tonic::Code::ResourceExhausted) {
                    tracing::warn!(error = %e, source_ip = %self.source_ip, "device flow poll failed transiently; heartbeating");
                }
            }
        }

        // Pending / throttled / transient: sleep the remainder of the interval
        // (never past the deadline), then send the next keepalive info-request.
        let elapsed = started.elapsed();
        let remaining_to_deadline = deadline.saturating_duration_since(Instant::now());
        tokio::time::sleep(interval.saturating_sub(elapsed).min(remaining_to_deadline)).await;
        self.ki = KiState::Device {
            device_code,
            deadline,
        };
        // Pure keepalive: 0 prompts, empty instructions (the URL+code was shown on
        // the first device-flow info-request), below the client idle timeout.
        Auth::Partial {
            name: Cow::Borrowed(""),
            instructions: Cow::Borrowed(""),
            prompts: Cow::Owned(Vec::new()),
        }
    }

    /// Emit a §7.1 refusal on `channel` and close it (a denial or a node fault).
    /// The authorized happy path never calls this — it bridges the channel.
    fn close_with(&self, channel: ChannelId, session: &mut Session, outcome: SshOutcome) {
        if let Some(msg) = outcome.user_message() {
            let line = format!("{msg}\r\n").into_bytes();
            let _ = session.extended_data(channel, 1, line);
        }
        let _ = session.exit_status_request(channel, outcome.exit_code());
        let _ = session.eof(channel);
        let _ = session.close(channel);
    }

    /// Start a session channel: authorize once, gate the requested capability,
    /// establish the inner leg once, open + replay the channel to the node, and
    /// bridge. A denial / node fault closes the channel with the §7.1 outcome; the
    /// happy path hands the channel to the bridge (no close here).
    async fn start_channel(
        &mut self,
        channel: ChannelId,
        kind: ChannelKind,
        session: &mut Session,
    ) {
        // (1) Connect-time authorization — decided once per connection, cached.
        if self.authz.is_none() && self.authz_denied.is_none() {
            match self.decide().await {
                Ok(a) => self.authz = Some(Arc::new(a)),
                Err(o) => self.authz_denied = Some(o),
            }
        }
        if let Some(o) = self.authz_denied {
            self.close_with(channel, session, o);
            return;
        }
        let authz = self.authz.clone().expect("authorized cached above");

        // (1.5) Per-channel-open LOCAL re-evaluation (FR-CHAN-2, Design §6.3):
        // decision_ttl re-validate (forced when the lock feed is unhealthy),
        // grant_expiry vs the Gateway clock (conservative/early), source pin, and
        // the local lock-set (deny wins, datastore-independent). No CP call except
        // the forced re-authorize. A failure closes THIS channel with the generic
        // §7.1 denial; live channels keep flowing.
        let authz = match self.local_recheck(authz, channel, session).await {
            Ok(a) => a,
            Err(()) => return,
        };

        // (1.6) Register the live session for lock-triggered teardown and arm the
        // mid-session identity-expiry timer (Parts D/F), once per connection.
        self.ensure_registered(&authz, session);

        // (1.7) Re-check the lock-set AFTER registering — closes the teardown TOCTOU
        // with the feed's add-before-scan: a lock pushed concurrently with this
        // channel-open is now either seen here (deny) or finds this session in the
        // registry (torn down), so a matching lock can never leave a live channel.
        if let Some(lock) = self.deps.lock_set.matching(&authz.bindings) {
            tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, lock_id = %sanitize(&lock.lock_id), outcome = "policy_denied", reason = "locked", "channel refused by a pushed lock (post-register recheck)");
            self.close_with(channel, session, SshOutcome::PolicyDenied);
            return;
        }

        // (2) Capability gate at channel-open (FR-SESS-2): the channel is admitted
        // only if one of its acceptable capabilities is granted; UNSPECIFIED (the
        // "never granted" sentinel for an unknown subsystem) is rejected outright.
        let accepts = required_capabilities(&kind);
        let granted = accepts
            .iter()
            .any(|c| *c != Capability::Unspecified && authz.capabilities.contains(&(*c as i32)));
        if !granted {
            tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "capability_withheld", accepts = ?accepts, "channel refused: capability not granted");
            self.close_with(channel, session, SshOutcome::PolicyDenied);
            return;
        }

        // (2.5) Begin the session recording ONCE, before any bytes flow. Recording
        // is mandatory (§12/FR-AUD-1): in strict mode a setup failure (incl. no
        // customer key) refuses the session here; non-strict proceeds unrecorded
        // (logged loudly, never silent).
        if self.recorder.is_none() {
            if let Some(o) = self.recorder_failed {
                self.close_with(channel, session, o);
                return;
            }
            // Break-glass ALWAYS forces strict recording (FR-ACC-6): the session dies
            // if recording fails. Gated on BOTH the local break-glass flag and the
            // SIGNED access_model (belt-and-suspenders). `force_strict` can only
            // tighten the configured strict mode, never loosen it.
            let force_strict = self.session_is_break_glass();
            let params = RecordingParams {
                recording_token: authz.recording_token.clone(),
                session_id: self.session_id.clone(),
                node_id: authz.node.node_id.clone(),
                principal: authz.node.principal.clone(),
                teardown: Some(session.handle()),
                abort: self
                    .session_abort
                    .clone()
                    .expect("session registered before the recorder begins"),
                force_strict,
            };
            let strict = self.deps.config.recorder.strict || force_strict;
            match self.deps.recorder_factory.begin(params).await {
                Ok(r) => self.recorder = Some(r),
                Err(e) if strict => {
                    tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, error = %e, break_glass = force_strict, outcome = "recording_unavailable", "strict-mode recording setup failed; refusing the session");
                    self.recorder_failed = Some(SshOutcome::RecordingUnavailable);
                    self.close_with(channel, session, SshOutcome::RecordingUnavailable);
                    return;
                }
                Err(e) => {
                    tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, error = %e, "STRICT MODE OFF: recording setup failed; proceeding UNRECORDED (degraded)");
                    self.recorder = Some(bridge::disabled_recorder());
                }
            }
        }

        // (3) Establish the inner leg once (dial + host-verify + sign + handshake).
        if self.inner.is_none() {
            if let Some(o) = self.inner_failed {
                self.close_with(channel, session, o);
                return;
            }
            match self.establish_inner(&authz).await {
                Ok(c) => self.inner = Some(c),
                Err(o) => {
                    self.inner_failed = Some(o);
                    self.close_with(channel, session, o);
                    return;
                }
            }
        }
        let inner = self.inner.as_ref().expect("inner client established above");

        // (4) Open the matching channel on the node, replaying any PTY. Classify
        // the channel for the recorder BEFORE `kind` is moved into the node open,
        // carrying the PTY size so the asciicast header reflects it (#10).
        let (pty_cols, pty_rows) = self
            .pty
            .get(&channel)
            .map(|p| (p.col as u16, p.row as u16))
            .unwrap_or((0, 0));
        let rec_kind = classify_rec_kind(&kind, pty_cols, pty_rows);
        let pty = self.pty.get(&channel);
        let inner_chan = match inner.open_channel(kind, pty).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, error = %e, outcome = "node_unreachable", "inner channel open/replay failed");
                self.close_with(channel, session, SshOutcome::NodeUnreachable);
                return;
            }
        };

        // (5) Bridge: outer data → inner (via the write half, in `data`); inner →
        // outer via the pump task. The per-session recorder taps both directions.
        let _bridge_setup =
            tracing::info_span!(parent: &self.session_span, "gateway.bridge_setup").entered();
        let (read, write) = crate::ssh::innerleg::split_channel(inner_chan);
        self.writers.insert(channel, write);
        // Drive node→client through the outer channel's WRITE half (backpressured);
        // the read half is dropped (outer→inner flows via the `data` callback).
        let Some(outer_chan) = self.pending_channels.remove(&channel) else {
            self.close_with(channel, session, SshOutcome::NodeUnreachable);
            return;
        };
        let (_outer_read, outer_write) = outer_chan.split();

        // Register the channel with the recorder (the asciicast header already
        // carries the PTY size via `rec_kind`), then hand it to the pump as a tap.
        let recorder = self.recorder.clone().expect("recorder set above");
        recorder.open_channel(channel, rec_kind);
        let tap: Arc<dyn RecorderTap> = recorder;

        let pump = tokio::spawn(bridge::pump_inner_to_outer(
            read,
            outer_write,
            session.handle(),
            channel,
            tap,
        ));
        self.pumps.insert(channel, pump);
        self.session_span.record("sessionlayer.outcome", "allow");
        tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "bridged", "inner leg bridged; session flowing");
    }

    /// The per-channel-open local checks (FR-CHAN-2). Runs entirely against the
    /// cached, signature-verified context + the pushed lock-set — no CP call except
    /// a forced re-authorize when `decision_ttl` has elapsed (or the lock feed is
    /// unhealthy → `decision_ttl` treated as 0, FR-CHAN-4). On any denial it closes
    /// the channel with the generic §7.1 outcome and returns `Err(())`.
    async fn local_recheck(
        &mut self,
        mut authz: Arc<Authorized>,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<Arc<Authorized>, ()> {
        let grant_expiry_skew_secs = self.deps.config.reeval.grant_expiry_skew_secs;

        // (a) Re-validate. A BREAK-GLASS session is authorized ONCE by its single-use
        // token and does NOT re-authorize — a re-auth would replay the consumed token
        // (fail-closed replay-DENY) and needlessly refuse new channels. Its deny-side
        // safety does not depend on the periodic re-auth: it comes from the actively-
        // pushed LockFeed (§8.4) + conservative grant_expiry, both enforced in (b)/(d).
        // So on the HEALTHY path it serves new channels from the cached context; when
        // the feed is UNHEALTHY it cannot confirm the absence of a lock, so it refuses
        // NEW privileged channel-opens (fail closed) — existing channels run to
        // grant_expiry (S10 degrade-safe contract, without the token-replay artifact).
        if self.session_is_break_glass() {
            if !self.deps.lock_set.healthy() {
                tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "breakglass_lock_feed_unhealthy", "break-glass: lock feed unhealthy; refusing new channel (fail closed)");
                self.close_with(channel, session, SshOutcome::PolicyDenied);
                return Err(());
            }
        } else {
            // Standing/JIT re-validate: re-authorize when decision_ttl has elapsed, or
            // immediately when the lock feed is unhealthy (effective TTL 0) so a
            // possibly-missed lock cannot be served stale-open.
            let max_decision_ttl_secs = self.deps.config.reeval.max_decision_ttl_secs;
            let healthy = self.deps.lock_set.healthy();
            let effective_ttl = if healthy {
                authz
                    .context
                    .decision_ttl_seconds
                    .min(max_decision_ttl_secs)
                    .max(0)
            } else {
                0
            };
            if authz.verified_at.elapsed().as_secs() as i64 >= effective_ttl {
                match self.decide().await {
                    Ok(fresh) => {
                        let fresh = Arc::new(fresh);
                        self.authz = Some(fresh.clone());
                        // Refresh the registered teardown bindings (the re-authorized
                        // context may carry drifted node_labels / allowed_logins, so a
                        // lock on the NEW facet still tears this live session down) and
                        // rearm the expiry timer against the refreshed grant_expiry.
                        if let Some(control) = self.session_control.clone() {
                            control.update_bindings(fresh.bindings.clone());
                            self.arm_expiry(fresh.context.grant_expiry_epoch_seconds);
                        }
                        authz = fresh;
                    }
                    Err(o) => {
                        // Re-authorize failed (CP down / now denied). Refuse this NEW
                        // channel-open; existing channels keep flowing (allow fails open
                        // for the live session, deny/new fails closed — §2, NFR-2).
                        tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "revalidate_failed", "per-channel re-authorize failed; refusing new channel");
                        self.close_with(channel, session, o);
                        return Err(());
                    }
                }
            }
        }

        // (b) grant_expiry vs the Gateway clock (conservative/early): once a grant
        // has expired, NO new privileged channel-open is admitted in any
        // mid-session-expiry mode (Part F). For a BREAK-GLASS session a missing
        // grant_expiry (==0) is FAIL-CLOSED (G1): an always-available override MUST be
        // time-boxed (bounded by grant_expiry or a Lock, and it no longer re-authorizes),
        // so a context signed without an expiry refuses the channel rather than running
        // unbounded. A standing/JIT session with ge==0 is bounded by decision_ttl
        // re-auth + the pushed lock-set, so 0 remains "no fixed expiry" there.
        let now = now_epoch_secs();
        let ge = authz.context.grant_expiry_epoch_seconds;
        if ge == 0 {
            if self.session_is_break_glass() {
                tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, break_glass = true, outcome = "policy_denied", reason = "breakglass_no_grant_expiry", "break-glass ALLOW without a grant_expiry; refusing (must be time-boxed)");
                self.close_with(channel, session, SshOutcome::PolicyDenied);
                return Err(());
            }
        } else if now + grant_expiry_skew_secs >= ge {
            tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "grant_expired", "grant expired; refusing new channel");
            self.close_with(channel, session, SshOutcome::PolicyDenied);
            return Err(());
        }

        // (c) Source pin: a channel-open whose source differs from the decision's is
        // refused (multiplexed channels share one connection, so this normally holds
        // — a mismatch means a mis-bound context).
        if !authz.context.source_address.is_empty()
            && authz.context.source_address != self.source_ip()
        {
            tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "source_pin_mismatch", "channel source does not match the decision context");
            self.close_with(channel, session, SshOutcome::PolicyDenied);
            return Err(());
        }

        // (d) Local lock-set (deny wins, independent of the datastore). A live match
        // is also being torn down by the feed; refusing here closes the race window.
        if let Some(lock) = self.deps.lock_set.matching(&authz.bindings) {
            tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, lock_id = %sanitize(&lock.lock_id), outcome = "policy_denied", reason = "locked", "channel refused by a pushed lock");
            self.close_with(channel, session, SshOutcome::PolicyDenied);
            return Err(());
        }

        Ok(authz)
    }

    /// Register this session in the live registry (so a pushed lock can tear it
    /// down) and arm the mid-session-expiry timer — once per connection.
    fn ensure_registered(&mut self, authz: &Arc<Authorized>, session: &Session) {
        if self.live_guard.is_some() {
            return;
        }
        let abort = Arc::new(AtomicBool::new(false));
        let control = SessionControl::new(authz.bindings.clone(), session.handle(), abort.clone());
        self.session_abort = Some(abort);
        self.live_guard = Some(
            self.deps
                .live_sessions
                .register(self.session_id.clone(), control.clone()),
        );
        self.session_control = Some(control);
        self.arm_expiry(authz.context.grant_expiry_epoch_seconds);
    }

    /// (Re)arm the mid-session identity-expiry timer for `grant_expiry` (Part F).
    /// In `run_to_ttl` mode there is no active teardown (new channels are already
    /// refused after expiry by [`Self::local_recheck`]); the other modes tear the
    /// live session down at (or a grace after) `grant_expiry`. A Lock overrides all.
    fn arm_expiry(&mut self, grant_expiry: i64) {
        if let Some(task) = self.expiry_task.take() {
            task.abort();
        }
        // Defense in depth (G1): a break-glass session MUST be time-boxed. A missing
        // grant_expiry is a contract violation — tear it down immediately rather than
        // run unbounded. (In practice local_recheck (b) already refuses the channel, so
        // ensure_registered/arm_expiry are not reached with ge==0 for break-glass; this
        // is the belt-and-suspenders backstop. RunToTtl is rejected for break-glass at
        // config validation, so a break-glass session never reaches the no-teardown mode.)
        if grant_expiry == 0 && self.session_is_break_glass() {
            if let Some(control) = self.session_control.clone() {
                tracing::warn!(session_id = %self.session_id, break_glass = true, outcome = "grant_expired", "break-glass session without a grant_expiry; tearing down (must be time-boxed)");
                control.terminate();
            }
            return;
        }
        let mode = self.mid_session_expiry_mode();
        if mode == MidSessionExpiryMode::RunToTtl || grant_expiry == 0 {
            return;
        }
        let Some(control) = self.session_control.clone() else {
            return;
        };
        let grace = if mode == MidSessionExpiryMode::GraceThenKill {
            self.deps.config.reeval.mid_session_grace_secs
        } else {
            0
        };
        let wait = (grant_expiry - now_epoch_secs()).max(0) as u64 + grace;
        let session_id = self.session_id.clone();
        self.expiry_task = Some(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(wait)).await;
            tracing::info!(session_id = %session_id, outcome = "grant_expired", "mid-session grant expiry: tearing session down");
            control.terminate();
        }));
    }

    /// Resolve the target, apply the credential reducer, call `Authorize`, and on
    /// ALLOW build the [`Authorized`] hand-off (node connection + host trust +
    /// grant + capabilities). Pre-authorization failures collapse to the generic
    /// denial (no existence disclosure); a missing node connection or missing
    /// host-verification material aborts (never TOFU).
    async fn decide(&self) -> Result<Authorized, SshOutcome> {
        let Some(auth) = &self.authenticated else {
            return Err(SshOutcome::AuthFailed);
        };
        let username = self.username.as_deref().unwrap_or_default();
        let target = if let Some(node) = &self.proxyjump_node {
            // ProxyJump inner hop (Session Sixteen, Part C): the node is fixed by the
            // `direct-tcpip` target (already wildcard-DNS normalized when the inner
            // server was spun up), and the whole username IS the login — no `%` parse.
            Target {
                login: username.to_string(),
                node: node.clone(),
            }
        } else {
            let Ok(mut target) = parse_username(username, self.deps.config.target_separator) else {
                tracing::info!(source_ip = %self.source_ip, username = %sanitize(username), outcome = "policy_denied", reason = "malformed_target", "generic denial");
                return Err(SshOutcome::PolicyDenied);
            };
            // Wildcard DNS (Part B): fold `web-01.ssh.corp` back to the bare node name
            // before resolution so it reaches the same node as a plain `login%web-01`
            // (the DNS suffix is a client convenience; see docs/addressing.md). A no-op
            // when no configured `ssh.node_dns_suffixes` matches (default).
            target.node = strip_dns_suffix(&target.node, &self.deps.config.node_dns_suffixes);
            target
        };

        // Credential-principal reducer (deny-only): a login-scoped credential may
        // only be used for a login it is scoped to (FR-AUTH-15 spirit, §5.4/§5.5).
        if !auth.principals.is_empty() && !auth.principals.iter().any(|p| p == &target.login) {
            tracing::info!(source_ip = %self.source_ip, outcome = "policy_denied", reason = "credential_principal_scope", "generic denial");
            return Err(SshOutcome::PolicyDenied);
        }

        let Some(node_id) = self.deps.resolver.resolve_node_id(&target) else {
            tracing::info!(source_ip = %self.source_ip, outcome = "policy_denied", reason = "unknown_node", "generic denial");
            return Err(SshOutcome::PolicyDenied);
        };

        let req = AuthorizeRequest {
            identity: auth.identity.clone(),
            identity_groups: auth.groups.clone(),
            // Session Sixteen Part A (FR-ADDR-1): forward the parsed node NAME (already
            // wildcard-DNS-normalized by Part B above). The CP resolves it to runtime.node.id via
            // findByName — authoritative, server-side — and returns the id in the NodeConnection;
            // node_id is kept only for back-compat (the CP ignores it when node_name is set, and
            // falls back to it when node_name is empty).
            node_name: target.node.clone(),
            node_id: node_id.clone(),
            requested_principal: target.login.clone(),
            source_ip: self.source_ip(),
            session_id: self.session_id.clone(),
            client: Some(version::component_info()),
            // Present ONLY on a break-glass connect: the CP consumes it (single-use),
            // creates the activation + fires the alert, forces access_model =
            // BREAKGLASS + strict, and evaluates the break-glass allow SUBJECT TO the
            // top-tier Lock (a Lock still denies — deny wins). Empty for standing/JIT.
            breakglass_token: self.breakglass_token.clone().unwrap_or_default(),
        };

        match self.deps.cpauth.authorize(req).await {
            Ok(resp)
                if resp.decision == Decision::Allow as i32 && !resp.session_token.is_empty() =>
            {
                // The node connection + host-verification material is mandatory.
                let Some(nc) = resp.node_connection else {
                    tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, node_id = %sanitize(&node_id), outcome = "node_unreachable", reason = "no_node_connection", "authorized but the CP returned no node connection; failing closed");
                    return Err(SshOutcome::NodeUnreachable);
                };
                let trust = host_trust_from(nc.host_verification);
                if trust.is_empty() {
                    // No enrollment anchor → the node cannot be verified → NEVER
                    // TOFU. Abort (FR-CONN-5/7).
                    tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, node_id = %sanitize(&node_id), outcome = "node_unreachable", reason = "no_host_verification_material", "aborting: node has no host-verification anchor (never TOFU)");
                    return Err(SshOutcome::NodeUnreachable);
                }
                // Per-node connector selection (Session Fourteen, FR-CONN-3). An
                // OUTBOUND_AGENT node is joined to its Agent by the CP-stamped
                // enrollment NAME; without one there is no join key, so fail closed to
                // node-offline rather than dial anything.
                if nc.connector_kind == ConnectorKind::OutboundAgent as i32
                    && nc.node_name.is_empty()
                {
                    tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, node_id = %sanitize(&node_id), outcome = "node_unreachable", reason = "agent_node_without_name", "outbound-agent node has no enrollment name; failing closed");
                    return Err(SshOutcome::NodeUnreachable);
                }
                // Part A: trust the decision context only because its signature
                // verifies (chain to the pinned internal mTLS CA + signer marker +
                // codeSigning EKU + ECDSA-P256/SHA-256). Fail closed on any doubt.
                // EVERY security field the Gateway acts on — access_model (forced-
                // strict + per-model expiry), capabilities, allowed_logins,
                // grant_expiry, source_address, the lock-match bindings — is read from
                // THIS decoded-from-`signed_context` struct; the response's redundant
                // UNSIGNED `resp.context` is deliberately NEVER read, so stripping/
                // downgrading it (e.g. dropping access_model=BREAKGLASS) cannot weaken
                // enforcement (F2). `verify_decision_context` decodes from the exact
                // signed bytes, not any convenience copy.
                let context = match decisionctx::verify_decision_context(
                    &resp.signed_context,
                    &resp.signature,
                    &resp.signer_certificate,
                    &self.deps.cpauth.current_ca_chain(),
                ) {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, error = %e, outcome = "policy_denied", reason = "decision_context_unverified", "rejecting unverified decision context (fail closed)");
                        return Err(SshOutcome::PolicyDenied);
                    }
                };
                // The signed context binds the session/gateway this decision was
                // made for — a mismatch means a mis-routed or replayed context.
                if context.session_id != self.session_id {
                    tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "policy_denied", reason = "context_session_mismatch", "decision context bound to a different session (fail closed)");
                    return Err(SshOutcome::PolicyDenied);
                }
                // Observability (G7): a break-glass auth should always come back
                // access_model=BREAKGLASS. A mismatch is a token mis-binding / contract
                // drift signal (the local flag still forces strict, so it is not a
                // downgrade — just worth flagging). Not user-facing.
                if self.break_glass && context.access_model != AccessModel::Breakglass as i32 {
                    tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, break_glass = true, access_model = context.access_model, "break-glass auth resolved to a non-BREAKGLASS access model (token mis-binding / contract drift?)");
                }
                let capabilities = granted_capabilities(Some(&context));
                let bindings = LockBindings::from_context(&context);
                tracing::info!(
                    outcome = "authorized",
                    identity = %sanitize(&auth.identity),
                    method = ?auth.method,
                    node_id = %sanitize(&node_id),
                    principal = %sanitize(&target.login),
                    session_id = %self.session_id,
                    "authorized; establishing inner leg"
                );
                // Session Sixteen Part A (F-ha-connect-nodename-1 read half): downstream
                // keys on the CP-RESOLVED node id from the SIGNED context, NOT the parsed
                // name. With a real inventory where name != uuid the two differ, and the
                // session token minted by Authorize is bound to the resolved id — so the
                // inner-leg SignContext.node_id MUST be context.node_id or
                // SignSessionCertificate fails closed (advisory ctx != token). The parsed
                // `node_id` local remains only for pre-verification logging.
                Ok(Authorized {
                    node: NodeTarget {
                        node_id: context.node_id.clone(),
                        principal: target.login.clone(),
                    },
                    dial: NodeDial {
                        node_id: context.node_id.clone(),
                        dial_address: nc.dial_address,
                        connector_kind: nc.connector_kind,
                        node_name: nc.node_name,
                        session_id: self.session_id.clone(),
                        principal: target.login.clone(),
                        // HA (Session Fifteen): the fresh presence owner the CP folded into
                        // the decision. Empty for agentless / no-fresh-owner; the agent-model
                        // connector routes local-vs-remote by owner==self and fails closed on
                        // an empty owner ("node offline").
                        owning_gateway_id: nc.owning_gateway_id,
                        owning_gateway_addr: nc.owning_gateway_addr,
                        owner_nonce: nc.owner_nonce,
                    },
                    trust,
                    grant: SessionGrant {
                        session_token: resp.session_token,
                        context: Some(context.clone()),
                    },
                    capabilities,
                    recording_token: resp.recording_token,
                    context,
                    verified_at: Instant::now(),
                    bindings,
                })
            }
            Ok(_) => {
                // DENY, a Lock, no-match, or ALLOW-without-token — one generic
                // denial to the user; the CP logged the specific reason.
                tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, break_glass = self.break_glass, outcome = "policy_denied", reason = "authorization_denied", "generic denial");
                Err(SshOutcome::PolicyDenied)
            }
            Err(e) => {
                self.note_cp_down("authorize");
                tracing::warn!(error = %e, source_ip = %self.source_ip, outcome = "cp_unavailable", "authorization RPC failed; failing closed (service unavailable)");
                Err(SshOutcome::ServiceUnavailable)
            }
        }
    }

    /// Establish the inner leg once for this connection: dial the node (Part A),
    /// mint the ephemeral inner cert (Part B / D2 — key generated locally, cert
    /// only returned), verify the node host identity during the handshake (Part C,
    /// no TOFU), and authenticate. Fail-closed with the §7.1 outcome at every step;
    /// a host-verification abort is generic to the user, specific in the log.
    async fn establish_inner(&self, authz: &Authorized) -> Result<InnerClient, SshOutcome> {
        use tracing::Instrument;
        // Stamp the trace root with the (non-secret) decision facts now that they
        // are known (OTEL-CONTRACT §4).
        self.session_span
            .record("sessionlayer.node_id", sanitize(&authz.node.node_id));
        self.session_span.record(
            "sessionlayer.access_model",
            access_model_label(authz.context.access_model),
        );
        // The connector is selected per node (agentless dial vs outbound-agent
        // dial-back); everything below this line is identical either way (D21/D23).
        let stream = match self
            .deps
            .connector
            .connect(&authz.dial)
            .instrument(tracing::info_span!(parent: &self.session_span, "gateway.node.connect", connector_kind = authz.dial.connector_kind))
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, connector_kind = authz.dial.connector_kind, error = %e, outcome = "node_unreachable", "node connect failed");
                return Err(SshOutcome::NodeUnreachable);
            }
        };

        let inner_kp = match InnerKeyPair::generate() {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = %e, session_id = %self.session_id, "inner keypair generation failed");
                return Err(SshOutcome::NodeUnreachable);
            }
        };
        let sign_ctx = Some(SignContext {
            session_id: self.session_id.clone(),
            node_id: authz.node.node_id.clone(),
            requested_principal: authz.node.principal.clone(),
        });
        let signed = match self
            .deps
            .cpauth
            .sign_session_certificate(&authz.grant.session_token, &inner_kp, sign_ctx)
            .await
        {
            Ok(c) => c,
            Err(e) if e.is_cp_down() => {
                self.note_cp_down("sign");
                tracing::warn!(error = %e, session_id = %self.session_id, outcome = "cp_unavailable", "inner-cert signing failed (CP unreachable)");
                return Err(SshOutcome::ServiceUnavailable);
            }
            Err(e) => {
                tracing::warn!(error = %e, session_id = %self.session_id, outcome = "node_unreachable", "inner-cert signing rejected (fail closed)");
                return Err(SshOutcome::NodeUnreachable);
            }
        };

        let cert = match Certificate::from_bytes(&signed.certificate_blob) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, session_id = %self.session_id, "CP returned an unparseable inner certificate");
                return Err(SshOutcome::NodeUnreachable);
            }
        };
        let key = match inner_kp
            .private_key_openssh_pem()
            .map_err(|e| e.to_string())
            .and_then(|pem| PrivateKey::from_openssh(&pem).map_err(|e| e.to_string()))
        {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = %e, session_id = %self.session_id, "inner private key could not be prepared");
                return Err(SshOutcome::NodeUnreachable);
            }
        };
        drop(inner_kp); // the local keypair is no longer needed (zeroized on drop)

        let verifier = HostVerifier::new(authz.trust.clone());
        let cfg = self.inner_leg_config();
        match InnerClient::establish(stream, verifier, &authz.node.principal, cert, key, &cfg)
            .instrument(tracing::info_span!(parent: &self.session_span, "gateway.host_verify"))
            .await
        {
            Ok(inner) => {
                tracing::info!(outcome = "host_verified", source_ip = %self.source_ip, session_id = %self.session_id, node_id = %sanitize(&authz.node.node_id), host_verified = ?inner.verified(), key_id = %sanitize(&signed.key_id), "inner leg established; node host identity verified (no TOFU)");
                Ok(inner)
            }
            Err(InnerLegError::HostVerification(reason)) => {
                tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, node_id = %sanitize(&authz.node.node_id), reason = %reason, outcome = "host_verification_failed", "ABORT: node host identity not verified (no TOFU)");
                Err(SshOutcome::NodeUnreachable)
            }
            Err(e) => {
                tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, error = %e, outcome = "node_unreachable", "inner SSH handshake failed");
                Err(SshOutcome::NodeUnreachable)
            }
        }
    }

    fn inner_leg_config(&self) -> InnerLegConfig {
        let inner = &self.deps.config.inner;
        InnerLegConfig {
            handshake_timeout: Duration::from_secs(inner.handshake_timeout_secs),
            window_size: inner.window_bytes,
            max_packet_size: inner.max_packet_bytes,
            idle_timeout: Duration::from_secs(inner.max_session_idle_secs),
        }
    }
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        // Connection end: abort any live pump tasks deterministically (dropping the
        // inner client also closes the node transport, but this bounds the teardown).
        for (_, pump) in self.pumps.drain() {
            pump.abort();
        }
        // Stop the mid-session-expiry timer (the connection is already ending). The
        // live_guard drops here too, deregistering the session from the lock registry.
        if let Some(task) = self.expiry_task.take() {
            task.abort();
        }
        // Finalize the recording off the Drop path (flush → seal-final → upload →
        // FinalizeRecording). Spawned via the tracker so teardown never blocks but a
        // graceful shutdown can still await it (#3); the recorder holds its own CP
        // client + uploader.
        if let Some(rec) = self.recorder.take() {
            self.deps.finalize_tracker.spawn(rec.finalize());
        }
    }
}

impl Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.remember_user(user);
        // Request the signature so pins are only resolved on proven possession.
        Ok(Auth::Accept)
    }

    // `skip_all`: the public key + username never enter the span (OTEL-CONTRACT §5).
    #[tracing::instrument(name = "gateway.outer_leg.auth", parent = &self.session_span, skip_all)]
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.remember_user(user);
        if self.attempt_cap_exceeded() {
            return Ok(self.hard_reject());
        }
        // Break-glass FIDO2 (Design §7, FR-ACC-6): an sk-ecdsa security key is the
        // PRIMARY break-glass path — try the break-glass resolver first. Its whole
        // security rests on FIDO PROOF-OF-POSSESSION, which russh ENFORCES BEFORE this
        // callback: `server/encrypted.rs` decodes the client's signature and calls
        // `Verifier::verify(&pubkey, session_id||request, &sig)`, and ONLY on success
        // invokes `auth_publickey` (a "signature wrong" rejects without calling us). For
        // an sk key that verify is `ssh_key::public::SkEcdsaSha2NistP256::verify`, which
        // checks the ECDSA signature over `sha256(application)||flags||counter||
        // sha256(request)` (`make_sk_signed_data`) — so the FIDO authenticator's private
        // key MUST have signed, and the assertion flags/counter are signature-covered
        // (un-forgeable). The registered break-glass key is PUBLIC/listable, so this
        // possession check is what stops a public-key holder from getting a break-glass
        // session. russh verifies POSSESSION ONLY; it does NOT surface the sk assertion
        // flags to any server seam, so the UP/user-presence (touch) bit is enforced by
        // the AUTHENTICATOR, not asserted server-side (F-gw-breakglass-userpresence-1,
        // Accepted-Risk) — break-glass keys MUST be provisioned touch-required. A key
        // that is NOT a registered break-glass credential FALLS THROUGH to the ordinary
        // pin path: a normal sk-ecdsa user rides the pubkey/pin path (SESSION §1.2),
        // never a hard reject. Only sk-ecdsa enters here.
        if self.deps.config.break_glass.enabled && is_break_glass_algorithm(public_key.algorithm())
        {
            self.conn.record_method("publickey-breakglass");
            if let Some(auth) = self.try_break_glass_publickey(public_key).await {
                return Ok(auth);
            }
            // Not a break-glass credential (or the CP could not answer) → fall through.
        } else if is_security_key_algorithm(public_key.algorithm()) {
            // A non-sk-ecdsa security key (e.g. sk-ed25519): break-glass supports ONLY
            // sk-ecdsa (SESSION Part D), so route it to the ordinary pin path — but log
            // it operator-side (§7.1-safe: the user still sees a normal auth outcome) so
            // a mis-provisioned emergency key does not fail silently (G4).
            tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, algorithm = %public_key.algorithm().as_str(), "non-sk-ecdsa security key offered; break-glass supports only sk-ecdsa — routing to the pin path");
        }
        self.conn.record_method("publickey-pin");
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        match self
            .deps
            .cpauth
            .resolve_pin(&fingerprint, &self.source_ip())
            .await
        {
            Ok(id) if id.resolved => {
                self.set_authenticated(id, AuthMethod::Pin);
                Ok(Auth::Accept)
            }
            Ok(_) => {
                tracing::info!(source_ip = %self.source_ip, "offered key is not pinned; degrading");
                Ok(self.reject_and_degrade())
            }
            // CP down: flag it (the KI fallback surfaces service-unavailable) and
            // degrade so the client moves to keyboard-interactive; never fail open.
            Err(e) if e.is_cp_down() => {
                self.note_cp_down("publickey-pin");
                Ok(self.reject_and_degrade())
            }
            Err(e) => {
                tracing::warn!(error = %e, source_ip = %self.source_ip, "pin resolution failed; degrading");
                Ok(self.reject_and_degrade())
            }
        }
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        self.remember_user(user);
        self.conn.record_method("publickey-cert");
        if self.attempt_cap_exceeded() {
            return Ok(self.hard_reject());
        }
        let blob = match certificate.to_bytes() {
            Ok(b) => b,
            Err(_) => return Ok(self.reject_and_degrade()),
        };
        match self
            .deps
            .cpauth
            .resolve_user_cert(blob, &self.source_ip())
            .await
        {
            Ok(id) if id.resolved => {
                self.set_authenticated(id, AuthMethod::UserCert);
                Ok(Auth::Accept)
            }
            Ok(_) => {
                tracing::info!(source_ip = %self.source_ip, "user certificate did not resolve; degrading");
                Ok(self.reject_and_degrade())
            }
            Err(e) if e.is_cp_down() => {
                self.note_cp_down("publickey-cert");
                Ok(self.reject_and_degrade())
            }
            Err(e) => {
                tracing::warn!(error = %e, source_ip = %self.source_ip, "user-cert resolution failed; degrading");
                Ok(self.reject_and_degrade())
            }
        }
    }

    // `skip_all`: the KI response (which may carry an OTP / device code) never
    // enters the span (OTEL-CONTRACT §5).
    #[tracing::instrument(name = "gateway.outer_leg.auth", parent = &self.session_span, skip_all)]
    async fn auth_keyboard_interactive(
        &mut self,
        user: &str,
        _submethods: &str,
        response: Option<Response<'_>>,
    ) -> Result<Auth, Self::Error> {
        self.remember_user(user);
        Ok(self.ki_step(response).await)
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        // Disarm the pre-auth deadline watchdog.
        self.conn.authenticated.store(true, Ordering::SeqCst);
        tracing::info!(outcome = "auth_succeeded", session_id = %self.session_id, source_ip = %self.source_ip, "outer-leg authentication succeeded");
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Tier-0 per-connection channel cap (bounds pump tasks + node channels +
        // buffers; russh enforces none). Over the cap → reject (drop the reply).
        self.channels_opened += 1;
        if self.channels_opened > self.deps.config.inner.max_channels_per_connection {
            tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "channel_cap", "per-connection channel cap exceeded; refusing channel open");
            return Ok(());
        }
        // Retain the channel so its write half drives the backpressured node→client
        // direction (see `pending_channels`).
        self.pending_channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col: u32,
        row: u32,
        pw: u32,
        ph: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Stash the PTY so it can be replayed to the node when the shell/exec
        // starts; ack it to the outer client.
        self.pty.insert(
            channel,
            PtyParams {
                term: term.to_string(),
                col,
                row,
                pix_w: pw,
                pix_h: ph,
                modes: modes.to_vec(),
            },
        );
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.start_channel(channel, ChannelKind::Shell, session)
            .await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.start_channel(channel, ChannelKind::Exec(data.to_vec()), session)
            .await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.start_channel(channel, ChannelKind::Subsystem(name.to_string()), session)
            .await;
        Ok(())
    }

    /// Outer → inner: forward client bytes to the node's channel write half. The
    /// recorder taps the input stream (`i`) first; the await naturally backpressures
    /// the outer read when the node is slow.
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // A lock or strict-mode teardown flips the shared abort flag; stop
        // forwarding client bytes to the node AT ONCE — before the async
        // disconnect lands — so no keystroke/command reaches the node after a lock
        // (the client->node half of the teardown, matching the node->client pump's
        // should_abort() gate). Covers both the strict recorder (torn) and the
        // non-strict/disabled recorder (which shares only the session_abort flag).
        if self
            .session_abort
            .as_ref()
            .is_some_and(|a| a.load(Ordering::SeqCst))
        {
            return Ok(());
        }
        if let Some(rec) = &self.recorder {
            if rec.should_abort() {
                return Ok(());
            }
            // Tap the input stream (`i`) BEFORE forwarding.
            rec.tap(channel, TapDirection::Input, None, data);
        }
        if let Some(w) = self.writers.get(&channel) {
            let _ = w.data(data).await;
        }
        Ok(())
    }

    /// Client closed its half — relay EOF to the node so the remote command sees
    /// end-of-input (SFTP/SCP uploads, `cat |` pipelines).
    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(w) = self.writers.get(&channel) {
            let _ = w.eof().await;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(w) = self.writers.remove(&channel) {
            let _ = w.close().await;
        }
        // Flush the channel's recorder state (final events / file-transfer audit).
        if let Some(rec) = &self.recorder {
            rec.close_channel(channel);
        }
        // Deterministic teardown: abort the pump rather than wait for the node to
        // propagate Close (no leak-until-disconnect, F-channelcap-1).
        if let Some(pump) = self.pumps.remove(&channel) {
            pump.abort();
        }
        self.pending_channels.remove(&channel);
        self.pty.remove(&channel);
        Ok(())
    }

    /// Relay an interactive resize to the node's PTY, recording it as an asciicast
    /// `r` event.
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col: u32,
        row: u32,
        pw: u32,
        ph: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(rec) = &self.recorder {
            rec.resize(channel, col as u16, row as u16);
        }
        if let Some(w) = self.writers.get(&channel) {
            let _ = w.window_change(col, row, pw, ph).await;
        }
        Ok(())
    }

    /// Agent forwarding is **always refused** (FR-SESS-2): never bridged to the
    /// node. Returning `false` sends `channel_failure` to the client.
    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "agent_forward_refused", "agent forwarding refused (always)");
        Ok(false)
    }

    /// A `direct-tcpip` channel open. Two cases:
    ///
    /// - **ProxyJump host-cert MITM** (Session Sixteen, Part C): when
    ///   `ssh.proxy_jump.enabled` and this is the OUTER jump connection, the request
    ///   is `ssh -J gw login@node` opening a forward to the node. We DO NOT proxy TCP
    ///   — we accept the channel and terminate the inner hop ourselves, presenting a
    ///   host-CA host cert for the node (no TOFU) and running the full recorded
    ///   session seam (see [`crate::ssh::proxyjump`]).
    /// - Otherwise it is a plain **local port-forward**, which is refused (the
    ///   capability gate; agent/port forwarding are default-deny). Dropping the reply
    ///   handle rejects the channel. Nested ProxyJump (a forward from an already-MITM
    ///   inner hop) is likewise refused.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<russh::server::Msg>,
        host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Nested ProxyJump (forward from an already-terminated inner hop) is refused:
        // one MITM hop only, never a forward chain.
        let proxy_jump = if self.proxyjump_node.is_some() {
            None
        } else {
            self.deps.proxy_jump.clone()
        };
        let Some(pj) = proxy_jump else {
            tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "port_forward_refused", "direct-tcpip (local port-forward) refused");
            return Ok(());
        };
        // Tier-0 per-connection channel cap (shared with channel_open_session): a
        // ProxyJump inner hop spawns a russh server + a login-grace watchdog, and the
        // host-cert fetch mints a host-CA cert — all before the inner authorize. Cap
        // the direct-tcpip opens so an authenticated-but-ungranted jump connection
        // cannot flood inner-server spawns / host-CA signing / memory (S16 F-proxyjump-dos).
        self.channels_opened += 1;
        if self.channels_opened > self.deps.config.inner.max_channels_per_connection {
            tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "channel_cap", "per-connection channel cap exceeded; refusing ProxyJump direct-tcpip");
            return Ok(());
        }
        // Accept the forwarded channel and hand it to an inner SSH server that
        // presents the node's host cert. Spawned so the outer connection keeps
        // pumping this channel's bytes to the inner server's stream.
        reply.accept().await;
        let stream = channel.into_stream();
        let deps = self.deps.clone();
        let source_ip = self.source_ip;
        let host = host_to_connect.to_string();
        let login_grace = Duration::from_secs(self.deps.config.login_grace_secs);
        tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, node = %sanitize(host_to_connect), outcome = "proxyjump_inner", "ProxyJump: terminating inner hop with a host-CA host cert (no TOFU)");
        tokio::spawn(async move {
            crate::ssh::proxyjump::serve_inner_hop(deps, pj, source_ip, host, stream, login_grace)
                .await;
        });
        Ok(())
    }
}

/// The SSH capabilities that admit a channel kind (FR-SESS-2) — the channel is
/// allowed if ANY is granted. Legacy `scp` is `exec` of the `scp` binary with
/// attacker-controlled argv (`scp -S <prog>`, shell metacharacters), so it can
/// never be a safe standalone capability: it requires **EXEC** (F-capgate-scp-1).
/// Modern scp runs over the SFTP subsystem, so SCP is honored there alongside SFTP
/// (Design §12.1, both SCP modes). An unknown subsystem has NO acceptable
/// capability → always refused (fail closed).
fn required_capabilities(kind: &ChannelKind) -> &'static [Capability] {
    match kind {
        ChannelKind::Shell => &[Capability::Shell],
        ChannelKind::Exec(_) => &[Capability::Exec],
        ChannelKind::Subsystem(name) if name == "sftp" => &[Capability::Sftp, Capability::Scp],
        ChannelKind::Subsystem(_) => &[],
    }
}

/// Classify a bridged channel for the recorder (Design §12.1, red-team #1): a
/// shell / exec is ALWAYS a terminal (asciicast v2) — a legacy scp-over-exec
/// additionally runs the SCP decoder for file-transfer audit, but NEVER instead of
/// asciicast, so the exec command string can never suppress content capture. Only
/// the sftp SUBSYSTEM (the node runs sftp-server, no shell) is decode-only.
fn classify_rec_kind(kind: &ChannelKind, cols: u16, rows: u16) -> RecChannelKind {
    match kind {
        ChannelKind::Shell => RecChannelKind::Terminal {
            command: None,
            scp: None,
            cols,
            rows,
        },
        ChannelKind::Exec(cmd) => RecChannelKind::Terminal {
            command: Some(cmd.clone()),
            scp: crate::ssh::recorder::scp::parse_scp_command(cmd)
                .map(|(upload, target)| crate::ssh::bridge::ScpMode { upload, target }),
            cols,
            rows,
        },
        ChannelKind::Subsystem(name) if name == "sftp" => RecChannelKind::Sftp,
        // Only the sftp subsystem is ever bridged (the capability gate refuses the
        // rest); default to an opaque terminal for safety.
        ChannelKind::Subsystem(_) => RecChannelKind::Terminal {
            command: None,
            scp: None,
            cols,
            rows,
        },
    }
}

/// Whether `alg` is a break-glass candidate algorithm — the FIDO2 publickey path
/// (Design §7, FR-ACC-6). ONLY `sk-ecdsa-sha2-nistp256@openssh.com`: P-256 is the
/// platform default and the CP registers break-glass credentials as sk-ecdsa. A
/// non-break-glass sk-ecdsa key (and every other algorithm, incl. sk-ed25519) rides
/// the ordinary pubkey/pin path — an sk-ecdsa key that does not resolve as a
/// break-glass credential falls through to the pin path (never a hard reject).
fn is_break_glass_algorithm(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::SkEcdsaSha2NistP256)
}

/// Whether `alg` is ANY FIDO2/U2F security-key algorithm. Used to log (G4) when a
/// non-sk-ecdsa security key (e.g. sk-ed25519) is offered — break-glass supports only
/// sk-ecdsa, so it routes to the pin path, but the emergency-path operator should see
/// that a mis-provisioned security key was tried.
fn is_security_key_algorithm(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::SkEcdsaSha2NistP256 | Algorithm::SkEd25519)
}

/// Whether a break-glass resolution actually succeeded: the identity resolved AND a
/// single-use token was minted. A resolved identity with no token is fail-closed
/// (no break-glass Authorize can proceed without the token, §7.1).
fn break_glass_resolved(res: &crate::pb::BreakglassResolution) -> bool {
    res.identity.as_ref().is_some_and(|i| i.resolved) && !res.breakglass_token.is_empty()
}

/// The granted capabilities from the decision context; default shell+exec when
/// the context declares none (Design §6.1 default). Agent-forward is never here.
fn granted_capabilities(context: Option<&DecisionContext>) -> Vec<i32> {
    match context {
        Some(ctx) if !ctx.capabilities.is_empty() => ctx.capabilities.clone(),
        _ => vec![Capability::Shell as i32, Capability::Exec as i32],
    }
}

/// Build the Gateway host-trust from the CP's proto material (public only).
fn host_trust_from(hv: Option<crate::pb::HostVerification>) -> HostTrust {
    match hv {
        Some(h) => HostTrust {
            host_ca_keys: h.host_ca_keys,
            expected_principals: h.expected_host_principals,
            host_certificates: h.host_certificates,
            pinned_host_keys: h.pinned_host_keys,
        },
        None => HostTrust::default(),
    }
}

/// A `num-prompts=0` info-request carrying a §7.1 message in `instructions`; the
/// client's empty response then meets [`KiState::TimedOut`] and auth is rejected.
/// Used to surface both the device-flow timeout and CP-unavailable outcomes.
fn partial_message(msg: &'static str) -> Auth {
    Auth::Partial {
        name: Cow::Borrowed(""),
        instructions: Cow::Borrowed(msg),
        prompts: Cow::Owned(Vec::new()),
    }
}

/// The device-flow timeout info-request (§7.1 "authentication timed out").
fn timed_out_partial() -> Auth {
    partial_message(DEVICE_FLOW_TIMEOUT)
}

/// Read the user's first keyboard-interactive response as a UTF-8 string, held in
/// a scrub-on-drop buffer (the first response may be a secret OTP; NEVER logged).
fn first_response(response: Option<Response<'_>>) -> Option<Zeroizing<String>> {
    let bytes = response?.next()?;
    std::str::from_utf8(&bytes)
        .ok()
        .map(|s| Zeroizing::new(s.to_string()))
}

/// Whether a char is unsafe to render in a log field or on a terminal: a control
/// character (Cc: C0/C1, incl. ESC/newline) OR a Unicode format/bidi character
/// (Cf: e.g. RLO U+202E, zero-width joiners, BOM) that could reorder or hide
/// text. `char::is_control()` covers only Cc, so the format/bidi ranges are
/// filtered explicitly (no unicode-category dependency).
fn is_unsafe_display(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200B}'..='\u{200F}' // zero-width space/joiners + LRM/RLM
            | '\u{202A}'..='\u{202E}' // bidi embeddings/overrides (RLO/LRO/…)
            | '\u{2060}'..='\u{2064}' // word joiner + invisible math operators
            | '\u{2066}'..='\u{206F}' // bidi isolates + deprecated format chars
            | '\u{FEFF}'              // BOM / zero-width no-break space
            | '\u{061C}'              // Arabic letter mark
            | '\u{180E}'              // Mongolian vowel separator
        )
}

/// Sanitize a client/CP-supplied string for a log field or a terminal line: drop
/// control + format/bidi characters and bound the length (log-injection /
/// terminal-escape / bidi-spoofing guard). Never applied to secrets — those are
/// not rendered at all. `pub(crate)` so the lock feed sanitizes CP-supplied
/// lock ids the same way (a breached CP must not inject control chars into logs).
pub(crate) fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !is_unsafe_display(*c))
        .take(256)
        .collect()
}

/// The `sessionlayer.access_model` span-attribute label (OTEL-CONTRACT §4). A safe,
/// closed enum — never free-form CP text. UNSPECIFIED maps to `standing` (the N-1
/// safe default, matching the mid-session-expiry handling).
fn access_model_label(access_model: i32) -> &'static str {
    match AccessModel::try_from(access_model) {
        Ok(AccessModel::Jit) => "jit",
        Ok(AccessModel::Breakglass) => "break_glass",
        _ => "standing",
    }
}

/// A random session id for this connect (opaque; not a UUID parser dependency).
/// Canonical RFC 4122 v4 UUID string. The contract (`authz.proto` `session_id`)
/// is a UUID and the CP `parseUuid`s it — an un-dashed hex blob is rejected and
/// denies the connect (fail-closed `missing_input`). Kept dependency-free (no
/// `uuid` crate) over the existing CSPRNG.
fn new_session_id() -> String {
    use rand_core::RngCore;
    let mut b = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0F) | 0x40; // version 4
    b[8] = (b[8] & 0x3F) | 0x80; // RFC 4122 variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// The Gateway wall clock as Unix epoch seconds (for grant/lock expiry checks).
fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_a_canonical_uuid() {
        // The CP `parseUuid`s `AuthorizeRequest.session_id` (contract: UUID); an
        // un-dashed blob denies the connect. Guard the canonical 8-4-4-4-12 v4 shape.
        let id = new_session_id();
        let groups: Vec<&str> = id.split('-').collect();
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(id
            .chars()
            .all(|c| c == '-' || c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(groups[2].as_bytes()[0], b'4'); // version 4
        assert!(matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b')); // RFC 4122 variant
        assert_ne!(new_session_id(), new_session_id()); // fresh per call
    }

    #[test]
    fn sanitize_strips_control_and_bounds_length() {
        // The dangerous control bytes (newline, ESC) are removed; the remaining
        // printable text is harmless without its escape introducer.
        let cleaned = sanitize("ab\nc\u{1b}[2Jd");
        assert!(!cleaned.contains('\n') && !cleaned.contains('\u{1b}'));
        assert_eq!(cleaned, "abc[2Jd");
        assert_eq!(sanitize(&"x".repeat(500)).len(), 256);
    }

    #[test]
    fn sanitize_strips_bidi_and_format_chars() {
        // A right-to-left override + zero-width joiner + BOM must all be stripped
        // (bidi-spoofing / invisible-text guard).
        let cleaned = sanitize("admin\u{202E}txt\u{200D}\u{FEFF}");
        assert_eq!(cleaned, "admintxt");
        assert!(!cleaned.contains('\u{202E}'));
    }

    /// The break-glass FIDO2 publickey path (Design §7, FR-ACC-6, divergence D6):
    /// ONLY sk-ecdsa is a break-glass candidate (P-256 is the platform default and
    /// the CP registers break-glass credentials as sk-ecdsa). sk-ed25519 and every
    /// other algorithm ride the ordinary pin path; a non-break-glass sk-ecdsa key
    /// also falls through to the pin path (never a hard reject).
    #[test]
    fn only_sk_ecdsa_routes_to_break_glass() {
        assert!(is_break_glass_algorithm(Algorithm::SkEcdsaSha2NistP256));
        assert!(!is_break_glass_algorithm(Algorithm::SkEd25519));
        assert!(!is_break_glass_algorithm(Algorithm::Ed25519));
    }

    /// Break-glass resolution is fail-closed: it succeeds ONLY when the identity
    /// resolved AND a single-use token was minted.
    #[test]
    fn break_glass_resolution_requires_identity_and_token() {
        let resolved_id = ResolvedIdentity {
            resolved: true,
            identity: "bg-admin".into(),
            principals: vec!["root".into()],
            groups: Vec::new(),
        };
        let ok = crate::pb::BreakglassResolution {
            identity: Some(resolved_id.clone()),
            breakglass_token: "tok".into(),
        };
        assert!(break_glass_resolved(&ok));
        // Resolved identity but NO token → fail closed (no break-glass Authorize).
        assert!(!break_glass_resolved(&crate::pb::BreakglassResolution {
            identity: Some(resolved_id),
            breakglass_token: String::new(),
        }));
        // Unresolved identity (even with a token) → false.
        assert!(!break_glass_resolved(&crate::pb::BreakglassResolution {
            identity: Some(ResolvedIdentity::default()),
            breakglass_token: "tok".into(),
        }));
        // Missing identity → false.
        assert!(!break_glass_resolved(&crate::pb::BreakglassResolution {
            identity: None,
            breakglass_token: "tok".into(),
        }));
    }

    // (Superseded by `session_id_is_a_canonical_uuid`, which asserts the canonical dashed-UUID
    // shape + distinctness; the old `session_ids_are_distinct_hex` asserted the un-dashed 32-char
    // hex form that F-ha-session-uuid-1 replaced.)

    /// Capability gate (FR-SESS-2): a legacy `scp` exec is gated by EXEC (never a
    /// standalone SCP), an unknown subsystem is never granted, and UNSPECIFIED is
    /// never an acceptable capability (F-capgate-scp-1 / F-capgate-unspec-1).
    #[test]
    fn capability_gate_never_admits_scp_exec_or_unknown_subsystem() {
        // A file-transfer-only grant (scp+sftp, no exec/shell).
        let scp_only = [Capability::Scp as i32, Capability::Sftp as i32];
        let admits = |kind: &ChannelKind, granted: &[i32]| {
            required_capabilities(kind)
                .iter()
                .any(|c| *c != Capability::Unspecified && granted.contains(&(*c as i32)))
        };

        // `scp -S /bin/sh …` and metacharacter smuggling are plain exec → need EXEC,
        // so an scp-only grant must NOT admit them.
        for cmd in [
            "scp -S /bin/sh a b",
            "scp x y; id",
            "/usr/bin/scp -o ProxyCommand=id a b",
        ] {
            let kind = ChannelKind::Exec(cmd.as_bytes().to_vec());
            assert_eq!(required_capabilities(&kind), &[Capability::Exec]);
            assert!(
                !admits(&kind, &scp_only),
                "scp-only must not admit exec {cmd:?}"
            );
        }
        // An honest exec is admitted only by EXEC.
        assert!(admits(
            &ChannelKind::Exec(b"id".to_vec()),
            &[Capability::Exec as i32]
        ));

        // Modern scp uses the sftp subsystem → SFTP or SCP admits it.
        let sftp = ChannelKind::Subsystem("sftp".into());
        assert!(admits(&sftp, &scp_only));
        assert!(admits(&sftp, &[Capability::Sftp as i32]));
        assert!(!admits(&sftp, &[Capability::Exec as i32]));

        // Unknown subsystem: no acceptable capability → refused even against a set
        // literally containing UNSPECIFIED (0).
        let unknown = ChannelKind::Subsystem("netconf".into());
        assert!(required_capabilities(&unknown).is_empty());
        assert!(!admits(&unknown, &[Capability::Unspecified as i32]));
        assert!(!admits(&unknown, &[Capability::Sftp as i32]));
    }
}
