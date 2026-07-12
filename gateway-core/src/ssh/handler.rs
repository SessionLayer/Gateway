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
use std::time::{Duration, Instant};

use russh::keys::{Certificate, HashAlg, PrivateKey, PublicKey};
use russh::server::{Auth, Handler, Response, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty};
use zeroize::Zeroizing;

use crate::config::SshServerConfig;
use crate::cpauth::{CpAuthClient, CpError};
use crate::pb::{
    AuthorizeRequest, Capability, Decision, DecisionContext, DeviceFlowStatus, ResolvedIdentity,
    SignContext,
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
use crate::ssh::outcome::{SshOutcome, DEVICE_FLOW_TIMEOUT, SERVICE_UNAVAILABLE};
use crate::ssh::target::{parse_username, TargetResolver};
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
    /// SSH server configuration (target separator, device-flow timing, inner-leg
    /// bounds, recorder policy, …).
    pub config: Arc<SshServerConfig>,
}

/// A single SSH connection's handler. Not `Clone`: it owns per-connection state.
pub struct SshHandler {
    deps: HandlerDeps,
    /// The real client source IP (PROXY-derived, gate-checked before this exists).
    source_ip: IpAddr,
    /// The SessionLayer session id allocated for this connect.
    session_id: String,
    /// The SSH username (client-supplied; parsed as `login%node`, never trusted
    /// as a principal, sanitized before logging).
    username: Option<String>,
    authenticated: Option<Authenticated>,
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
}

impl SshHandler {
    /// Construct a handler for a freshly-accepted, gate-passed connection.
    pub fn new(deps: HandlerDeps, source_ip: IpAddr, conn: Arc<ConnState>) -> Self {
        Self {
            deps,
            source_ip,
            session_id: new_session_id(),
            username: None,
            authenticated: None,
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
            conn,
        }
    }

    fn remember_user(&mut self, user: &str) {
        self.username = Some(user.to_string());
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
            let params = RecordingParams {
                recording_token: authz.recording_token.clone(),
                session_id: self.session_id.clone(),
                node_id: authz.node.node_id.clone(),
                principal: authz.node.principal.clone(),
                teardown: Some(session.handle()),
            };
            let strict = self.deps.config.recorder.strict;
            match self.deps.recorder_factory.begin(params).await {
                Ok(r) => self.recorder = Some(r),
                Err(e) if strict => {
                    tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, error = %e, outcome = "recording_unavailable", "strict-mode recording setup failed; refusing the session");
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
        tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "bridged", "inner leg bridged; session flowing");
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
        let Ok(target) = parse_username(username, self.deps.config.target_separator) else {
            tracing::info!(source_ip = %self.source_ip, username = %sanitize(username), outcome = "policy_denied", reason = "malformed_target", "generic denial");
            return Err(SshOutcome::PolicyDenied);
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
            node_id: node_id.clone(),
            requested_principal: target.login.clone(),
            source_ip: self.source_ip(),
            session_id: self.session_id.clone(),
            client: Some(version::component_info()),
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
                let capabilities = granted_capabilities(resp.context.as_ref());
                tracing::info!(
                    outcome = "authorized",
                    identity = %sanitize(&auth.identity),
                    method = ?auth.method,
                    node_id = %sanitize(&node_id),
                    principal = %sanitize(&target.login),
                    session_id = %self.session_id,
                    "authorized; establishing inner leg"
                );
                Ok(Authorized {
                    node: NodeTarget {
                        node_id: node_id.clone(),
                        principal: target.login.clone(),
                    },
                    dial: NodeDial {
                        node_id,
                        dial_address: nc.dial_address,
                    },
                    trust,
                    grant: SessionGrant {
                        session_token: resp.session_token,
                        context: resp.context,
                    },
                    capabilities,
                    recording_token: resp.recording_token,
                })
            }
            Ok(_) => {
                // DENY, a Lock, no-match, or ALLOW-without-token — one generic
                // denial to the user; the CP logged the specific reason.
                tracing::info!(source_ip = %self.source_ip, outcome = "policy_denied", reason = "authorization_denied", "generic denial");
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
        let stream = match self.deps.connector.connect(&authz.dial).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(source_ip = %self.source_ip, session_id = %self.session_id, error = %e, outcome = "node_unreachable", "agentless dial failed");
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
        match InnerClient::establish(stream, verifier, &authz.node.principal, cert, key, &cfg).await
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

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.remember_user(user);
        self.conn.record_method("publickey-pin");
        if self.attempt_cap_exceeded() {
            return Ok(self.hard_reject());
        }
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
        // A strict-mode recording failure tears the session down; do not forward
        // further (un-recorded) bytes to the node while the disconnect is in flight.
        if let Some(rec) = &self.recorder {
            if rec.is_torn_down() {
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

    /// Local port forwarding is refused this session (the capability gate; the
    /// forwarded-channel bridge is a clean follow-up seam). Dropping the reply
    /// handle rejects the channel.
    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<russh::server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::info!(source_ip = %self.source_ip, session_id = %self.session_id, outcome = "port_forward_refused", "direct-tcpip (local port-forward) refused");
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
/// not rendered at all.
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !is_unsafe_display(*c))
        .take(256)
        .collect()
}

/// A random session id for this connect (opaque; not a UUID parser dependency).
fn new_session_id() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn session_ids_are_distinct_hex() {
        let a = new_session_id();
        let b = new_session_id();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

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
