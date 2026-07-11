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
//! (deny-only), then calls S5 **`Authorize`**; on ALLOW it obtains the signed
//! decision context + session token and hands them to the [`NodeConnector`] seam
//! (the Session-Seven stub closes the session cleanly at "inner leg pending").
//! Every SSH-surface outcome follows the §7.1 taxonomy ([`SshOutcome`]); no
//! secret/OTP/token/plaintext is ever logged.

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use russh::keys::{Certificate, HashAlg, PublicKey};
use russh::server::{Auth, Handler, Response, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty};
use zeroize::Zeroizing;

use crate::config::SshServerConfig;
use crate::cpauth::{CpAuthClient, CpError};
use crate::pb::{AuthorizeRequest, Decision, DeviceFlowStatus, ResolvedIdentity};
use crate::ssh::connector::{NodeConnectError, NodeConnector, NodeTarget, SessionGrant};
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
    /// The CP auth/authorize client (Part D).
    pub cpauth: Arc<CpAuthClient>,
    /// The inner-leg connector seam (Session-Seven stub).
    pub connector: Arc<dyn NodeConnector>,
    /// The target `node`-name → node-id resolver (Session-Sixteen seam).
    pub resolver: Arc<dyn TargetResolver>,
    /// SSH server configuration (target separator, device-flow timing, …).
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
    /// Guard so the connect-time authorize + connector hand-off runs exactly once.
    decided: bool,
    /// Count of credential-resolution attempts (bounds the CP-RPC amplification
    /// per connection — russh does NOT enforce its own `max_auth_attempts`).
    auth_attempts: usize,
    /// Shared with the accept loop (pre-auth deadline + auth-failed record).
    conn: Arc<ConnState>,
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
            decided: false,
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

    /// The one connect-time authorization decision + connector hand-off, run once.
    async fn authorize_and_close(&mut self, channel: ChannelId, session: &mut Session) {
        if self.decided {
            return;
        }
        self.decided = true;
        let outcome = self.decide().await;

        if let Some(msg) = outcome.user_message() {
            let line = format!("{msg}\r\n").into_bytes();
            // Refusals go to stderr (extended data code 1); the clean authorized
            // "inner leg pending" goes to stdout.
            let _ = if outcome.exit_code() == 0 {
                session.data(channel, line)
            } else {
                session.extended_data(channel, 1, line)
            };
        }
        let _ = session.exit_status_request(channel, outcome.exit_code());
        let _ = session.eof(channel);
        let _ = session.close(channel);
    }

    /// Resolve the target, apply the credential reducer, call `Authorize`, and (on
    /// ALLOW) hand to the connector. Returns the §7.1 outcome. Pre-authorization
    /// failures are all the same generic denial (no existence disclosure).
    async fn decide(&self) -> SshOutcome {
        let Some(auth) = &self.authenticated else {
            return SshOutcome::AuthFailed;
        };
        let username = self.username.as_deref().unwrap_or_default();
        let target = match parse_username(username, self.deps.config.target_separator) {
            Ok(t) => t,
            Err(_) => {
                tracing::info!(source_ip = %self.source_ip, username = %sanitize(username), outcome = "policy_denied", reason = "malformed_target", "generic denial");
                return SshOutcome::PolicyDenied;
            }
        };

        // Credential-principal reducer (deny-only): a login-scoped credential may
        // only be used for a login it is scoped to (FR-AUTH-15 spirit, §5.4/§5.5).
        if !auth.principals.is_empty() && !auth.principals.iter().any(|p| p == &target.login) {
            tracing::info!(source_ip = %self.source_ip, outcome = "policy_denied", reason = "credential_principal_scope", "generic denial");
            return SshOutcome::PolicyDenied;
        }

        let Some(node_id) = self.deps.resolver.resolve_node_id(&target) else {
            tracing::info!(source_ip = %self.source_ip, outcome = "policy_denied", reason = "unknown_node", "generic denial");
            return SshOutcome::PolicyDenied;
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
                tracing::info!(
                    outcome = "authorized",
                    identity = %sanitize(&auth.identity),
                    method = ?auth.method,
                    node_id = %sanitize(&node_id),
                    principal = %sanitize(&target.login),
                    session_id = %self.session_id,
                    "authorized; handing to inner-leg connector"
                );
                let node = NodeTarget {
                    node_id,
                    principal: target.login.clone(),
                };
                let grant = SessionGrant {
                    session_token: resp.session_token,
                    context: resp.context,
                };
                match self.deps.connector.connect(&node, &grant).await {
                    // Session Seven stops at the seam; Session Eight bridges here.
                    Ok(_stream) => SshOutcome::InnerLegPending,
                    Err(NodeConnectError::InnerLegPending) => SshOutcome::InnerLegPending,
                }
            }
            Ok(_) => {
                // DENY, a Lock, no-match, or ALLOW-without-token — one generic
                // denial to the user; the CP logged the specific reason.
                tracing::info!(source_ip = %self.source_ip, outcome = "policy_denied", reason = "authorization_denied", "generic denial");
                SshOutcome::PolicyDenied
            }
            Err(e) => {
                self.note_cp_down("authorize");
                tracing::warn!(error = %e, source_ip = %self.source_ip, outcome = "cp_unavailable", "authorization RPC failed; failing closed (service unavailable)");
                SshOutcome::ServiceUnavailable
            }
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
        _channel: Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col: u32,
        _row: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Acknowledge PTY setup; the authorize + hand-off runs on shell/exec.
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.authorize_and_close(channel, session).await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.authorize_and_close(channel, session).await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.authorize_and_close(channel, session).await;
        Ok(())
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
}
