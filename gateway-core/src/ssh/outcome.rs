//! The SSH-surface error taxonomy (Session Seven, Part F; Design §7.1,
//! FR-AUTH-16/18).
//!
//! One place decides what the user sees, so the non-leaking contract is
//! auditable: **pre-authorization outcomes are generic** (they never reveal
//! whether an identity, node, or rule exists), and locks/revocations produce the
//! **same** generic denial as any authorization failure. The detailed reason
//! (which rule/lock/method) goes only to the structured decision log at the call
//! site — never to the user.
//!
//! | Situation | User sees | Emitted where |
//! |---|---|---|
//! | Source IP outside gate | nothing (dropped at TCP, no banner) | accept loop |
//! | Auth failed (all methods) | standard SSH auth failure | russh (we reject) |
//! | Authorized-but-denied (RBAC/lock/no-match) | "access denied by policy" | channel |
//! | Device-flow timeout | "authentication timed out, please reconnect" | keyboard-interactive |
//! | CP unreachable | "service temporarily unavailable" (fail closed) | channel |
//! | Node unreachable / host-verify failed (post-authz) | "the target node is offline or unavailable" | channel |
//! | Authorized | (no message — the channel is bridged to the node) | — |

/// Generic authorization denial — a Lock, an RBAC deny, a no-match, a malformed
/// or unknown target, or the credential-principal reducer all collapse to this
/// one message (no existence disclosure).
pub const ACCESS_DENIED: &str = "access denied by policy";

/// The device-flow poll deadline elapsed.
pub const DEVICE_FLOW_TIMEOUT: &str = "authentication timed out, please reconnect";

/// The CP could not be reached / return a decision — fail closed (NFR-2).
pub const SERVICE_UNAVAILABLE: &str = "service temporarily unavailable";

/// Post-authorization node-side failure: the node could not be dialed, its host
/// identity could not be verified (no TOFU), the inner cert could not be minted
/// for a node reason, or the inner handshake failed. One message for all so a
/// **host-verification failure is not distinguishable** from an offline node (the
/// specific reason is in the operator log only — Part C).
pub const NODE_UNREACHABLE: &str = "the target node is offline or unavailable";

/// A §7.1 outcome. Values that reach an SSH channel carry a user message + exit
/// code; the pre-banner / native-auth-failure values carry neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshOutcome {
    /// Real source IP outside the global gate — dropped at TCP, no banner.
    SourceBlocked,
    /// All auth methods failed — standard SSH auth failure (russh emits it).
    AuthFailed,
    /// Authorization denied (RBAC/lock/no-match/malformed/credential-scope).
    PolicyDenied,
    /// The device flow timed out.
    DeviceFlowTimeout,
    /// The CP was unreachable/errored during the connect-time decision.
    ServiceUnavailable,
    /// Post-authorization node-side failure (dial / host-verify / inner
    /// handshake). Generic to the user; specific in the operator log.
    NodeUnreachable,
}

impl SshOutcome {
    /// The user-visible message, or `None` when the user sees no custom text
    /// (dropped pre-banner, or a standard SSH auth failure).
    pub fn user_message(&self) -> Option<&'static str> {
        match self {
            SshOutcome::SourceBlocked | SshOutcome::AuthFailed => None,
            SshOutcome::PolicyDenied => Some(ACCESS_DENIED),
            SshOutcome::DeviceFlowTimeout => Some(DEVICE_FLOW_TIMEOUT),
            SshOutcome::ServiceUnavailable => Some(SERVICE_UNAVAILABLE),
            SshOutcome::NodeUnreachable => Some(NODE_UNREACHABLE),
        }
    }

    /// The channel exit status for a channel-emitted refusal. Every channel-level
    /// outcome here is a non-zero refusal (the authorized happy path bridges the
    /// channel instead of emitting an outcome).
    pub fn exit_code(&self) -> u32 {
        1
    }

    /// Whether this outcome is a **pre-authorization** result (must stay
    /// generic — no identity/node/rule existence disclosure). [`NodeUnreachable`]
    /// is post-authorization (the user is already entitled to know the node
    /// exists, §7.1) but still carries no host-verification detail.
    ///
    /// [`NodeUnreachable`]: SshOutcome::NodeUnreachable
    pub fn is_pre_authorization(&self) -> bool {
        matches!(
            self,
            SshOutcome::SourceBlocked
                | SshOutcome::AuthFailed
                | SshOutcome::PolicyDenied
                | SshOutcome::DeviceFlowTimeout
                | SshOutcome::ServiceUnavailable
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denial_is_generic_and_leaks_nothing() {
        // The generic denial must not name an identity, node, rule, lock, or
        // reason — a reviewer can grep this list.
        let msg = ACCESS_DENIED.to_lowercase();
        for forbidden in [
            "identity",
            "user",
            "node",
            "host",
            "rule",
            "lock",
            "revoke",
            "principal",
            "group",
            "expired",
            "unknown",
            "no match",
            "grant",
        ] {
            assert!(
                !msg.contains(forbidden),
                "generic denial leaked the token {forbidden:?}"
            );
        }
    }

    #[test]
    fn messages_are_terminal_safe() {
        for m in [
            ACCESS_DENIED,
            DEVICE_FLOW_TIMEOUT,
            SERVICE_UNAVAILABLE,
            NODE_UNREACHABLE,
        ] {
            assert!(
                m.chars().all(|c| !c.is_control()),
                "message must carry no control characters: {m:?}"
            );
        }
    }

    #[test]
    fn channel_refusals_exit_nonzero_and_node_unreachable_is_post_authz() {
        assert_eq!(SshOutcome::PolicyDenied.exit_code(), 1);
        assert_eq!(SshOutcome::ServiceUnavailable.exit_code(), 1);
        assert_eq!(SshOutcome::NodeUnreachable.exit_code(), 1);
        assert!(SshOutcome::PolicyDenied.is_pre_authorization());
        // NodeUnreachable is post-authz (the node is known to exist) but leaks no
        // host-verification detail (one message for offline vs verify-failed).
        assert!(!SshOutcome::NodeUnreachable.is_pre_authorization());
    }

    #[test]
    fn node_unreachable_message_leaks_no_host_verification_detail() {
        let m = NODE_UNREACHABLE.to_lowercase();
        for forbidden in [
            "host key",
            "certificate",
            "cert",
            "tofu",
            "pin",
            "verif",
            "ca ",
            "principal",
        ] {
            assert!(
                !m.contains(forbidden),
                "node-unreachable leaked {forbidden:?}"
            );
        }
    }

    #[test]
    fn pre_banner_and_auth_failure_have_no_custom_message() {
        assert!(SshOutcome::SourceBlocked.user_message().is_none());
        assert!(SshOutcome::AuthFailed.user_message().is_none());
    }
}
