//! SSH-surface error taxonomy: pre-auth outcomes are generic (no identity/node/rule disclosure);
//! locks/denials produce the same generic denial as any auth failure (deny wins).
//! Detailed reasons go only to structured logs at the call site, never to the user.

/// Generic denial (Lock/RBAC deny/no-match/malformed target/credential-scope; no disclosure).
pub const ACCESS_DENIED: &str = "access denied by policy";

/// Device-flow poll deadline elapsed.
pub const DEVICE_FLOW_TIMEOUT: &str = "authentication timed out, please reconnect";

/// CP unreachable / decision failure (fail-closed).
pub const SERVICE_UNAVAILABLE: &str = "service temporarily unavailable";

/// Post-auth node-side failure (dial/host-verify/handshake); one message for all (no host-verify detail disclosed).
pub const NODE_UNREACHABLE: &str = "the target node is offline or unavailable";

/// Recording failure when mandatory (fail-closed; reason in operator log only).
pub const RECORDING_UNAVAILABLE: &str = "session cannot start: recording unavailable";

use crate::telemetry::metrics::Counted;

/// SSH outcome: channel-level outcomes carry a user message + exit code; pre-banner outcomes carry neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshOutcome {
    /// Source IP outside global gate — dropped at TCP, no banner.
    SourceBlocked,
    /// All auth methods failed — russh emits the standard SSH auth failure.
    AuthFailed,
    /// Authorization denied (RBAC/lock/no-match/malformed/credential-scope).
    PolicyDenied,
    /// Device-flow poll deadline elapsed.
    DeviceFlowTimeout,
    /// CP was unreachable / decision error (fail-closed).
    ServiceUnavailable,
    /// Post-auth node-side failure (dial/host-verify/handshake); generic to user, specific in operator log.
    /// The [`Counted`] payload is only mintable by `telemetry::metrics::node_unreachable`, so
    /// no site can fail a session closed here without the counter seeing it.
    NodeUnreachable(Counted),
    /// Recording failure when mandatory (fail-closed).
    RecordingUnavailable,
}

impl SshOutcome {
    pub fn user_message(&self) -> Option<&'static str> {
        match self {
            SshOutcome::SourceBlocked | SshOutcome::AuthFailed => None,
            SshOutcome::PolicyDenied => Some(ACCESS_DENIED),
            SshOutcome::DeviceFlowTimeout => Some(DEVICE_FLOW_TIMEOUT),
            SshOutcome::ServiceUnavailable => Some(SERVICE_UNAVAILABLE),
            SshOutcome::NodeUnreachable(_) => Some(NODE_UNREACHABLE),
            SshOutcome::RecordingUnavailable => Some(RECORDING_UNAVAILABLE),
        }
    }

    pub fn exit_code(&self) -> u32 {
        1
    }

    pub fn span_label(&self) -> &'static str {
        match self {
            SshOutcome::SourceBlocked => "source_blocked",
            SshOutcome::AuthFailed => "auth_failed",
            SshOutcome::PolicyDenied => "policy_denied",
            SshOutcome::DeviceFlowTimeout => "device_flow_timeout",
            SshOutcome::ServiceUnavailable => "cp_unavailable",
            SshOutcome::NodeUnreachable(counted) => counted.outcome(),
            SshOutcome::RecordingUnavailable => "recording_unavailable",
        }
    }

    /// Whether this outcome is pre-authorization (must stay generic; no identity/node/rule disclosure). NodeUnreachable is post-authorization but carries no host-verify detail.
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
        use crate::telemetry::metrics::{node_unreachable, UnreachableReason};
        let counted = node_unreachable(UnreachableReason::NodeConnectFailed);
        let unreachable = SshOutcome::NodeUnreachable(counted);
        assert_eq!(SshOutcome::PolicyDenied.exit_code(), 1);
        assert_eq!(SshOutcome::ServiceUnavailable.exit_code(), 1);
        assert_eq!(unreachable.exit_code(), 1);
        assert!(SshOutcome::PolicyDenied.is_pre_authorization());
        assert!(!unreachable.is_pre_authorization());
        assert_eq!(unreachable.span_label(), counted.outcome());
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
