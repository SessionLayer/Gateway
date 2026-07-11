//! Target resolution — username encoding (Session Seven, Part G, FR-ADDR-1).
//!
//! Stock OpenSSH carries the target in the username: `ssh login%node@gw`. The
//! Gateway splits `login%node` into the requested Linux login and the target
//! node identifier; `login` becomes `Authorize.requested_principal` and `node`
//! the node the CP authorizes against. **Node existence/labels are the CP's
//! inventory concern** — a malformed or unknown target yields a *generic*
//! pre-authorization denial (no existence disclosure, §7.1); the parser never
//! decides access.
//!
//! Other addressing modes (wildcard DNS, ProxyJump + host-cert MITM, Design §11)
//! are **Session Sixteen**: the `node`-NAME → node-id inventory lookup plugs in
//! at the [`TargetResolver`] seam below (tests pass a node id the mock CP knows).

/// A parsed SSH target: the requested login and the node identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The Linux login the user requested (the SSH username's `login` half). Fed
    /// to `Authorize.requested_principal`; the CP confirms it against the
    /// RBAC-allowed logins — the client never picks a raw principal (§5.3).
    pub login: String,
    /// The target node identifier (the `node` half). Fed to `Authorize.node_id`
    /// after resolution through the [`TargetResolver`] seam.
    pub node: String,
}

/// A malformed username encoding. Kept coarse on purpose: the caller maps ANY
/// parse failure to the same generic pre-authz denial, so nothing about the
/// target is disclosed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("malformed SSH target username")]
pub struct TargetError;

/// Parse the username encoding `login<sep>node` (default separator `%`).
///
/// Requires exactly one separator with non-empty halves. A bare username (no
/// separator) is rejected here — wildcard-DNS / ProxyJump addressing (which omit
/// the separator) are Session Sixteen and resolve elsewhere.
pub fn parse_username(username: &str, separator: char) -> Result<Target, TargetError> {
    let (login, node) = username.split_once(separator).ok_or(TargetError)?;
    // A second separator is ambiguous under this encoding → reject (generic).
    if node.contains(separator) {
        return Err(TargetError);
    }
    if login.is_empty() || node.is_empty() {
        return Err(TargetError);
    }
    Ok(Target {
        login: login.to_string(),
        node: node.to_string(),
    })
}

/// The seam that maps a parsed target's `node` NAME to the node id the CP
/// authorizes against. Session Seven uses [`IdentityResolver`] (pass-through:
/// the tests hand the mock CP a node id directly); Session Sixteen attaches the
/// wildcard-DNS / ProxyJump / inventory-lookup resolvers here without touching
/// the negotiation or authorization code above.
pub trait TargetResolver: Send + Sync {
    /// Resolve `target.node` to the CP node identifier. An unknown node returns
    /// `None` → the caller issues a generic pre-authz denial (no disclosure).
    fn resolve_node_id(&self, target: &Target) -> Option<String>;
}

/// Pass-through resolver: the parsed `node` string *is* the node id (Session
/// Seven test/dev shape; the mock CP knows the id). Real name→id inventory
/// resolution arrives in Session Sixteen behind [`TargetResolver`].
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityResolver;

impl TargetResolver for IdentityResolver {
    fn resolve_node_id(&self, target: &Target) -> Option<String> {
        (!target.node.is_empty()).then(|| target.node.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login_and_node() {
        let t = parse_username("deploy%web-01", '%').unwrap();
        assert_eq!(t.login, "deploy");
        assert_eq!(t.node, "web-01");
    }

    #[test]
    fn rejects_missing_separator() {
        assert_eq!(parse_username("deploy", '%'), Err(TargetError));
    }

    #[test]
    fn rejects_empty_halves() {
        assert_eq!(parse_username("%web-01", '%'), Err(TargetError));
        assert_eq!(parse_username("deploy%", '%'), Err(TargetError));
        assert_eq!(parse_username("%", '%'), Err(TargetError));
    }

    #[test]
    fn rejects_second_separator() {
        assert_eq!(parse_username("deploy%web%evil", '%'), Err(TargetError));
    }

    #[test]
    fn identity_resolver_passes_node_through() {
        let t = parse_username("dba%db-7", '%').unwrap();
        assert_eq!(
            IdentityResolver.resolve_node_id(&t).as_deref(),
            Some("db-7")
        );
    }
}
