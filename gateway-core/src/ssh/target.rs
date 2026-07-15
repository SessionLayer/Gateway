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

/// Strip a configured wildcard-DNS suffix from a parsed node target (Session Sixteen, Part B,
/// Design §11, FR-ADDR-2).
///
/// Under the ssh_config convenience `Host *.ssh.corp` → `Hostname gw`, `User %r%%%h`, an
/// `ssh user@web-01.ssh.corp` reaches the Gateway as the username `user%web-01.ssh.corp`; the
/// `%` [`parse_username`] split yields `node = "web-01.ssh.corp"`. With a configured suffix
/// `ssh.corp` this returns the bare node name `web-01`, which then goes to the name→id resolution
/// (Part A: `Authorize.node_name` → CP `findByName`).
///
/// Rules: DNS is case-insensitive; a leading dot on a configured suffix is optional; the node must
/// end with `.<suffix>` and leave a **non-empty** bare name (a node equal to the suffix is left
/// unchanged); the **most-specific (longest) matching** suffix wins; at most one suffix is
/// stripped; a node matching no configured suffix is returned unchanged (so the plain `login%node`
/// path is untouched). This is a pure normalization — it makes no access decision; an unknown name
/// still yields a generic no-disclosure deny at the CP.
pub fn strip_dns_suffix(node: &str, suffixes: &[String]) -> String {
    let node_lower = node.to_ascii_lowercase();
    let mut best_cut: Option<usize> = None;
    for suffix in suffixes {
        let bare = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
        if bare.is_empty() {
            continue;
        }
        let dotted = format!(".{bare}");
        // Require a non-empty bare name left of the suffix (node strictly longer than `.suffix`).
        if node_lower.ends_with(&dotted) && node.len() > dotted.len() {
            let cut = node.len() - dotted.len();
            // The longest suffix cuts earliest (smallest index) → prefer the most specific.
            if best_cut.is_none_or(|b| cut < b) {
                best_cut = Some(cut);
            }
        }
    }
    match best_cut {
        // Slice the ORIGINAL (case-preserved) node; ASCII lowercasing kept byte offsets stable.
        Some(cut) => node[..cut].to_string(),
        None => node.to_string(),
    }
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

    fn suffixes(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn wildcard_dns_the_full_parse_then_strip_flow() {
        // ssh user@web-01.ssh.corp  →  ssh_config User %r%%%h  →  username "user%web-01.ssh.corp".
        let t = parse_username("user%web-01.ssh.corp", '%').unwrap();
        assert_eq!(t.login, "user");
        assert_eq!(t.node, "web-01.ssh.corp");
        assert_eq!(
            strip_dns_suffix(&t.node, &suffixes(&["ssh.corp"])),
            "web-01",
            "the configured suffix is stripped to the bare node name"
        );
    }

    #[test]
    fn strip_accepts_a_leading_dot_and_is_case_insensitive() {
        assert_eq!(
            strip_dns_suffix("web-01.ssh.corp", &suffixes(&[".ssh.corp"])),
            "web-01"
        );
        // DNS is case-insensitive on the SUFFIX; the bare name keeps its original case.
        assert_eq!(
            strip_dns_suffix("Web-01.SSH.Corp", &suffixes(&["ssh.corp"])),
            "Web-01"
        );
    }

    #[test]
    fn strip_prefers_the_most_specific_suffix() {
        // Both match; the longest (most specific) wins.
        assert_eq!(
            strip_dns_suffix(
                "db.prod.ssh.corp",
                &suffixes(&["ssh.corp", "prod.ssh.corp"])
            ),
            "db"
        );
    }

    #[test]
    fn strip_is_a_noop_when_nothing_matches() {
        // A bare name (the plain login%node path) is untouched.
        assert_eq!(
            strip_dns_suffix("web-01", &suffixes(&["ssh.corp"])),
            "web-01"
        );
        // A different domain is untouched (only configured suffixes strip).
        assert_eq!(
            strip_dns_suffix("web-01.other.net", &suffixes(&["ssh.corp"])),
            "web-01.other.net"
        );
        // No configured suffixes ⇒ wildcard DNS disabled ⇒ untouched.
        assert_eq!(strip_dns_suffix("web-01.ssh.corp", &[]), "web-01.ssh.corp");
        // A node EQUAL to the suffix would leave an empty bare name ⇒ left unchanged.
        assert_eq!(
            strip_dns_suffix("ssh.corp", &suffixes(&["ssh.corp"])),
            "ssh.corp"
        );
        // Blank/whitespace suffix entries are ignored.
        assert_eq!(
            strip_dns_suffix("web-01.ssh.corp", &suffixes(&["", "  ", "."])),
            "web-01.ssh.corp"
        );
    }
}
