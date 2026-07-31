//! Target resolution: username encoding `login%node` into login + node identifier (FR-ADDR-1).
//! Parser never decides access; malformed/unknown targets yield generic pre-auth denial (no disclosure).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub login: String,
    pub node: String,
}

/// Malformed username encoding (coarse-grained; maps to generic pre-auth denial for no disclosure).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("malformed SSH target username")]
pub struct TargetError;

pub fn parse_username(username: &str, separator: char) -> Result<Target, TargetError> {
    let (login, node) = username.split_once(separator).ok_or(TargetError)?;
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

pub fn strip_dns_suffix(node: &str, suffixes: &[String]) -> String {
    let node_lower = node.to_ascii_lowercase();
    let mut best_cut: Option<usize> = None;
    for suffix in suffixes {
        let bare = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
        if bare.is_empty() {
            continue;
        }
        let dotted = format!(".{bare}");
        // Non-empty bare name required (node strictly longer than `.suffix`).
        if node_lower.ends_with(&dotted) && node.len() > dotted.len() {
            let cut = node.len() - dotted.len();
            if best_cut.is_none_or(|b| cut < b) {
                best_cut = Some(cut);
            }
        }
    }
    match best_cut {
        Some(cut) => node[..cut].to_string(),
        None => node.to_string(),
    }
}

pub trait TargetResolver: Send + Sync {
    fn resolve_node_id(&self, target: &Target) -> Option<String>;
}

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
