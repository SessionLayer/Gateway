//! Minimal, dependency-free CIDR containment (Session Seven).
//!
//! The source-IP controls (FR-AUTH-13/14) need to test whether a client IP is
//! inside a configured set of CIDRs — the LB allow-list (PROXY-v2 trust) and the
//! global gate. A hand-rolled matcher keeps the Tier-0 supply chain tight and is
//! exhaustively testable; it handles IPv4 and IPv6 with prefix-masked equality.
//! Source IP is a **deny-only** reducer everywhere (FR-AUTH-15): these helpers
//! only ever *suppress* a connection, never grant one.

use std::net::IpAddr;

/// A parsed CIDR (`network/prefix`) that can test membership of an [`IpAddr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Parse a CIDR in `addr/prefix` form. A bare address (no `/`) is accepted as
    /// a host route (full-length prefix). Rejects a prefix longer than the address
    /// family allows, or an unparseable address (fail closed at config time).
    pub fn parse(s: &str) -> Result<Self, CidrError> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let network: IpAddr = addr_part
            .parse()
            .map_err(|_| CidrError(format!("invalid IP address in CIDR {s:?}")))?;
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = match prefix_part {
            None => max,
            Some(p) => {
                let n: u8 = p
                    .parse()
                    .map_err(|_| CidrError(format!("invalid prefix length in CIDR {s:?}")))?;
                if n > max {
                    return Err(CidrError(format!(
                        "prefix /{n} exceeds address family maximum /{max} in {s:?}"
                    )));
                }
                n
            }
        };
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Whether `ip` falls inside this CIDR. A v4 CIDR never contains a v6 address
    /// and vice versa (different families never match).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix_len)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix_len)
            }
            _ => false,
        }
    }
}

/// A CIDR parse failure (surfaced at config load, fail closed).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct CidrError(String);

/// Compare the first `prefix_len` bits of two equal-length octet strings.
fn prefix_eq(a: &[u8], b: &[u8], prefix_len: u8) -> bool {
    let full = (prefix_len / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix_len % 8;
    if rem == 0 {
        return true;
    }
    // Compare the remaining high `rem` bits of the next octet.
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Parse a list of CIDR strings, failing closed on the first bad entry.
pub fn parse_cidrs(list: &[String]) -> Result<Vec<Cidr>, CidrError> {
    list.iter().map(|s| Cidr::parse(s)).collect()
}

/// Whether `ip` is contained in ANY of `cidrs`. An empty set returns `false`
/// (callers decide what an empty allow-list means for their gate).
pub fn any_contains(cidrs: &[Cidr], ip: IpAddr) -> bool {
    cidrs.iter().any(|c| c.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn v4_prefix_membership() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(v4("10.1.2.3")));
        assert!(c.contains(v4("10.255.255.255")));
        assert!(!c.contains(v4("11.0.0.0")));
        assert!(!c.contains(v4("9.255.255.255")));
    }

    #[test]
    fn v4_non_byte_aligned_prefix() {
        let c = Cidr::parse("192.168.1.0/28").unwrap();
        assert!(c.contains(v4("192.168.1.15")));
        assert!(!c.contains(v4("192.168.1.16")));
    }

    #[test]
    fn host_route_and_slash32() {
        let bare = Cidr::parse("203.0.113.5").unwrap();
        assert!(bare.contains(v4("203.0.113.5")));
        assert!(!bare.contains(v4("203.0.113.6")));
        assert_eq!(bare, Cidr::parse("203.0.113.5/32").unwrap());
    }

    #[test]
    fn v6_prefix_membership_and_family_isolation() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains(v6("2001:db8:abcd::1")));
        assert!(!c.contains(v6("2001:db9::1")));
        // A v6 CIDR must never match a v4 address (and vice versa).
        assert!(!c.contains(v4("10.0.0.1")));
        let c4 = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(!c4.contains(v6("::ffff:10.0.0.1")));
    }

    #[test]
    fn zero_prefix_matches_whole_family_only() {
        let c = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains(v4("1.2.3.4")));
        assert!(!c.contains(v6("::1")), "v4 /0 must not match v6");
    }

    #[test]
    fn bad_cidrs_fail_closed() {
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("2001:db8::/129").is_err());
        assert!(Cidr::parse("not-an-ip/8").is_err());
        assert!(Cidr::parse("10.0.0.0/xx").is_err());
    }

    #[test]
    fn any_contains_over_a_set() {
        let set = parse_cidrs(&["10.0.0.0/8".into(), "192.168.0.0/16".into()]).unwrap();
        assert!(any_contains(&set, v4("192.168.5.5")));
        assert!(!any_contains(&set, v4("172.16.0.1")));
        assert!(
            !any_contains(&[], v4("10.0.0.1")),
            "empty set contains nothing"
        );
    }
}
