//! PROXY protocol v2 parsing + source-IP resolution (Session Seven, Part B).
//!
//! Behind an L4 load balancer the immediate TCP peer is the LB, not the user, so
//! the **real** client IP must come from a PROXY v2 header — and that header is
//! trustworthy **only** from a configured LB CIDR (2.3M internet SSH servers
//! accept spoofed headers; Design §15). This module resolves the real source IP
//! **fail-closed both ways** (FR-AUTH-14):
//!
//! - LB CIDRs empty → PROXY protocol is OFF; the TCP peer is the source (the
//!   single-instance / no-LB deployment).
//! - LB CIDRs set → PROXY protocol is REQUIRED. A header from an LB peer is
//!   parsed for the real IP; a **missing/malformed** header from an LB peer is
//!   rejected, and **any** connection from a non-LB peer is rejected (a header
//!   from it would be a spoof; its absence a bypass of the LB).
//!
//! The v2 parser is small, bounded, and exhaustively tested. Only the source
//! address is extracted (destination + ports + TLVs are ignored). Source IP is a
//! deny-only reducer downstream (FR-AUTH-15).

use crate::netmatch::Cidr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};

/// The 12-byte PROXY v2 signature (`\r\n\r\n\0\r\nQUIT\n`).
pub const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// The 16-byte fixed header (signature + ver/cmd + fam/proto + length).
const PREFIX_LEN: usize = 16;

/// Upper bound on the declared address-block length. The real families we parse
/// need ≤ 36 bytes; the spec allows TLVs up to a u16, but a hostile/oversized
/// length is refused (Tier-0 accept-path bound) rather than allocated.
const MAX_ADDR_LEN: usize = 1024;

/// A PROXY v2 parse / trust failure. Every variant is a rejection (fail closed);
/// the connection is dropped with **no SSH banner** (§7.1 row 1 semantics).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProxyError {
    /// The immediate TCP peer is not inside any trusted LB CIDR, but PROXY
    /// protocol is required — a header from it would be spoofable, so refuse.
    #[error("connection from non-LB peer {0} rejected (PROXY protocol required)")]
    UntrustedPeer(IpAddr),

    /// The 12-byte v2 signature was absent — an LB peer that did not prepend a
    /// PROXY header (or a raw connection past the LB). Missing → rejected.
    #[error("missing/invalid PROXY v2 signature from LB peer")]
    BadSignature,

    /// The version nibble was not 2 (only v2 is accepted; v1 text header is not).
    #[error("unsupported PROXY protocol version (expected v2)")]
    BadVersion,

    /// The command nibble was neither LOCAL (0) nor PROXY (1).
    #[error("invalid PROXY v2 command")]
    BadCommand,

    /// The declared address-block length exceeds the accept-path bound.
    #[error("PROXY v2 address block too long ({0} bytes)")]
    TooLong(usize),

    /// The stream ended before the full header could be read (truncated).
    #[error("truncated PROXY v2 header")]
    Truncated,

    /// The address block was shorter than the family requires.
    #[error("PROXY v2 address block too short for its family")]
    ShortAddress,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Local,
    Proxy,
}

#[derive(Debug, PartialEq, Eq)]
enum Family {
    Unspec,
    Inet,
    Inet6,
    Other,
}

struct Prefix {
    command: Command,
    family: Family,
    addr_len: usize,
}

/// Parse and validate the fixed 16-byte v2 prefix.
fn parse_prefix(buf: &[u8; PREFIX_LEN]) -> Result<Prefix, ProxyError> {
    if buf[..12] != V2_SIGNATURE {
        return Err(ProxyError::BadSignature);
    }
    if buf[12] >> 4 != 0x2 {
        return Err(ProxyError::BadVersion);
    }
    let command = match buf[12] & 0x0F {
        0x0 => Command::Local,
        0x1 => Command::Proxy,
        _ => return Err(ProxyError::BadCommand),
    };
    let family = match buf[13] >> 4 {
        0x0 => Family::Unspec,
        0x1 => Family::Inet,
        0x2 => Family::Inet6,
        _ => Family::Other, // AF_UNIX (3) etc. — no IP source to extract.
    };
    let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if addr_len > MAX_ADDR_LEN {
        return Err(ProxyError::TooLong(addr_len));
    }
    Ok(Prefix {
        command,
        family,
        addr_len,
    })
}

/// Extract the real source IP from a parsed prefix + its address block, falling
/// back to the immediate `peer` for LOCAL (health-check) and non-IP families
/// (per the PROXY spec: the receiver uses the real connection endpoints).
fn source_from_block(prefix: &Prefix, block: &[u8], peer: IpAddr) -> Result<IpAddr, ProxyError> {
    if prefix.command == Command::Local {
        return Ok(peer);
    }
    match prefix.family {
        Family::Inet => {
            // src(4) dst(4) sport(2) dport(2)
            if block.len() < 12 {
                return Err(ProxyError::ShortAddress);
            }
            let src = [block[0], block[1], block[2], block[3]];
            Ok(IpAddr::V4(Ipv4Addr::from(src)))
        }
        Family::Inet6 => {
            // src(16) dst(16) sport(2) dport(2)
            if block.len() < 36 {
                return Err(ProxyError::ShortAddress);
            }
            let mut src = [0u8; 16];
            src.copy_from_slice(&block[0..16]);
            Ok(IpAddr::V6(Ipv6Addr::from(src)))
        }
        Family::Unspec | Family::Other => Ok(peer),
    }
}

/// Read the full v2 header from `stream` and return the resolved source IP.
/// Assumes the caller has already confirmed the peer is a trusted LB (this reads
/// unconditionally). Errors are fail-closed rejections.
async fn read_v2<S: AsyncRead + Unpin>(stream: &mut S, peer: IpAddr) -> Result<IpAddr, ProxyError> {
    let mut prefix_buf = [0u8; PREFIX_LEN];
    read_exact(stream, &mut prefix_buf).await?;
    let prefix = parse_prefix(&prefix_buf)?;

    let mut block = vec![0u8; prefix.addr_len];
    read_exact(stream, &mut block).await?;
    source_from_block(&prefix, &block, peer)
}

/// `read_exact` that maps an early EOF to [`ProxyError::Truncated`].
async fn read_exact<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
) -> Result<(), ProxyError> {
    match stream.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(ProxyError::Truncated),
        Err(_) => Err(ProxyError::Truncated),
    }
}

/// Resolve the real client source IP for a freshly-accepted connection,
/// fail-closed per FR-AUTH-14.
///
/// - `lb_cidrs` empty → PROXY off; returns `peer` unchanged (no read).
/// - `lb_cidrs` set and `peer` ∈ LB → reads + parses a mandatory PROXY v2 header,
///   returning the header's source IP (missing/malformed → rejection).
/// - `lb_cidrs` set and `peer` ∉ LB → [`ProxyError::UntrustedPeer`] (rejected).
///
/// On any error the caller MUST drop the connection **before any SSH banner**.
pub async fn resolve_source_ip<S: AsyncRead + Unpin>(
    stream: &mut S,
    peer: IpAddr,
    lb_cidrs: &[Cidr],
) -> Result<IpAddr, ProxyError> {
    if lb_cidrs.is_empty() {
        return Ok(peer);
    }
    if !lb_cidrs.iter().any(|c| c.contains(peer)) {
        return Err(ProxyError::UntrustedPeer(peer));
    }
    read_v2(stream, peer).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_header(src: [u8; 4]) -> Vec<u8> {
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x21); // v2 | PROXY
        h.push(0x11); // INET | STREAM
        h.extend_from_slice(&12u16.to_be_bytes()); // addr block length
        h.extend_from_slice(&src); // src ip
        h.extend_from_slice(&[10, 0, 0, 1]); // dst ip
        h.extend_from_slice(&[0x1F, 0x90]); // sport
        h.extend_from_slice(&[0x00, 0x16]); // dport
        h
    }

    fn v6_header(src: [u8; 16]) -> Vec<u8> {
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x21); // v2 | PROXY
        h.push(0x21); // INET6 | STREAM
        h.extend_from_slice(&36u16.to_be_bytes());
        h.extend_from_slice(&src);
        h.extend_from_slice(&[0u8; 16]); // dst
        h.extend_from_slice(&[0x1F, 0x90]);
        h.extend_from_slice(&[0x00, 0x16]);
        h
    }

    async fn resolve(bytes: &[u8], peer: IpAddr, lb: &[Cidr]) -> Result<IpAddr, ProxyError> {
        let mut src: &[u8] = bytes;
        resolve_source_ip(&mut src, peer, lb).await
    }

    fn lb() -> Vec<Cidr> {
        vec![Cidr::parse("10.0.0.0/8").unwrap()]
    }

    #[tokio::test]
    async fn valid_v4_header_from_lb_yields_client_ip() {
        let got = resolve(
            &v4_header([203, 0, 113, 7]),
            "10.1.1.1".parse().unwrap(),
            &lb(),
        )
        .await
        .unwrap();
        assert_eq!(got, "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn valid_v6_header_from_lb_yields_client_ip() {
        let mut src = [0u8; 16];
        src[0..2].copy_from_slice(&[0x20, 0x01]); // 2001:db8::7
        src[2..4].copy_from_slice(&[0x0d, 0xb8]);
        src[15] = 7;
        let got = resolve(&v6_header(src), "10.1.1.1".parse().unwrap(), &lb())
            .await
            .unwrap();
        assert_eq!(got, "2001:db8::7".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn missing_header_from_lb_is_rejected() {
        // Raw SSH bytes (no PROXY header) from an LB peer → BadSignature.
        let err = resolve(b"SSH-2.0-client\r\n", "10.1.1.1".parse().unwrap(), &lb())
            .await
            .unwrap_err();
        assert_eq!(err, ProxyError::BadSignature);
    }

    #[tokio::test]
    async fn header_from_non_lb_peer_is_rejected() {
        // Even a well-formed header, if the immediate peer is not an LB, is a spoof.
        let err = resolve(
            &v4_header([203, 0, 113, 7]),
            "192.0.2.9".parse().unwrap(),
            &lb(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::UntrustedPeer(_)));
    }

    #[tokio::test]
    async fn no_lb_config_uses_peer_ip_without_reading() {
        let got = resolve(b"SSH-2.0-client", "192.0.2.5".parse().unwrap(), &[])
            .await
            .unwrap();
        assert_eq!(got, "192.0.2.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn prefix_rejects_bad_signature() {
        let mut buf = [0u8; PREFIX_LEN];
        buf[12] = 0x21;
        assert!(matches!(parse_prefix(&buf), Err(ProxyError::BadSignature)));
    }

    #[test]
    fn prefix_rejects_wrong_version() {
        let mut buf = [0u8; PREFIX_LEN];
        buf[..12].copy_from_slice(&V2_SIGNATURE);
        buf[12] = 0x11; // version 1
        assert!(matches!(parse_prefix(&buf), Err(ProxyError::BadVersion)));
    }

    #[test]
    fn prefix_rejects_bad_command() {
        let mut buf = [0u8; PREFIX_LEN];
        buf[..12].copy_from_slice(&V2_SIGNATURE);
        buf[12] = 0x2F; // v2, command 0xF
        assert!(matches!(parse_prefix(&buf), Err(ProxyError::BadCommand)));
    }

    #[test]
    fn prefix_rejects_oversized_length() {
        let mut buf = [0u8; PREFIX_LEN];
        buf[..12].copy_from_slice(&V2_SIGNATURE);
        buf[12] = 0x21;
        buf[13] = 0x11;
        buf[14..16].copy_from_slice(&(MAX_ADDR_LEN as u16 + 1).to_be_bytes());
        assert!(matches!(parse_prefix(&buf), Err(ProxyError::TooLong(_))));
    }

    #[tokio::test]
    async fn truncated_address_block_is_rejected() {
        // Declares 12 bytes of addresses but supplies only 4.
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x21);
        h.push(0x11);
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[203, 0, 113, 7]);
        let err = resolve(&h, "10.1.1.1".parse().unwrap(), &lb())
            .await
            .unwrap_err();
        assert_eq!(err, ProxyError::Truncated);
    }

    #[test]
    fn unspec_family_falls_back_to_peer() {
        let mut buf = [0u8; PREFIX_LEN];
        buf[..12].copy_from_slice(&V2_SIGNATURE);
        buf[12] = 0x21; // v2 PROXY
        buf[13] = 0x00; // UNSPEC
        let prefix = parse_prefix(&buf).unwrap();
        let peer: IpAddr = "10.9.9.9".parse().unwrap();
        assert_eq!(source_from_block(&prefix, &[], peer).unwrap(), peer);
    }

    #[test]
    fn local_command_falls_back_to_peer() {
        // A LOCAL command (LB health check) uses the real connection peer.
        let mut buf = [0u8; PREFIX_LEN];
        buf[..12].copy_from_slice(&V2_SIGNATURE);
        buf[12] = 0x20; // v2 LOCAL
        buf[13] = 0x11;
        let prefix = parse_prefix(&buf).unwrap();
        let peer: IpAddr = "10.9.9.9".parse().unwrap();
        assert_eq!(source_from_block(&prefix, &[0u8; 12], peer).unwrap(), peer);
    }
}
