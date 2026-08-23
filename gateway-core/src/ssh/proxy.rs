//! PROXY v2 parse + source IP (fail-closed; header trusted only from LB CIDR).

use crate::netmatch::Cidr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

const PREFIX_LEN: usize = 16;

const MAX_ADDR_LEN: usize = 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProxyError {
    #[error("connection from non-LB peer {0} rejected (PROXY protocol required)")]
    UntrustedPeer(IpAddr),
    #[error("missing/invalid PROXY v2 signature from LB peer")]
    BadSignature,
    #[error("unsupported PROXY protocol version (expected v2)")]
    BadVersion,
    #[error("invalid PROXY v2 command")]
    BadCommand,
    #[error("PROXY v2 address block too long ({0} bytes)")]
    TooLong(usize),
    #[error("truncated PROXY v2 header")]
    Truncated,
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
        _ => Family::Other,
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

fn source_from_block(prefix: &Prefix, block: &[u8], peer: IpAddr) -> Result<IpAddr, ProxyError> {
    if prefix.command == Command::Local {
        return Ok(peer);
    }
    match prefix.family {
        Family::Inet => {
            if block.len() < 12 {
                return Err(ProxyError::ShortAddress);
            }
            let src = [block[0], block[1], block[2], block[3]];
            Ok(IpAddr::V4(Ipv4Addr::from(src)))
        }
        Family::Inet6 => {
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

async fn read_v2<S: AsyncRead + Unpin>(stream: &mut S, peer: IpAddr) -> Result<IpAddr, ProxyError> {
    let mut prefix_buf = [0u8; PREFIX_LEN];
    read_exact(stream, &mut prefix_buf).await?;
    let prefix = parse_prefix(&prefix_buf)?;

    let mut block = vec![0u8; prefix.addr_len];
    read_exact(stream, &mut block).await?;
    source_from_block(&prefix, &block, peer)
}

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

/// Resolve real client source IP (fail-closed). Empty LB CIDRs: PROXY off. On error, caller MUST drop connection before SSH banner.
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
        h.push(0x21);
        h.push(0x11);
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&src);
        h.extend_from_slice(&[10, 0, 0, 1]);
        h.extend_from_slice(&[0x1F, 0x90]);
        h.extend_from_slice(&[0x00, 0x16]);
        h
    }

    fn v6_header(src: [u8; 16]) -> Vec<u8> {
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x21);
        h.push(0x21);
        h.extend_from_slice(&36u16.to_be_bytes());
        h.extend_from_slice(&src);
        h.extend_from_slice(&[0u8; 16]);
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
        src[0..2].copy_from_slice(&[0x20, 0x01]);
        src[2..4].copy_from_slice(&[0x0d, 0xb8]);
        src[15] = 7;
        let got = resolve(&v6_header(src), "10.1.1.1".parse().unwrap(), &lb())
            .await
            .unwrap();
        assert_eq!(got, "2001:db8::7".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn missing_header_from_lb_is_rejected() {
        let err = resolve(b"SSH-2.0-client\r\n", "10.1.1.1".parse().unwrap(), &lb())
            .await
            .unwrap_err();
        assert_eq!(err, ProxyError::BadSignature);
    }

    #[tokio::test]
    async fn header_from_non_lb_peer_is_rejected() {
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
        buf[12] = 0x11;
        assert!(matches!(parse_prefix(&buf), Err(ProxyError::BadVersion)));
    }

    #[test]
    fn prefix_rejects_bad_command() {
        let mut buf = [0u8; PREFIX_LEN];
        buf[..12].copy_from_slice(&V2_SIGNATURE);
        buf[12] = 0x2F;
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
        buf[12] = 0x21;
        buf[13] = 0x00;
        let prefix = parse_prefix(&buf).unwrap();
        let peer: IpAddr = "10.9.9.9".parse().unwrap();
        assert_eq!(source_from_block(&prefix, &[], peer).unwrap(), peer);
    }

    #[test]
    fn local_command_falls_back_to_peer() {
        let mut buf = [0u8; PREFIX_LEN];
        buf[..12].copy_from_slice(&V2_SIGNATURE);
        buf[12] = 0x20;
        buf[13] = 0x11;
        let prefix = parse_prefix(&buf).unwrap();
        let peer: IpAddr = "10.9.9.9".parse().unwrap();
        assert_eq!(source_from_block(&prefix, &[0u8; 12], peer).unwrap(), peer);
    }
}
