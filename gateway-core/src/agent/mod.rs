pub mod dial;
pub mod registry;
pub mod server;
pub mod stream;
#[cfg(feature = "test-agent")]
pub mod testclient;
pub mod token;
pub mod wire;

use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use crate::agent::wire::HEADER_LEN;

pub const CONTROL_PATH: &str = "/agent/v1/control";

pub const DIALBACK_PATH: &str = "/agent/v1/dialback";

/// A per-session byte relay on the same TLS server as the agent paths; the connecting peer
/// is a GATEWAY, not an agent.
pub const PEER_RELAY_PATH: &str = "/peer/v1/relay";

/// Bound on the `heartbeat_interval_secs` we propose in `HELLO_ACK`: below 1 is a
/// self-inflicted DoS, above 300 a dead peer goes undetected too long.
pub const HEARTBEAT_INTERVAL_SECS_RANGE: std::ops::RangeInclusive<u64> = 1..=300;

/// Bound on the `max_frame_bytes` we propose in `HELLO_ACK`: it must clear the inner leg's
/// max packet with headroom, and bound per-connection memory.
pub const MAX_FRAME_BYTES_RANGE: std::ops::RangeInclusive<usize> = 4096..=1_048_576;

/// The Agent <-> Gateway **wire** protocol range, `(major, minor)`. This is a DISTINCT
/// protocol from the CP <-> Gateway gRPC plane (`crate::version::PROTOCOL_*`): it reuses the
/// `ProtocolVersion`/`ComponentInfo` concept and the N-1 resolver, but it has its own version
/// line, and the Control Plane is not a party to it. Do NOT couple it to the gRPC version,
/// which is already at 1.1: advertising the gRPC max here would offer Agents a wire minor
/// that does not exist.
pub const WIRE_PROTOCOL_MIN: (u32, u32) = (1, 0);

pub const WIRE_PROTOCOL_MAX: (u32, u32) = (1, 0);

pub fn wire_component_info() -> crate::pb::ComponentInfo {
    crate::pb::ComponentInfo {
        name: crate::version::COMPONENT_NAME.to_string(),
        semver: crate::version::SEMVER.to_string(),
        protocol_min: Some(crate::version::protocol_version(WIRE_PROTOCOL_MIN)),
        protocol_max: Some(crate::version::protocol_version(WIRE_PROTOCOL_MAX)),
    }
}

/// The URI SAN scheme the CP stamps into an agent's identity certificate. A GATEWAY
/// identity cert instead carries `sessionlayer://gateway/<uuid>` + a dNSName = its name;
/// the HA peer identity is the NAME (the dNSName), so the gateway-vs-agent distinction on
/// the peer-relay path is "has no agent URI SAN".
const AGENT_URI_PREFIX: &str = "sessionlayer://agent/";

/// The URI SAN scheme the CP stamps into a GATEWAY identity certificate
/// (`sessionlayer://gateway/<uuid>`). Its PRESENCE is the positive gateway check on the
/// peer-relay path: a CA never issues this SAN to a non-gateway, so requiring it — not merely
/// the ABSENCE of an agent URI SAN — closes the residual where a leaf carrying only a
/// gateway-named dNSName could be mistaken for a gateway.
const GATEWAY_URI_PREFIX: &str = "sessionlayer://gateway/";

/// The peer an agent connection resolves to, taken **only** from its mTLS client
/// certificate — the CP stamped both SANs, so neither is self-asserted. `AgentHello`
/// deliberately has nowhere to claim an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPeer {
    pub agent_id: String,
    pub node_name: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerError {
    #[error("no client certificate presented")]
    NoCertificate,
    #[error("client certificate did not parse")]
    Parse,
    #[error("certificate does not resolve to exactly one agent identity")]
    NotOneAgent,
    #[error("certificate does not resolve to exactly one node name")]
    NotOneNode,
    #[error("certificate does not resolve to exactly one gateway identity")]
    NotOneGateway,
}

pub fn peer_identity(cert_der: &[u8]) -> Result<AgentPeer, PeerError> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|_| PeerError::Parse)?;

    let mut agent_ids = Vec::new();
    let mut node_names = Vec::new();
    for ext in cert.extensions() {
        let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() else {
            continue;
        };
        for name in &san.general_names {
            match name {
                GeneralName::URI(uri) => {
                    if let Some(id) = uri.strip_prefix(AGENT_URI_PREFIX) {
                        agent_ids.push(id.to_string());
                    }
                }
                GeneralName::DNSName(dns) => node_names.push(dns.to_string()),
                _ => {}
            }
        }
    }

    let [agent_id] = agent_ids.as_slice() else {
        return Err(PeerError::NotOneAgent);
    };
    let [node_name] = node_names.as_slice() else {
        return Err(PeerError::NotOneNode);
    };
    if agent_id.is_empty() || node_name.is_empty() {
        return Err(PeerError::NotOneAgent);
    }
    Ok(AgentPeer {
        agent_id: agent_id.clone(),
        node_name: node_name.clone(),
    })
}

/// Resolve a peer **gateway** NAME from its mTLS client certificate, for the peer-relay path.
///
/// The HA routing key is the gateway NAME (`gateway_identity.name`), which the CP stamps as
/// the **dNSName SAN** alongside a `sessionlayer://gateway/<uuid>` URI SAN. A gateway peer must
/// therefore satisfy BOTH: exactly one dNSName SAN (the name we return) AND a present gateway
/// URI SAN (the positive check). A certificate carrying an *agent* URI SAN is an agent —
/// refused on this gateway-only path. The relay token binding (`owner_gateway_id == this
/// name`) is the second, decisive check at the call site.
pub fn gateway_peer_identity(cert_der: &[u8]) -> Result<String, PeerError> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|_| PeerError::Parse)?;

    let mut dns_names = Vec::new();
    let mut has_gateway_uri = false;
    for ext in cert.extensions() {
        let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() else {
            continue;
        };
        for name in &san.general_names {
            match name {
                GeneralName::URI(uri) if uri.starts_with(AGENT_URI_PREFIX) => {
                    return Err(PeerError::NotOneGateway);
                }
                GeneralName::URI(uri) if uri.starts_with(GATEWAY_URI_PREFIX) => {
                    has_gateway_uri = true;
                }
                GeneralName::DNSName(dns) => dns_names.push(dns.to_string()),
                _ => {}
            }
        }
    }
    // Positive check: a gateway MUST carry the gateway URI SAN, not merely lack an agent one —
    // otherwise a leaf with a gateway-named dNSName but no gateway identity would pass.
    if !has_gateway_uri {
        return Err(PeerError::NotOneGateway);
    }
    let [name] = dns_names.as_slice() else {
        return Err(PeerError::NotOneGateway);
    };
    if name.is_empty() {
        return Err(PeerError::NotOneGateway);
    }
    Ok(name.clone())
}

/// `max_message_size`/`max_frame_size` are the DoS guard: an oversized frame is refused at
/// its **length header**, so it is never buffered. `write_buffer_size = 0` makes every message
/// an eager socket write, and the bounded `max_write_buffer_size` is what turns a blocked
/// socket into `poll_ready` ⇒ `Pending` — the backpressure the byte stream relies on.
pub fn ws_config(max_frame_bytes: usize) -> WebSocketConfig {
    let max_message = max_frame_bytes.saturating_add(HEADER_LEN);
    WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(0)
        .max_write_buffer_size(max_message.saturating_mul(2).saturating_add(1024))
        .max_message_size(Some(max_message))
        .max_frame_size(Some(max_message))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ca {
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    fn ca() -> Ca {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["Test mTLS CA".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        Ca {
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    fn leaf(ca: &Ca, sans: Vec<rcgen::SanType>) -> Vec<u8> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = sans;
        params.signed_by(&key, &ca.issuer).unwrap().der().to_vec()
    }

    fn uri(u: &str) -> rcgen::SanType {
        rcgen::SanType::URI(rcgen::string::Ia5String::try_from(u).unwrap())
    }

    fn dns(d: &str) -> rcgen::SanType {
        rcgen::SanType::DnsName(rcgen::string::Ia5String::try_from(d).unwrap())
    }

    #[test]
    fn resolves_the_agent_and_node_from_the_cert_sans() {
        let ca = ca();
        let der = leaf(
            &ca,
            vec![uri("sessionlayer://agent/agent-7"), dns("node-a")],
        );
        assert_eq!(
            peer_identity(&der).unwrap(),
            AgentPeer {
                agent_id: "agent-7".into(),
                node_name: "node-a".into(),
            }
        );
    }

    #[test]
    fn a_cert_that_does_not_resolve_to_exactly_one_agent_is_refused() {
        let ca = ca();
        let two = leaf(
            &ca,
            vec![
                uri("sessionlayer://agent/agent-7"),
                uri("sessionlayer://agent/agent-8"),
                dns("node-a"),
            ],
        );
        assert_eq!(peer_identity(&two), Err(PeerError::NotOneAgent));

        let none = leaf(&ca, vec![uri("sessionlayer://gateway/gw-1"), dns("node-a")]);
        assert_eq!(peer_identity(&none), Err(PeerError::NotOneAgent));
    }

    #[test]
    fn a_cert_that_does_not_resolve_to_exactly_one_node_is_refused() {
        let ca = ca();
        let two = leaf(
            &ca,
            vec![
                uri("sessionlayer://agent/agent-7"),
                dns("node-a"),
                dns("node-b"),
            ],
        );
        assert_eq!(peer_identity(&two), Err(PeerError::NotOneNode));

        let none = leaf(&ca, vec![uri("sessionlayer://agent/agent-7")]);
        assert_eq!(peer_identity(&none), Err(PeerError::NotOneNode));
    }

    #[test]
    fn garbage_is_not_a_certificate() {
        assert_eq!(peer_identity(&[]), Err(PeerError::Parse));
        assert_eq!(peer_identity(b"not a cert"), Err(PeerError::Parse));
    }

    #[test]
    fn gateway_peer_resolves_by_dns_name_and_refuses_agents() {
        let ca = ca();
        let gw = leaf(
            &ca,
            vec![dns("gw-A"), uri("sessionlayer://gateway/abc-uuid")],
        );
        assert_eq!(gateway_peer_identity(&gw).unwrap(), "gw-A");
        let dns_only = leaf(&ca, vec![dns("gw-B")]);
        assert_eq!(
            gateway_peer_identity(&dns_only),
            Err(PeerError::NotOneGateway)
        );
        let agent = leaf(&ca, vec![uri("sessionlayer://agent/a7"), dns("node-a")]);
        assert_eq!(gateway_peer_identity(&agent), Err(PeerError::NotOneGateway));
        let no_dns = leaf(&ca, vec![uri("sessionlayer://gateway/abc-uuid")]);
        assert_eq!(
            gateway_peer_identity(&no_dns),
            Err(PeerError::NotOneGateway)
        );
        let none = leaf(&ca, vec![uri("sessionlayer://decision-context-signer")]);
        assert_eq!(gateway_peer_identity(&none), Err(PeerError::NotOneGateway));
        assert_eq!(gateway_peer_identity(b"garbage"), Err(PeerError::Parse));
    }

    #[test]
    fn ws_config_bounds_the_frame_and_the_write_buffer() {
        let cfg = ws_config(65536);
        assert_eq!(cfg.max_message_size, Some(65536 + HEADER_LEN));
        assert_eq!(cfg.max_frame_size, Some(65536 + HEADER_LEN));
        assert!(cfg.max_write_buffer_size < usize::MAX);
        assert!(cfg.max_write_buffer_size > cfg.write_buffer_size);
    }
}
