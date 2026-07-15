//! The outbound-agent transport (Session Fourteen; Design §9.2/§10.2, FR-CONN-1/2/3,
//! FR-HA-8). Normative contract: `contracts/wire/agent-gateway-v1.md`.
//!
//! The **Agent dials out**; the Gateway never dials a node, so a node needs zero
//! inbound reachability. This module is the Gateway half: a mutually-authenticated
//! WebSocket server ([`server`]) that agents register a long-lived **control**
//! channel with, a single-use signed **dial-back token** ([`token`]), and a
//! [`NodeConnector`](crate::ssh::connector::NodeConnector) ([`dial`]) that signals the
//! owning Agent and waits for it to dial back with a spliced byte stream
//! ([`stream`]).
//!
//! **The seam is invariant (D21/D23).** Everything above `NodeConnector::connect()` —
//! the inner-leg certificate, no-TOFU host verification, the byte bridge, the recorder
//! — is byte-for-byte the agentless path. The agent model changes only *how the
//! Gateway obtains the `ByteStream`*, so a compromised Agent cannot bypass host
//! verification or the inner certificate: it does not hold, see, or influence either.

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

/// The long-lived control-channel path (contract §1).
pub const CONTROL_PATH: &str = "/agent/v1/control";

/// The per-session dial-back path (contract §1).
pub const DIALBACK_PATH: &str = "/agent/v1/dialback";

/// Normative bound on the `heartbeat_interval_secs` we propose in `HELLO_ACK`
/// (contract §3): below 1 is a self-inflicted DoS, above 300 a dead peer goes undetected
/// too long.
pub const HEARTBEAT_INTERVAL_SECS_RANGE: std::ops::RangeInclusive<u64> = 1..=300;

/// Normative bound on the `max_frame_bytes` we propose in `HELLO_ACK` (contract §3): it
/// must clear the inner leg's max packet with headroom, and bound per-connection memory.
pub const MAX_FRAME_BYTES_RANGE: std::ops::RangeInclusive<usize> = 4096..=1_048_576;

/// The Agent <-> Gateway **wire** protocol range, `(major, minor)`. This is a DISTINCT
/// protocol from the CP <-> Gateway gRPC plane (`crate::version::PROTOCOL_*`): it reuses
/// the `ProtocolVersion`/`ComponentInfo` *concept* and the N-1 resolver, but it has its own
/// version line, and the Control Plane is not a party to it (contract §1). Baseline **1.0**
/// (contract §3) — do NOT couple it to the gRPC version, which is already at 1.1; advertising
/// the gRPC max here would offer Agents a wire minor that does not exist and violate §3.
pub const WIRE_PROTOCOL_MIN: (u32, u32) = (1, 0);

/// Highest Agent <-> Gateway wire protocol this build speaks. Bump only when the framed
/// protocol itself gains a minor — never in lockstep with the gRPC plane.
pub const WIRE_PROTOCOL_MAX: (u32, u32) = (1, 0);

/// This Gateway's [`ComponentInfo`](crate::pb::ComponentInfo) for the wire preface: the
/// artifact identity (name + semver) with the **agent-wire** protocol range, not the gRPC
/// one.
pub fn wire_component_info() -> crate::pb::ComponentInfo {
    crate::pb::ComponentInfo {
        name: crate::version::COMPONENT_NAME.to_string(),
        semver: crate::version::SEMVER.to_string(),
        protocol_min: Some(crate::version::protocol_version(WIRE_PROTOCOL_MIN)),
        protocol_max: Some(crate::version::protocol_version(WIRE_PROTOCOL_MAX)),
    }
}

/// The URI SAN scheme the CP stamps into an agent's identity certificate.
const AGENT_URI_PREFIX: &str = "sessionlayer://agent/";

/// The peer an agent connection resolves to, taken **only** from its mTLS client
/// certificate — the CP stamped both SANs, so neither is self-asserted. `AgentHello`
/// deliberately has nowhere to claim an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPeer {
    /// From the URI SAN `sessionlayer://agent/<agent_id>`.
    pub agent_id: String,
    /// From the dNSName SAN — the node's enrollment name, and the join key between a
    /// session and the control channel that owns the node.
    pub node_name: String,
}

/// Why a client certificate does not resolve to exactly one agent (fail closed).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerError {
    /// The TLS handshake completed without a client certificate. (The verifier
    /// requires one, so this is belt-and-braces.)
    #[error("no client certificate presented")]
    NoCertificate,
    /// The client certificate did not parse as X.509 DER.
    #[error("client certificate did not parse")]
    Parse,
    /// Not exactly one `sessionlayer://agent/<id>` URI SAN.
    #[error("certificate does not resolve to exactly one agent identity")]
    NotOneAgent,
    /// Not exactly one dNSName SAN (the node name).
    #[error("certificate does not resolve to exactly one node name")]
    NotOneNode,
}

/// Resolve the agent peer from its mTLS client certificate (contract §1).
///
/// A certificate that does not resolve to **exactly one** agent — zero, or several
/// smuggled in as extra SANs — is refused rather than guessed at.
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

/// The WebSocket bounds both roles run under.
///
/// `max_message_size`/`max_frame_size` are the DoS guard the contract requires: an
/// oversized frame is refused at its **length header**, so it is never buffered.
/// `write_buffer_size = 0` makes every message an eager socket write, and the bounded
/// `max_write_buffer_size` is what turns a blocked socket into `poll_ready` ⇒
/// `Pending` — the backpressure the byte stream relies on.
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
        // Two agent URI SANs — an attempt to be two agents at once.
        let two = leaf(
            &ca,
            vec![
                uri("sessionlayer://agent/agent-7"),
                uri("sessionlayer://agent/agent-8"),
                dns("node-a"),
            ],
        );
        assert_eq!(peer_identity(&two), Err(PeerError::NotOneAgent));

        // No agent URI SAN at all (e.g. some other internal leaf).
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
    fn ws_config_bounds_the_frame_and_the_write_buffer() {
        let cfg = ws_config(65536);
        assert_eq!(cfg.max_message_size, Some(65536 + HEADER_LEN));
        assert_eq!(cfg.max_frame_size, Some(65536 + HEADER_LEN));
        // Bounded write buffering is what makes poll_ready a real backpressure gate.
        assert!(cfg.max_write_buffer_size < usize::MAX);
        assert!(cfg.max_write_buffer_size > cfg.write_buffer_size);
    }
}
