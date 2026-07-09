//! CP <-> Gateway version-negotiation client (`Handshake.Negotiate`).
//!
//! This is the ONLY RPC in Session One (per the frozen `handshake.proto`). It
//! proves the contract-first codegen and cross-repo wiring end to end: the CP
//! implements the server, the Gateway generates and calls the client here.
//!
//! SECURITY: transport security (mTLS + per-RPC session-bound authorization)
//! arrives in Session Four. Session One runs this over PLAINTEXT localhost for
//! the smoke test only — insecure-by-design, dev-only. The messages carry no
//! secrets, so negotiating before authentication is acceptable (see the SECURITY
//! note in `handshake.proto`).

use crate::pb::handshake_client::HandshakeClient;
use crate::pb::{ClientHello, ProtocolVersion, ServerHello};
use crate::version;

/// A failure while negotiating the protocol version with the Control Plane.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// The gRPC transport to the Control Plane could not be established.
    #[error("failed to connect to Control Plane at {endpoint}: {source}")]
    Connect {
        /// The endpoint that was dialed.
        endpoint: String,
        /// The underlying transport error.
        #[source]
        source: tonic::transport::Error,
    },

    /// `Negotiate` returned an error status. Notably `FAILED_PRECONDITION` when
    /// the peers share no common version (fail-closed per VERSIONING.md §3).
    #[error("Handshake.Negotiate failed: {0}")]
    Rpc(#[from] tonic::Status),

    /// The `ServerHello` omitted the selected version (malformed response).
    #[error("Control Plane returned no selected protocol version")]
    MissingSelectedVersion,

    /// The Control Plane selected a version outside this build's supported
    /// range — a contract violation; we refuse it rather than proceed.
    #[error("Control Plane selected protocol {selected} outside supported range {range}")]
    OutOfRange {
        /// The version the server selected.
        selected: String,
        /// This build's supported range.
        range: String,
    },
}

/// A successful negotiation: the resolved protocol version and the server's
/// advertised identity (diagnostics only).
#[derive(Debug, Clone)]
pub struct Negotiated {
    /// The resolved highest common protocol version.
    pub selected: ProtocolVersion,
    /// The Control Plane's advertised component name.
    pub server_name: String,
    /// The Control Plane's advertised build SemVer.
    pub server_semver: String,
}

impl Negotiated {
    /// The selected version formatted as `major.minor` (e.g. `1.0`).
    pub fn version_string(&self) -> String {
        version::format_version(&self.selected)
    }
}

/// Connect to the CP gRPC `Handshake` service at `endpoint`, advertise this
/// build's supported protocol range, and return the negotiated version.
///
/// `endpoint` is an HTTP(S) URL, e.g. `http://127.0.0.1:9090`. Session One runs
/// this over plaintext for the dev smoke test; mTLS arrives in Session Four.
pub async fn negotiate(endpoint: &str) -> Result<Negotiated, HandshakeError> {
    let connect_err = |source| HandshakeError::Connect {
        endpoint: endpoint.to_string(),
        source,
    };

    let channel = tonic::transport::Endpoint::from_shared(endpoint.to_string())
        .map_err(connect_err)?
        .connect()
        .await
        .map_err(connect_err)?;

    let mut client = HandshakeClient::new(channel);

    let request = tonic::Request::new(ClientHello {
        client: Some(version::component_info()),
    });

    let hello = client.negotiate(request).await?.into_inner();
    interpret(hello)
}

/// Validate and interpret a `ServerHello`, independent of transport so it is
/// directly unit-testable. Enforces that the selected version lies within this
/// build's supported range.
fn interpret(hello: ServerHello) -> Result<Negotiated, HandshakeError> {
    let selected = hello
        .selected
        .ok_or(HandshakeError::MissingSelectedVersion)?;

    let sel = (selected.major, selected.minor);
    if sel < version::PROTOCOL_MIN || sel > version::PROTOCOL_MAX {
        return Err(HandshakeError::OutOfRange {
            selected: version::format_version(&selected),
            range: version::protocol_range(),
        });
    }

    let server = hello.server.unwrap_or_default();
    Ok(Negotiated {
        selected,
        server_name: server.name,
        server_semver: server.semver,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::handshake_server::{Handshake, HandshakeServer};
    use crate::pb::ComponentInfo;

    /// A mock Control Plane `Handshake` server that resolves the highest common
    /// version exactly per VERSIONING.md, advertising a configurable range.
    #[derive(Clone)]
    struct MockCp {
        server_min: (u32, u32),
        server_max: (u32, u32),
    }

    #[tonic::async_trait]
    impl Handshake for MockCp {
        async fn negotiate(
            &self,
            request: tonic::Request<ClientHello>,
        ) -> Result<tonic::Response<ServerHello>, tonic::Status> {
            let client = request.into_inner().client.unwrap_or_default();
            let cmin = client.protocol_min.unwrap_or_default();
            let cmax = client.protocol_max.unwrap_or_default();

            match version::resolve_common_version(
                (cmin.major, cmin.minor),
                (cmax.major, cmax.minor),
                self.server_min,
                self.server_max,
            ) {
                Some((major, minor)) => Ok(tonic::Response::new(ServerHello {
                    server: Some(ComponentInfo {
                        name: "SessionLayer Control Plane".to_string(),
                        semver: "0.1.0".to_string(),
                        protocol_min: Some(version::protocol_version(self.server_min)),
                        protocol_max: Some(version::protocol_version(self.server_max)),
                    }),
                    selected: Some(ProtocolVersion { major, minor }),
                })),
                None => Err(tonic::Status::failed_precondition("no common version")),
            }
        }
    }

    /// Stand up the mock CP on an ephemeral loopback port. The listener is bound
    /// before returning, so the port is accepting connections and there is no
    /// connect race with the spawned serve loop. No running CP is required.
    async fn spawn_mock(cp: MockCp) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .serve_with_incoming(HandshakeServer::new(cp), incoming)
                .await
                .expect("mock CP server runs");
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn resolves_highest_common_version_against_mock_cp() {
        // Server speaks [1.0, 1.2]; this build speaks [1.0, 1.0] -> common 1.0.
        let (endpoint, _srv) = spawn_mock(MockCp {
            server_min: (1, 0),
            server_max: (1, 2),
        })
        .await;

        let negotiated = negotiate(&endpoint).await.expect("negotiation succeeds");
        assert_eq!(negotiated.version_string(), "1.0");
        assert_eq!(negotiated.selected, ProtocolVersion { major: 1, minor: 0 });
        assert_eq!(negotiated.server_name, "SessionLayer Control Plane");
    }

    #[tokio::test]
    async fn no_common_version_fails_closed() {
        // Server speaks only major 2 -> no overlap with our major-1 range.
        let (endpoint, _srv) = spawn_mock(MockCp {
            server_min: (2, 0),
            server_max: (2, 0),
        })
        .await;

        let err = negotiate(&endpoint)
            .await
            .expect_err("must fail closed on no common version");
        assert!(
            matches!(err, HandshakeError::Rpc(status) if status.code() == tonic::Code::FailedPrecondition),
            "expected FAILED_PRECONDITION"
        );
    }

    #[test]
    fn interpret_rejects_out_of_range_selection() {
        // A server that selected 2.0 (outside our [1.0, 1.0]) is refused.
        let hello = ServerHello {
            server: Some(ComponentInfo::default()),
            selected: Some(ProtocolVersion { major: 2, minor: 0 }),
        };
        assert!(matches!(
            interpret(hello),
            Err(HandshakeError::OutOfRange { .. })
        ));
    }

    #[test]
    fn interpret_rejects_missing_selection() {
        let hello = ServerHello {
            server: Some(ComponentInfo::default()),
            selected: None,
        };
        assert!(matches!(
            interpret(hello),
            Err(HandshakeError::MissingSelectedVersion)
        ));
    }
}
