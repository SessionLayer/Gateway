//! CP ↔ Gateway version-negotiation client (Handshake.Negotiate); the ONLY RPC per frozen handshake.proto.
//! Runs on the production boot path over the mTLS channel `main.rs` builds with
//! `mtls::connect_bootstrap`; no secrets in the messages either way.

use crate::pb::handshake_client::HandshakeClient;
use crate::pb::{ClientHello, ProtocolVersion, ServerHello};
use crate::version;
use std::time::Duration;
use tonic::transport::Channel;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("failed to connect to Control Plane at {endpoint}: {source}")]
    Connect {
        endpoint: String,
        #[source]
        source: tonic::transport::Error,
    },

    #[error("Handshake.Negotiate failed (gRPC status {:?})", .0.code())]
    Rpc(#[from] tonic::Status),

    #[error("timed out negotiating with Control Plane at {endpoint} after {after:?}")]
    Timeout { endpoint: String, after: Duration },

    #[error("Control Plane returned no selected protocol version")]
    MissingSelectedVersion,

    #[error("Control Plane selected protocol {selected} outside supported range {range}")]
    OutOfRange { selected: String, range: String },
}

#[derive(Debug, Clone)]
pub struct Negotiated {
    pub selected: ProtocolVersion,
    pub server_name: String,
    pub server_semver: String,
}

impl Negotiated {
    pub fn version_string(&self) -> String {
        version::format_version(&self.selected)
    }
}

pub async fn negotiate(endpoint: &str) -> Result<Negotiated, HandshakeError> {
    negotiate_with_timeouts(endpoint, DEFAULT_CONNECT_TIMEOUT, DEFAULT_RPC_TIMEOUT).await
}

async fn negotiate_with_timeouts(
    endpoint: &str,
    connect_timeout: Duration,
    rpc_timeout: Duration,
) -> Result<Negotiated, HandshakeError> {
    let overall = connect_timeout + rpc_timeout;
    match tokio::time::timeout(
        overall,
        negotiate_inner(endpoint, connect_timeout, rpc_timeout),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(HandshakeError::Timeout {
            endpoint: endpoint.to_string(),
            after: overall,
        }),
    }
}

async fn negotiate_inner(
    endpoint: &str,
    connect_timeout: Duration,
    rpc_timeout: Duration,
) -> Result<Negotiated, HandshakeError> {
    let connect_err = |source| HandshakeError::Connect {
        endpoint: endpoint.to_string(),
        source,
    };

    let channel = tonic::transport::Endpoint::from_shared(endpoint.to_string())
        .map_err(connect_err)?
        .connect_timeout(connect_timeout)
        .timeout(rpc_timeout)
        .connect()
        .await
        .map_err(connect_err)?;

    negotiate_over_channel(channel).await
}

pub async fn negotiate_over_channel(channel: Channel) -> Result<Negotiated, HandshakeError> {
    let mut client = HandshakeClient::new(channel);
    let request = tonic::Request::new(ClientHello {
        client: Some(version::component_info()),
    });
    let hello = client.negotiate(request).await?.into_inner();
    interpret(hello)
}

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
        server_name: sanitize_diagnostic(&server.name),
        server_semver: sanitize_diagnostic(&server.semver),
    })
}

fn sanitize_diagnostic(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(128).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::handshake_server::{Handshake, HandshakeServer};
    use crate::pb::ComponentInfo;

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
        let (endpoint, _srv) = spawn_mock(MockCp {
            server_min: (1, 0),
            server_max: (1, 2),
        })
        .await;

        let negotiated = negotiate(&endpoint).await.expect("negotiation succeeds");
        assert_eq!(negotiated.version_string(), "1.1");
        assert_eq!(negotiated.selected, ProtocolVersion { major: 1, minor: 1 });
        assert_eq!(negotiated.server_name, "SessionLayer Control Plane");
    }

    #[tokio::test]
    async fn negotiates_n_minus_one_with_an_older_cp() {
        let (endpoint, _srv) = spawn_mock(MockCp {
            server_min: (1, 0),
            server_max: (1, 0),
        })
        .await;

        let negotiated = negotiate(&endpoint).await.expect("negotiation succeeds");
        assert_eq!(negotiated.version_string(), "1.0");
    }

    #[tokio::test]
    async fn no_common_version_fails_closed() {
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

    #[test]
    fn interpret_sanitizes_hostile_diagnostic_strings() {
        let hello = ServerHello {
            server: Some(ComponentInfo {
                name: "evil\u{1b}[2Jname\nline".to_string(),
                semver: "1.0\u{7f}\u{9b}".to_string(),
                ..Default::default()
            }),
            selected: Some(ProtocolVersion { major: 1, minor: 0 }),
        };
        let negotiated = interpret(hello).expect("selection is in range");
        assert!(!negotiated.server_name.chars().any(|c| c.is_control()));
        assert!(!negotiated.server_semver.chars().any(|c| c.is_control()));
        assert_eq!(negotiated.server_name, "evil[2Jnameline");
    }

    #[tokio::test]
    async fn negotiation_times_out_against_a_silent_peer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _conn = listener.accept().await;
            std::future::pending::<()>().await;
        });
        let endpoint = format!("http://{addr}");

        let result = tokio::time::timeout(
            Duration::from_secs(4),
            negotiate_with_timeouts(
                &endpoint,
                Duration::from_millis(250),
                Duration::from_millis(250),
            ),
        )
        .await;

        assert!(
            result.is_ok(),
            "negotiate must return within its own timeout, not hang"
        );
        let err = result
            .unwrap()
            .expect_err("silent peer must yield an error");
        assert!(
            matches!(
                err,
                HandshakeError::Timeout { .. }
                    | HandshakeError::Connect { .. }
                    | HandshakeError::Rpc(_)
            ),
            "expected a bounded timeout/connect/rpc error, got {err:?}"
        );
    }
}
