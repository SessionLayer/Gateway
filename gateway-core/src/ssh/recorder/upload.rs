//! The WORM object upload (Design §12.2, Part E; FR-DATA-2).
//!
//! A **dumb HTTP PUT** of the ciphertext object to the CP-issued presigned URL,
//! sending the credential's `required_headers` verbatim (they carry the
//! object-lock mode + retain-until-date that make the object WORM and are part of
//! the SigV4 signature — altering them breaks the signature, so the uploader
//! cannot strip the lock). The Gateway does **no** SigV4 in production; the bytes
//! never traverse the Control Plane. Uses only `hyper` (already transitive via
//! tonic) — no `reqwest`/`webpki-roots`. Plain-http (the MinIO E2E) needs no TLS;
//! https uses the existing rustls (ring) stack with an operator-configured CA
//! (fail closed when https is requested without one — no implicit web-PKI roots).
//!
//! The body is **streamed** from the source (a spilled temp file streams in
//! constant memory; a small in-memory recording sends its buffer directly), so a
//! large recording never doubles peak RAM at upload.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// The ciphertext object to upload: a small recording held in memory, or a spilled
/// temp file streamed from disk. Re-usable across retry attempts (each attempt
/// builds a fresh body).
pub enum UploadSource {
    /// The whole ciphertext object in memory (short session).
    Mem(Bytes),
    /// A spilled ciphertext temp file (large session), streamed at upload time.
    File {
        /// Path to the ciphertext temp file.
        path: PathBuf,
        /// Exact object length (the HTTP Content-Length).
        len: u64,
    },
}

impl UploadSource {
    fn content_length(&self) -> u64 {
        match self {
            UploadSource::Mem(b) => b.len() as u64,
            UploadSource::File { len, .. } => *len,
        }
    }

    /// Build a fresh streaming body for one upload attempt.
    fn body(&self) -> BoxBody<Bytes, std::io::Error> {
        match self {
            UploadSource::Mem(bytes) => Full::new(bytes.clone())
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
            UploadSource::File { path, len } => {
                let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(4);
                let path = path.clone();
                tokio::spawn(async move {
                    match tokio::fs::File::open(&path).await {
                        Ok(mut f) => {
                            let mut buf = vec![0u8; 64 * 1024];
                            loop {
                                match f.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if tx
                                            .send(Ok(Bytes::copy_from_slice(&buf[..n])))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        let _ = tx.send(Err(e)).await;
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                        }
                    }
                });
                ChannelBody { rx, len: *len }.boxed()
            }
        }
    }
}

/// A body whose frames arrive over a channel (the spilled-file reader task).
struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<std::io::Result<Bytes>>,
    len: u64,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(Frame::data(b)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        // Exact length ⇒ hyper sends Content-Length (S3/MinIO require it for PUT).
        SizeHint::with_exact(self.len)
    }
}

/// A failure PUTting the object (operator log; the user sees only the generic
/// recording-unavailable outcome). No untrusted response body is ever rendered.
#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    /// The presigned URL was malformed (scheme/host/port).
    #[error("malformed upload URL")]
    Url,
    /// https was requested but no CA trust anchor is configured (fail closed).
    #[error("https upload requires a configured CA trust anchor")]
    NoTls,
    /// A plain-http upload was attempted while https is required (fail closed).
    #[error("plain-http upload refused (https required)")]
    HttpsRequired,
    /// Transport failure (connect / TLS / write) — retryable.
    #[error("upload transport failure")]
    Transport,
    /// The store returned a non-2xx status. Only the numeric code is rendered.
    #[error("upload rejected by the object store (HTTP {0})")]
    Status(u16),
    /// The PUT did not complete within the configured bound — retryable.
    #[error("upload timed out")]
    Timeout,
}

impl UploadError {
    /// Whether a retry could plausibly succeed (transient transport/timeout/5xx),
    /// as opposed to a permanent client error (malformed URL, 4xx, config).
    pub fn is_retryable(&self) -> bool {
        match self {
            UploadError::Transport | UploadError::Timeout => true,
            UploadError::Status(code) => *code >= 500,
            UploadError::Url | UploadError::NoTls | UploadError::HttpsRequired => false,
        }
    }
}

/// A single-object HTTP(S) PUT uploader. Cheap to share (`Arc`).
pub struct HttpUploader {
    timeout: Duration,
    require_https: bool,
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl HttpUploader {
    /// Build an uploader bounding each PUT by `timeout`. `require_https` refuses a
    /// plain-http target (set `false` only for the E2E MinIO). `tls` (a rustls
    /// client config over the operator CA) is required for https targets.
    pub fn new(
        timeout: Duration,
        require_https: bool,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) -> Self {
        Self {
            timeout,
            require_https,
            tls,
        }
    }

    /// PUT `source` to `url`, sending `required_headers` verbatim. Succeeds only on
    /// a 2xx status (fail closed).
    pub async fn put(
        &self,
        url: &str,
        required_headers: &BTreeMap<String, String>,
        source: &UploadSource,
    ) -> Result<Option<String>, UploadError> {
        let target = parse_url(url)?;
        if target.https {
            if self.tls.is_none() {
                return Err(UploadError::NoTls);
            }
        } else if self.require_https {
            return Err(UploadError::HttpsRequired);
        }
        let fut = self.put_inner(&target, required_headers, source);
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(UploadError::Timeout),
        }
    }

    async fn put_inner(
        &self,
        target: &UrlParts,
        required_headers: &BTreeMap<String, String>,
        source: &UploadSource,
    ) -> Result<Option<String>, UploadError> {
        let tcp = TcpStream::connect((target.host.as_str(), target.port))
            .await
            .map_err(|_| UploadError::Transport)?;
        tcp.set_nodelay(true).ok();

        if target.https {
            let tls = self.tls.clone().ok_or(UploadError::NoTls)?;
            let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
                .map_err(|_| UploadError::Url)?;
            let stream = tokio_rustls::TlsConnector::from(tls)
                .connect(server_name, tcp)
                .await
                .map_err(|_| UploadError::Transport)?;
            send_put(TokioIo::new(stream), target, required_headers, source).await
        } else {
            send_put(TokioIo::new(tcp), target, required_headers, source).await
        }
    }
}

/// Aborts the spawned connection-driver task on ALL exit paths (success, error,
/// timeout — the future is dropped), so it never leaks (#13).
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn send_put<IO>(
    io: IO,
    target: &UrlParts,
    required_headers: &BTreeMap<String, String>,
    source: &UploadSource,
) -> Result<Option<String>, UploadError>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| UploadError::Transport)?;
    // The connection future must be driven; abort it on any exit (guard drop).
    let _conn = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));

    let mut builder = Request::builder()
        .method("PUT")
        .uri(&target.path_and_query)
        .header(hyper::header::HOST, &target.authority)
        .header(hyper::header::CONTENT_LENGTH, source.content_length());
    // The presigned signature covers `required_headers` (object-lock etc.); send
    // them verbatim. `host`/`content-length` are set above and never duplicated.
    for (k, v) in required_headers {
        if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    let request = builder.body(source.body()).map_err(|_| UploadError::Url)?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|_| UploadError::Transport)?;
    let status = response.status();
    // Capture the object-store version id (S3 `x-amz-version-id`) so replay/export
    // can pin THIS finalized version, not a later shadow PUT to the same key
    // (§15 crown-jewels; WORM Object Lock protects a version, not a key from a new
    // version). Do NOT read the (untrusted, possibly hostile-sized) response body.
    let version_id = response
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    drop(response);

    if status.is_success() {
        Ok(version_id)
    } else {
        Err(UploadError::Status(status.as_u16()))
    }
}

/// Build a rustls client config over an operator-provided CA PEM bundle, for an
/// https WORM store (no implicit web-PKI roots — the CA is the sole trust
/// anchor). The ring provider must already be installed process-wide.
pub fn build_upload_tls(ca_pem: &[u8]) -> Result<Arc<rustls::ClientConfig>, UploadError> {
    let ders = crate::mtls::pem_certs_to_der(ca_pem).map_err(|_| UploadError::NoTls)?;
    let mut roots = rustls::RootCertStore::empty();
    for der in ders {
        roots
            .add(rustls::pki_types::CertificateDer::from(der))
            .map_err(|_| UploadError::NoTls)?;
    }
    if roots.is_empty() {
        return Err(UploadError::NoTls);
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The pieces of a presigned URL the uploader needs.
struct UrlParts {
    https: bool,
    host: String,
    port: u16,
    authority: String,
    path_and_query: String,
}

/// Parse `http(s)://host[:port]/path?query` without a URL crate. Handles a
/// bracketed IPv6 literal.
fn parse_url(url: &str) -> Result<UrlParts, UploadError> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(UploadError::Url);
    };
    let (authority, path_and_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(UploadError::Url);
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let end = inner.find(']').ok_or(UploadError::Url)?;
        let host = inner[..end].to_string();
        let port = match inner[end + 1..].strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| UploadError::Url)?,
            None => default_port(https),
        };
        (host, port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse().map_err(|_| UploadError::Url)?)
    } else {
        (authority.to_string(), default_port(https))
    };
    Ok(UrlParts {
        https,
        host,
        port,
        authority: authority.to_string(),
        path_and_query: path_and_query.to_string(),
    })
}

fn default_port(https: bool) -> u16 {
    if https {
        443
    } else {
        80
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_url_with_port_and_query() {
        let u = parse_url("http://127.0.0.1:9000/bucket/obj?X-Amz-Signature=abc").unwrap();
        assert!(!u.https);
        assert_eq!(u.host, "127.0.0.1");
        assert_eq!(u.port, 9000);
        assert_eq!(u.authority, "127.0.0.1:9000");
        assert_eq!(u.path_and_query, "/bucket/obj?X-Amz-Signature=abc");
    }

    #[test]
    fn parses_https_default_port_and_ipv6() {
        let u = parse_url("https://example.com/key").unwrap();
        assert!(u.https);
        assert_eq!(u.port, 443);
        let v = parse_url("http://[::1]:9000/k").unwrap();
        assert_eq!(v.host, "::1");
        assert_eq!(v.port, 9000);
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(matches!(parse_url("ftp://x/y"), Err(UploadError::Url)));
    }

    #[test]
    fn retryable_classification() {
        assert!(UploadError::Transport.is_retryable());
        assert!(UploadError::Timeout.is_retryable());
        assert!(UploadError::Status(503).is_retryable());
        assert!(!UploadError::Status(403).is_retryable());
        assert!(!UploadError::HttpsRequired.is_retryable());
    }
}
