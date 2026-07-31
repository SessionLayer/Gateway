//! WORM PUT of ciphertext (no SigV4, no web-PKI, operator CA only).

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

pub enum UploadSource {
    Mem(Bytes),
    File { path: PathBuf, len: u64 },
}

impl UploadSource {
    fn content_length(&self) -> u64 {
        match self {
            UploadSource::Mem(b) => b.len() as u64,
            UploadSource::File { len, .. } => *len,
        }
    }

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
        SizeHint::with_exact(self.len)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("malformed upload URL")]
    Url,
    #[error("https upload requires a configured CA trust anchor")]
    NoTls,
    #[error("plain-http upload refused (https required)")]
    HttpsRequired,
    #[error("upload transport failure")]
    Transport,
    #[error("upload rejected by the object store (HTTP {0})")]
    Status(u16),
    #[error("upload timed out")]
    Timeout,
}

impl UploadError {
    pub fn is_retryable(&self) -> bool {
        match self {
            UploadError::Transport | UploadError::Timeout => true,
            UploadError::Status(code) => *code >= 500,
            UploadError::Url | UploadError::NoTls | UploadError::HttpsRequired => false,
        }
    }
}

pub struct HttpUploader {
    timeout: Duration,
    require_https: bool,
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl HttpUploader {
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
    let _conn = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));

    let mut builder = Request::builder()
        .method("PUT")
        .uri(&target.path_and_query)
        .header(hyper::header::HOST, &target.authority)
        .header(hyper::header::CONTENT_LENGTH, source.content_length());
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

struct UrlParts {
    https: bool,
    host: String,
    port: u16,
    authority: String,
    path_and_query: String,
}

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
