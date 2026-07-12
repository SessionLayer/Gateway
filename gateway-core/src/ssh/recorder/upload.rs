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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

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
    /// Transport failure (connect / TLS / write).
    #[error("upload transport failure")]
    Transport,
    /// The store returned a non-2xx status. Only the numeric code is rendered.
    #[error("upload rejected by the object store (HTTP {0})")]
    Status(u16),
    /// The PUT did not complete within the configured bound.
    #[error("upload timed out")]
    Timeout,
}

/// A single-object HTTP(S) PUT uploader. Cheap to share (`Arc`).
pub struct HttpUploader {
    timeout: Duration,
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl HttpUploader {
    /// Build an uploader bounding each PUT by `timeout`. `tls` (a rustls client
    /// config over the operator CA) is required for https targets; `None` still
    /// serves plain-http targets (the E2E MinIO).
    pub fn new(timeout: Duration, tls: Option<Arc<rustls::ClientConfig>>) -> Self {
        Self { timeout, tls }
    }

    /// PUT `body` to `url`, sending `required_headers` verbatim. Succeeds only on a
    /// 2xx status (fail closed).
    pub async fn put(
        &self,
        url: &str,
        required_headers: &BTreeMap<String, String>,
        body: Vec<u8>,
    ) -> Result<(), UploadError> {
        let target = parse_url(url)?;
        let fut = self.put_inner(&target, required_headers, body);
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(UploadError::Timeout),
        }
    }

    async fn put_inner(
        &self,
        target: &UrlParts,
        required_headers: &BTreeMap<String, String>,
        body: Vec<u8>,
    ) -> Result<(), UploadError> {
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
            send_put(TokioIo::new(stream), target, required_headers, body).await
        } else {
            send_put(TokioIo::new(tcp), target, required_headers, body).await
        }
    }
}

async fn send_put<IO>(
    io: IO,
    target: &UrlParts,
    required_headers: &BTreeMap<String, String>,
    body: Vec<u8>,
) -> Result<(), UploadError>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| UploadError::Transport)?;
    // The connection future must be driven; run it alongside the request.
    let conn = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method("PUT")
        .uri(&target.path_and_query)
        .header(hyper::header::HOST, &target.authority);
    // The presigned signature covers `required_headers` (object-lock etc.); send
    // them verbatim. `host` is set from the authority above (never duplicated).
    for (k, v) in required_headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    let request = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| UploadError::Url)?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|_| UploadError::Transport)?;
    let status = response.status();
    // Drain the (small) response body so the connection closes cleanly; never
    // render its content (untrusted).
    let _ = response.into_body().collect().await;
    conn.abort();

    if status.is_success() {
        Ok(())
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
        // IPv6 literal: host between brackets, optional :port after ']'.
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
}
