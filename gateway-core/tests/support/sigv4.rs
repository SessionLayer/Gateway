//! A minimal AWS SigV4 **presigner** + tiny HTTP client — TEST SUPPORT ONLY.
//!
//! There is no aws-sdk in Rust, so the in-process mock CP mints a real presigned
//! PUT to the MinIO container itself (over `hmac` + `sha2`, both already deps),
//! exactly as the production CP's WORM-credential issuer would. The Gateway then
//! does a dumb PUT with the returned headers verbatim. This module also provides a
//! small hyper HTTP helper so the test can create the object-lock bucket and
//! GET/DELETE the stored object to assert encryption + WORM.
//!
//! NEVER compiled into the Gateway binary (it lives under `tests/`).

use std::collections::BTreeMap;

use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;

type HmacSha256 = Hmac<Sha256>;

/// An S3/MinIO target the presigner signs against.
#[derive(Clone)]
pub struct S3Target {
    /// `host:port` reachable by the Gateway (also the signed `Host`).
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    pub bucket: String,
}

/// Presign an S3 request (query-parameter auth). `signed_headers` are extra
/// headers that MUST be sent verbatim by the caller (e.g. object-lock). Returns
/// the presigned URL + the headers map the caller sends (excluding `host`, which
/// the client sets from the authority).
pub fn presign(
    t: &S3Target,
    method: &str,
    path: &str,
    extra_query: &[(&str, &str)],
    signed_headers: &[(&str, &str)],
    expires_secs: u64,
) -> (String, BTreeMap<String, String>) {
    let now = time::OffsetDateTime::now_utc();
    let amzdate = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let datestamp = &amzdate[..8];
    let scope = format!("{datestamp}/{}/s3/aws4_request", t.region);

    // Canonical (sorted, lowercased) headers — always includes host.
    let mut headers: Vec<(String, String)> = vec![("host".to_string(), t.endpoint.clone())];
    for (k, v) in signed_headers {
        headers.push((k.to_lowercase(), v.to_string()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let signed_headers_str = headers
        .iter()
        .map(|(k, _)| k.clone())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    // Canonical query string (sorted, URI-encoded); includes any subresource.
    let mut query: Vec<(String, String)> = vec![
        ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
        (
            "X-Amz-Credential".into(),
            format!("{}/{}", t.access_key, scope),
        ),
        ("X-Amz-Date".into(), amzdate.clone()),
        ("X-Amz-Expires".into(), expires_secs.to_string()),
        ("X-Amz-SignedHeaders".into(), signed_headers_str.clone()),
    ];
    for (k, v) in extra_query {
        query.push((k.to_string(), v.to_string()));
    }
    query.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_uri = uri_encode(path, false); // keep '/'
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers_str}\nUNSIGNED-PAYLOAD"
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );

    let signing_key = derive_key(&t.secret_key, datestamp, &t.region);
    let signature = hex(&hmac(&signing_key, string_to_sign.as_bytes()));

    let url = format!(
        "http://{}{}?{}&X-Amz-Signature={}",
        t.endpoint, canonical_uri, canonical_query, signature
    );
    let required: BTreeMap<String, String> = signed_headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    (url, required)
}

fn derive_key(secret: &str, datestamp: &str, region: &str) -> [u8; 32] {
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, b"s3");
    hmac(&k_service, b"aws4_request")
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// AWS URI-encoding: unreserved chars pass through; `/` is kept only when
/// `encode_slash` is false (path segments).
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// An ISO-8601 UTC instant `n` days from now (an object-lock retain-until date).
pub fn retain_until_days(days: i64) -> String {
    let t = time::OffsetDateTime::now_utc() + time::Duration::days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// A tiny HTTP/1.1 client for the test to drive MinIO directly (create bucket,
/// GET/DELETE the object). Plain HTTP only. Returns `(status, body)`.
pub async fn http_send(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("http only"))?;
    let (authority, path_and_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority);
    let port: u16 = authority
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(80);

    let tcp = TcpStream::connect((host, port)).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    let conn = tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(path_and_query)
        .header(hyper::header::HOST, authority);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = builder.body(Full::new(Bytes::from(body)))?;
    let response = sender.send_request(request).await?;
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await?.to_bytes().to_vec();
    conn.abort();
    Ok((status, bytes))
}
