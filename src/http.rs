//! Minimal async HTTP client (the family pattern, mirrored from
//! unidpp-gateway's src/http.rs — dependency-light on purpose: no
//! reqwest, no TLS; the console talks to loopback services).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A response from a loopback service.
#[derive(Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

impl HttpResponse {
    /// The body as parsed JSON, if it parses.
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_str(&self.body).ok()
    }
}

/// GET `http://127.0.0.1:port/path` with a short timeout. Any failure
/// is a miss the caller renders as "unreachable" — the console never
/// lets one down service blank the dashboard.
pub async fn get(port: u16, path: &str) -> Option<HttpResponse> {
    request(port, "GET", path, None).await
}

async fn request(port: u16, method: &str, path: &str, body: Option<&str>) -> Option<HttpResponse> {
    let timeout = Duration::from_secs(2);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(("127.0.0.1", port)))
        .await
        .ok()?
        .ok()?;
    let body = body.unwrap_or("");
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.ok()?;
    if !body.is_empty() {
        stream.write_all(body.as_bytes()).await.ok()?;
    }
    // No write-half-close: hyper treats a client EOF before responding
    // as an abandoned connection. The server closes after its response
    // (Connection: close), which terminates the read.
    let mut raw = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut raw))
        .await
        .ok()?
        .ok()?;
    let text = raw;
    let header_end = text.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = String::from_utf8_lossy(&text[..header_end]).to_string();
    let status = headers
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let mut body_bytes = &text[header_end + 4..];
    if let Some(range) = headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        if body_bytes.len() >= range {
            body_bytes = &body_bytes[..range];
        }
    }
    Some(HttpResponse {
        status,
        body: String::from_utf8_lossy(body_bytes).to_string(),
    })
}

/// Probe many loopback targets at once. One unreachable service
/// costs its own timeout once, not the sum of everyone's — the
/// dashboard's contract when the operator reaches for it mid-incident.
pub async fn get_all(targets: &[(Option<u16>, &str)]) -> Vec<Option<HttpResponse>> {
    let mut set = tokio::task::JoinSet::new();
    for (i, (port, path)) in targets.iter().enumerate() {
        let port = *port;
        let path = path.to_string();
        set.spawn(async move {
            let resp = match port {
                Some(p) => get(p, &path).await,
                None => None,
            };
            (i, resp)
        });
    }
    let mut out: Vec<Option<HttpResponse>> = (0..targets.len()).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((i, resp)) = joined {
            out[i] = resp;
        }
    }
    out
}

/// The port of a `host:port` bind string (loopback services).
pub fn port_of(bind: &str) -> Option<u16> {
    bind.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
}
