//! Хост сайта: принимает потоки `rift/http/0` (HTTP/1.1 поверх QUIC-стрима) и отвечает из
//! локального приложения (`Proxy`: Node.js, nginx, что угодно, по http или https) либо из папки (`Static`).
//!
//! Прокси потоковый, поэтому SSE и большие тела не буферизуются, а `Upgrade` (WebSocket) проходит насквозь.
//! Хост ставит заголовки, которым приложение может верить, потому что клиента он знает по ключу:
//! * `Rift-Client-Id: <NodeID>` — всегда перезаписывается, подделать нельзя;
//! * `Host` — адрес upstream (иначе Vite, Next и подобные отвечают «host not allowed»), исходный — в `X-Forwarded-Host`;
//! * `X-Forwarded-Proto: https` (браузер Rift показывает сайты как https).

use std::{
    convert::Infallible,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::Incoming,
    header::{self, HeaderMap, HeaderName, HeaderValue},
    service::service_fn,
    upgrade,
};
use hyper_util::rt::TokioIo;
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::TlsConnector;

use crate::NodeId;

pub const HTTP_ALPN: &[u8] = b"rift/http/0";
const MAX_RESPONSE: usize = 64 * 1024 * 1024;

pub(crate) type Body = BoxBody<Bytes, hyper::Error>;

fn body(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

fn text(status: StatusCode, msg: impl Into<Bytes>) -> Response<Body> {
    let mut r = Response::new(body(msg));
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    r
}

// ---------------------------------------------------------------- хост

#[derive(Debug, Clone)]
pub enum Backend {
    Proxy(Proxy),
    Static(Arc<Path>),
}

#[derive(Debug, Clone)]
pub struct Host {
    backend: Backend,
}

impl Host {
    /// Прокси на локальное приложение: `host:port`, `http://…` или `https://…`.
    /// `insecure` — не проверять сертификат upstream (self-signed на localhost).
    pub fn proxy(upstream: &str, insecure: bool) -> Result<Self> {
        Ok(Self { backend: Backend::Proxy(Proxy::parse(upstream, insecure)?) })
    }

    /// Статический сайт из папки (собранный React/Vue): неизвестные пути без расширения → `index.html`.
    pub fn static_dir(dir: &Path) -> Result<Self> {
        let root = dir.canonicalize().with_context(|| format!("нет папки {}", dir.display()))?;
        if !root.is_dir() {
            bail!("{} — не папка", root.display());
        }
        Ok(Self { backend: Backend::Static(root.into()) })
    }
}

impl ProtocolHandler for Host {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let client = conn.remote_id();
        while let Ok((send, recv)) = conn.accept_bi().await {
            let backend = self.backend.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(tokio::io::join(recv, send));
                let svc = service_fn(move |req| {
                    let backend = backend.clone();
                    async move { Ok::<_, Infallible>(backend.handle(req, client).await) }
                });
                hyper::server::conn::http1::Builder::new()
                    .half_close(true) // клиент закрывает свою сторону сразу после запроса
                    .serve_connection(io, svc)
                    .with_upgrades()
                    .await
                    .ok();
            });
        }
        Ok(())
    }
}

impl Backend {
    async fn handle(&self, req: Request<Incoming>, client: NodeId) -> Response<Body> {
        match self {
            Backend::Proxy(p) => match p.forward(req, client).await {
                Ok(r) => r,
                Err(e) => text(StatusCode::BAD_GATEWAY, format!("rift: upstream недоступен: {e:#}\n")),
            },
            Backend::Static(root) => serve_static(root, &req).await,
        }
    }
}

// ---------------------------------------------------------------- прокси

#[derive(Clone)]
pub struct Proxy {
    addr: String,
    host_header: HeaderValue,
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Proxy({}{})", if self.tls.is_some() { "https://" } else { "http://" }, self.addr)
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Для `--upstream-insecure`: принимает любой сертификат.
#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl Proxy {
    pub fn parse(upstream: &str, insecure: bool) -> Result<Self> {
        let (tls, rest) = match upstream.split_once("://") {
            Some(("https", r)) => (true, r),
            Some(("http", r)) => (false, r),
            Some((s, _)) => bail!("схема {s}:// не поддерживается (http или https)"),
            None => (false, upstream),
        };
        let authority = rest.trim_end_matches('/');
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h, p.parse::<u16>().context("кривой порт upstream")?),
            _ => (authority, if tls { 443 } else { 80 }),
        };
        let host = host.trim_matches(|c| c == '[' || c == ']');
        let tls = if tls {
            let config = if insecure {
                rustls::ClientConfig::builder_with_provider(provider())
                    .with_safe_default_protocol_versions()?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AcceptAny(provider())))
                    .with_no_client_auth()
            } else {
                let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
                rustls::ClientConfig::builder_with_provider(provider())
                    .with_safe_default_protocol_versions()?
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            };
            let name = ServerName::try_from(host.to_string()).map_err(|e| anyhow!("имя для TLS: {e}"))?;
            Some((TlsConnector::from(Arc::new(config)), name))
        } else {
            None
        };
        Ok(Self {
            addr: format!("{host}:{port}"),
            host_header: HeaderValue::from_str(&format!("{host}:{port}"))?,
            tls,
        })
    }

    async fn forward(&self, mut req: Request<Incoming>, client: NodeId) -> Result<Response<Body>> {
        let wants_upgrade = req.headers().contains_key(header::UPGRADE)
            && header_has_token(req.headers(), header::CONNECTION, "upgrade");
        let client_upgrade = upgrade::on(&mut req);
        let (mut parts, incoming) = req.into_parts();

        // Приложение должно видеть исходное имя и настоящего клиента.
        if let Some(h) = parts.headers.get(header::HOST).cloned() {
            parts.headers.insert(HeaderName::from_static("x-forwarded-host"), h);
        }
        strip_hop_by_hop(&mut parts.headers, wants_upgrade);
        for h in ["rift-client-id", "forwarded", "x-forwarded-for", "x-forwarded-proto"] {
            parts.headers.remove(h);
        }
        parts.headers.insert(HeaderName::from_static("rift-client-id"), HeaderValue::from_str(&client.to_string())?);
        parts.headers.insert(HeaderName::from_static("x-forwarded-proto"), HeaderValue::from_static("https"));
        parts.headers.insert(header::HOST, self.host_header.clone());
        parts.uri = parts.uri.path_and_query().map_or_else(|| Uri::from_static("/"), |pq| Uri::try_from(pq.as_str()).unwrap_or_else(|_| Uri::from_static("/")));
        parts.version = hyper::Version::HTTP_11;
        let upstream_req = Request::from_parts(parts, incoming);

        let tcp = TcpStream::connect(&self.addr).await.with_context(|| format!("не удалось подключиться к {}", self.addr))?;
        let mut resp = match &self.tls {
            None => send_over(TokioIo::new(tcp), upstream_req).await?,
            Some((connector, name)) => {
                let tls = connector.connect(name.clone(), tcp).await.context("TLS с upstream")?;
                send_over(TokioIo::new(tls), upstream_req).await?
            }
        };

        let switching = resp.status() == StatusCode::SWITCHING_PROTOCOLS;
        if switching {
            let upstream_upgrade = upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(c), Ok(u)) = (client_upgrade.await, upstream_upgrade.await) {
                    tokio::io::copy_bidirectional(&mut TokioIo::new(c), &mut TokioIo::new(u)).await.ok();
                }
            });
        }
        let (mut parts, incoming) = resp.into_parts();
        strip_hop_by_hop(&mut parts.headers, switching);
        Ok(Response::from_parts(parts, incoming.boxed()))
    }
}

async fn send_over<T>(io: T, req: Request<Incoming>) -> Result<Response<Incoming>>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        conn.with_upgrades().await.ok();
    });
    Ok(sender.send_request(req).await?)
}

fn header_has_token(h: &HeaderMap, name: HeaderName, token: &str) -> bool {
    h.get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
}

/// Заголовки, которые относятся к одному соединению, а не к сообщению. При апгрейде нужны `Connection`/`Upgrade`.
fn strip_hop_by_hop(h: &mut HeaderMap, keep_upgrade: bool) {
    for name in ["keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding"] {
        h.remove(name);
    }
    if !keep_upgrade {
        h.remove(header::CONNECTION);
        h.remove(header::UPGRADE);
    }
}

// ---------------------------------------------------------------- статика

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref() {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("avif") => "image/avif",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("wasm") => "application/wasm",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("mp3") => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Путь запроса → путь внутри `root`. `None`, если пытаются выйти из папки.
fn resolve_static(root: &Path, url_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(url_path)?;
    let mut p = root.to_path_buf();
    for seg in decoded.split('/').filter(|s| !s.is_empty()) {
        if seg == ".." || seg == "." || seg.contains(['\\', '\0']) {
            return None;
        }
        p.push(seg);
    }
    Some(p)
}

async fn read_file(root: &Path, path: &Path) -> Option<(Vec<u8>, PathBuf)> {
    // Символическая ссылка не должна выводить за пределы папки.
    let real = tokio::fs::canonicalize(path).await.ok()?;
    if !real.starts_with(root) {
        return None;
    }
    let real = if real.is_dir() { real.join("index.html") } else { real };
    Some((tokio::fs::read(&real).await.ok()?, real))
}

async fn serve_static(root: &Path, req: &Request<Incoming>) -> Response<Body> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return text(StatusCode::METHOD_NOT_ALLOWED, "rift: только GET и HEAD\n");
    }
    let Some(path) = resolve_static(root, req.uri().path()) else {
        return text(StatusCode::NOT_FOUND, "rift: не найдено\n");
    };
    let found = match read_file(root, &path).await {
        Some(f) => Some(f),
        // SPA: маршрут без расширения («/cart/42») отдаёт index.html, а несуществующий файл («/app.js») — 404.
        None if path.extension().is_none() => read_file(root, &root.join("index.html")).await,
        None => None,
    };
    let Some((bytes, real)) = found else {
        return text(StatusCode::NOT_FOUND, "rift: не найдено\n");
    };
    let mut r = Response::new(if req.method() == Method::HEAD { body(Bytes::new()) } else { body(bytes.clone()) });
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type(&real)));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    r
}

// ---------------------------------------------------------------- клиент

/// Один запрос «открыл поток → отправил байты → прочитал всё до конца».
pub async fn fetch(endpoint: &Endpoint, host: impl Into<EndpointAddr>, request: &[u8]) -> Result<Vec<u8>> {
    let conn = endpoint.connect(host, HTTP_ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(request).await?;
    send.shutdown().await?;
    let body = recv.read_to_end(MAX_RESPONSE).await?;
    conn.close(0u32.into(), b"bye");
    Ok(body)
}

pub fn get_request(name: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {name}\r\nUser-Agent: rift\r\nConnection: close\r\n\r\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use std::{future::Future, time::Duration};

    use http_body_util::StreamBody;
    use hyper::body::Frame;
    use iroh::{RelayMode, SecretKey};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Notify,
    };
    use tokio_stream::wrappers::ReceiverStream;

    use super::*;
    use crate::{Config, Node};

    type UBody = BoxBody<Bytes, Infallible>;

    fn ubody(s: impl Into<Bytes>) -> UBody {
        Full::new(s.into()).boxed()
    }

    async fn node(host: Option<Host>) -> Node {
        let extra: Vec<(Vec<u8>, crate::Handler)> = host.into_iter().map(|h| (HTTP_ALPN.to_vec(), Box::new(h) as crate::Handler)).collect();
        Node::bind(Config {
            key: SecretKey::generate(),
            relay_mode: RelayMode::Disabled,
            lan: false,
            proxy: None,
            bridge: None,
            relay_ca: None,
            vpn: None,
            extra,
        })
        .await
        .unwrap()
    }

    /// HTTP/1.1-сервер приложения на свободном порту.
    async fn upstream<F, Fut>(handler: F) -> String
    where
        F: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Response<UBody>> + Send + 'static,
    {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = l.accept().await {
                let handler = handler.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |r| {
                        let handler = handler.clone();
                        async move { Ok::<_, Infallible>(handler(r).await) }
                    });
                    hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).with_upgrades().await.ok();
                });
            }
        });
        addr
    }

    fn h(r: &Request<Incoming>, name: &str) -> String {
        r.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string()
    }

    /// Поднимает хост с бэкендом `host` и отдаёт (клиентская нода, хост-нода).
    async fn pair(host: Host) -> (Node, Node) {
        (node(None).await, node(Some(host)).await)
    }

    fn split(resp: &[u8]) -> (String, Vec<u8>) {
        let i = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("конец заголовков");
        (String::from_utf8_lossy(&resp[..i]).into_owned(), resp[i + 4..].to_vec())
    }

    async fn get(c: &Node, hn: &Node, req: &str) -> (String, String) {
        let raw = fetch(c.endpoint(), hn.endpoint().addr(), req.as_bytes()).await.unwrap();
        let (head, body) = split(&raw);
        (head, String::from_utf8_lossy(&body).into_owned())
    }

    fn req(method: &str, path: &str, extra: &str) -> String {
        format!("{method} {path} HTTP/1.1\r\nHost: shop.brand\r\nConnection: close\r\n{extra}\r\n")
    }

    #[tokio::test]
    async fn proxy_sets_trusted_headers_and_ignores_spoofed_ones() {
        let up = upstream(|r| async move {
            let b = format!(
                "path={} host={} id={} fwd_host={} proto={} xff={} fwd={}",
                r.uri(), h(&r, "host"), h(&r, "rift-client-id"), h(&r, "x-forwarded-host"),
                h(&r, "x-forwarded-proto"), h(&r, "x-forwarded-for"), h(&r, "forwarded"),
            );
            Response::new(ubody(b))
        })
        .await;
        let (c, hn) = pair(Host::proxy(&up, false).unwrap()).await;
        let spoof = "Rift-Client-Id: deadbeef\r\nX-Forwarded-For: 1.2.3.4\r\nForwarded: for=6.6.6.6\r\nX-Forwarded-Proto: http\r\n";
        let (head, body) = get(&c, &hn, &req("GET", "/a/b?x=1", spoof)).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(body.contains("path=/a/b?x=1"), "{body}");
        assert!(body.contains(&format!("host={up}")), "{body}");
        assert!(body.contains(&format!("id={}", c.id())), "{body}");
        assert!(body.contains("fwd_host=shop.brand"), "{body}");
        assert!(body.contains("proto=https"), "{body}");
        assert!(body.contains("xff=- fwd=-"), "{body}");
        assert!(!body.contains("deadbeef"));
    }

    #[tokio::test]
    async fn request_bodies_and_statuses_pass_through() {
        let up = upstream(|mut r| async move {
            let m = r.method().clone();
            let bytes = r.body_mut().collect().await.unwrap().to_bytes();
            let mut resp = Response::new(ubody(format!("{m} got {} bytes", bytes.len())));
            *resp.status_mut() = StatusCode::CREATED;
            resp.headers_mut().insert("x-app", HeaderValue::from_static("yes"));
            resp
        })
        .await;
        let (c, hn) = pair(Host::proxy(&up, false).unwrap()).await;
        let payload = "x".repeat(300_000);
        let (head, body) = get(&c, &hn, &req("POST", "/up", &format!("Content-Length: {}\r\n\r\n{payload}", payload.len()))).await;
        assert!(head.starts_with("HTTP/1.1 201"), "{head}");
        assert!(head.to_lowercase().contains("x-app: yes"));
        assert_eq!(body, "POST got 300000 bytes");
    }

    #[tokio::test]
    async fn upgrade_passes_through_both_ways() {
        let up = upstream(|mut r| async move {
            if r.headers().get("upgrade").is_some_and(|v| v == "echo") {
                let on = upgrade::on(&mut r);
                tokio::spawn(async move {
                    let mut io = TokioIo::new(on.await.unwrap());
                    let mut buf = [0u8; 64];
                    while let Ok(n) = io.read(&mut buf).await {
                        if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
                let mut resp = Response::new(ubody(""));
                *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                resp.headers_mut().insert("connection", HeaderValue::from_static("upgrade"));
                resp.headers_mut().insert("upgrade", HeaderValue::from_static("echo"));
                resp
            } else {
                Response::new(ubody("no upgrade"))
            }
        })
        .await;
        let (c, hn) = pair(Host::proxy(&up, false).unwrap()).await;
        let conn = c.endpoint().connect(hn.endpoint().addr(), HTTP_ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(req("GET", "/ws", "Upgrade: echo\r\n").replace("Connection: close", "Connection: Upgrade").as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 256];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await.expect("ответ").unwrap().unwrap();
            head.extend_from_slice(&buf[..n]);
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
        // после 101 это уже сырой двунаправленный канал
        send.write_all(b"ping").await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await.expect("эхо").unwrap().unwrap();
        assert_eq!(&buf[..n], b"ping");
        send.write_all(b"again").await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await.expect("эхо 2").unwrap().unwrap();
        assert_eq!(&buf[..n], b"again");
    }

    #[tokio::test]
    async fn streaming_responses_are_not_buffered() {
        let go = Arc::new(Notify::new());
        let go_up = go.clone();
        let up = upstream(move |_| {
            let go = go_up.clone();
            async move {
                let (tx, rx) = tokio::sync::mpsc::channel(4);
                tokio::spawn(async move {
                    tx.send(Ok(Frame::data(Bytes::from("data: one\n\n")))).await.ok();
                    go.notified().await; // второе событие — только когда клиент уже получил первое
                    tx.send(Ok(Frame::data(Bytes::from("data: two\n\n")))).await.ok();
                });
                let mut r = Response::new(StreamBody::new(ReceiverStream::new(rx)).boxed());
                r.headers_mut().insert("content-type", HeaderValue::from_static("text/event-stream"));
                r
            }
        })
        .await;
        let (c, hn) = pair(Host::proxy(&up, false).unwrap()).await;
        let conn = c.endpoint().connect(hn.endpoint().addr(), HTTP_ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(req("GET", "/events", "Accept: text/event-stream\r\n").as_bytes()).await.unwrap();
        let (mut got, mut buf) = (Vec::new(), [0u8; 512]);
        let mut read_until = async |needle: &str, got: &mut Vec<u8>| {
            while !String::from_utf8_lossy(got).contains(needle) {
                let n = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf))
                    .await
                    .unwrap_or_else(|_| panic!("прокси держит данные: {needle:?} не пришло, получено {:?}", String::from_utf8_lossy(got)))
                    .unwrap()
                    .expect("поток закрылся");
                got.extend_from_slice(&buf[..n]);
            }
        };
        read_until("data: one", &mut got).await;
        assert!(!String::from_utf8_lossy(&got).contains("data: two"));
        go.notify_one();
        read_until("data: two", &mut got).await;
    }

    #[tokio::test]
    async fn https_upstream_with_self_signed_cert() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = l.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    let svc = service_fn(|r: Request<Incoming>| async move {
                        Ok::<_, Infallible>(Response::new(ubody(format!("secure host={}", h(&r, "host")))))
                    });
                    hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await.ok();
                });
            }
        });
        let url = format!("https://localhost:{port}");

        let (c, hn) = pair(Host::proxy(&url, true).unwrap()).await;
        let (head, body) = get(&c, &hn, &req("GET", "/", "")).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(body, format!("secure host=localhost:{port}"));

        // Без --upstream-insecure self-signed не принимается.
        let (c, hn) = pair(Host::proxy(&url, false).unwrap()).await;
        let (head, _) = get(&c, &hn, &req("GET", "/", "")).await;
        assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    }

    #[tokio::test]
    async fn dead_upstream_is_502() {
        let (c, hn) = pair(Host::proxy("127.0.0.1:1", false).unwrap()).await;
        let (head, body) = get(&c, &hn, &req("GET", "/", "")).await;
        assert!(head.starts_with("HTTP/1.1 502"), "{head}");
        assert!(body.contains("upstream недоступен"), "{body}");
    }

    #[test]
    fn upstream_urls() {
        let addr = |u: &str| Proxy::parse(u, false).unwrap().addr;
        assert_eq!(addr("127.0.0.1:3000"), "127.0.0.1:3000");
        assert_eq!(addr("http://localhost:3000/"), "localhost:3000");
        assert_eq!(addr("http://localhost"), "localhost:80");
        assert_eq!(addr("https://example.com"), "example.com:443");
        assert_eq!(addr("http://[::1]:8080"), "::1:8080");
        assert!(Proxy::parse("ftp://x", false).is_err());
        assert!(Proxy::parse("localhost:notaport", false).is_err());
    }

    #[tokio::test]
    async fn static_site_spa_and_path_safety() {
        let base = std::env::temp_dir().join(format!("rift-static-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let root = base.join("site");
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::write(root.join("index.html"), "<h1>home</h1>").unwrap();
        std::fs::write(root.join("assets/app.js"), "console.log(1)").unwrap();
        std::fs::write(base.join("secret.txt"), "TOP SECRET").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(base.join("secret.txt"), root.join("link.txt")).unwrap();

        let (c, hn) = pair(Host::static_dir(&root).unwrap()).await;
        let g = async |path: &str| get(&c, &hn, &req("GET", path, "")).await;

        let (head, body) = g("/").await;
        assert!(head.starts_with("HTTP/1.1 200") && head.to_lowercase().contains("text/html"), "{head}");
        assert_eq!(body, "<h1>home</h1>");
        let (head, body) = g("/assets/app.js").await;
        assert!(head.to_lowercase().contains("text/javascript"), "{head}");
        assert_eq!(body, "console.log(1)");
        // SPA: маршрут без расширения отдаёт index.html, несуществующий файл — 404.
        let (head, body) = g("/cart/42").await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(body, "<h1>home</h1>");
        assert!(g("/missing.js").await.0.starts_with("HTTP/1.1 404"));
        // Выход из папки: прямой, закодированный, через символическую ссылку.
        for p in ["/../secret.txt", "/%2e%2e/secret.txt", "/assets/../../secret.txt", "/%2e%2e%2fsecret.txt", "/link.txt"] {
            let (head, body) = g(p).await;
            assert!(!body.contains("SECRET"), "{p} отдал секрет");
            assert!(head.starts_with("HTTP/1.1 404") || head.starts_with("HTTP/1.1 200"), "{p}: {head}");
            if head.starts_with("HTTP/1.1 200") {
                assert_eq!(body, "<h1>home</h1>", "{p}: ожидался только SPA-fallback");
            }
        }
        // Методы.
        let (head, _) = get(&c, &hn, &req("POST", "/", "Content-Length: 0\r\n")).await;
        assert!(head.starts_with("HTTP/1.1 405"), "{head}");
        let (head, body) = get(&c, &hn, &req("HEAD", "/", "")).await;
        assert!(head.starts_with("HTTP/1.1 200") && head.to_lowercase().contains("content-length: 13"), "{head}");
        assert!(body.is_empty());
        std::fs::remove_dir_all(base).ok();
    }
}
