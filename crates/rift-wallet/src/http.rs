//! Минимальный HTTP/HTTPS-клиент для JSON-API: без перенаправлений, с таймаутом. Хватает для toncenter-подобных серверов.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::{io::{AsyncRead, AsyncWrite}, net::TcpStream};
use tokio_rustls::TlsConnector;
use url::Url;

const TIMEOUT: Duration = Duration::from_secs(20);
/// Ответ больше этого — не API, а мусор или атака.
const MAX_BODY: usize = 8 << 20;

fn tls() -> TlsConnector {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().expect("версии TLS").with_root_certificates(roots).with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

/// Возвращает (код ответа, тело).
pub async fn request(method: Method, url: &Url, headers: &[(&str, &str)], body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
    tokio::time::timeout(TIMEOUT, request_inner(method, url, headers, body)).await.context("сервер не ответил за 20 с")?
}

async fn request_inner(method: Method, url: &Url, headers: &[(&str, &str)], body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
    let host = url.host_str().context("в адресе нет хоста")?;
    let https = match url.scheme() {
        "https" => true,
        "http" => false,
        s => bail!("схема {s} не поддерживается"),
    };
    let port = url.port_or_known_default().context("нет порта")?;
    let tcp = TcpStream::connect((host, port)).await.with_context(|| format!("не удалось подключиться к {host}:{port}"))?;
    if https {
        let name = ServerName::try_from(host.to_string()).context("имя сервера")?;
        send(tls().connect(name, tcp).await.context("TLS")?, method, url, host, headers, body).await
    } else {
        send(tcp, method, url, host, headers, body).await
    }
}

async fn send<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: S, method: Method, url: &Url, host: &str, headers: &[(&str, &str)], body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(conn);
    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let mut req = Request::builder().method(method).uri(path).header("host", host).header("accept", "application/json").header("user-agent", "rift-wallet");
    if body.is_some() {
        req = req.header("content-type", "application/json");
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = sender.send_request(req.body(Full::new(Bytes::from(body.unwrap_or_default())))?).await?;
    let status = resp.status().as_u16();
    let collected = resp.into_body().collect().await?.to_bytes();
    if collected.len() > MAX_BODY {
        bail!("ответ слишком большой ({} байт)", collected.len());
    }
    Ok((status, collected.to_vec()))
}
