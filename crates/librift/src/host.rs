//! Хост сайта: принимает потоки `rift/http/0` и гонит их в локальное приложение (Node.js, nginx…).
//! Это прозрачный TCP-туннель, поэтому HTTP/1.1, WebSocket и SSE проходят как есть.
//!
//! ponytail: заголовки (`Host`, `Rift-Client-Id`) не переписываются — нужен HTTP-разбор (hyper).
//! Upstream по https пока не поддержан.

use std::sync::Arc;

use anyhow::Result;
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use tokio::{io::AsyncWriteExt, net::TcpStream};

pub const HTTP_ALPN: &[u8] = b"rift/http/0";
const MAX_RESPONSE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Host {
    upstream: Arc<str>,
}

impl Host {
    /// `upstream` — `host:port` локального приложения.
    pub fn new(upstream: impl Into<Arc<str>>) -> Self {
        Self { upstream: upstream.into() }
    }
}

impl ProtocolHandler for Host {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        while let Ok((send, recv)) = conn.accept_bi().await {
            let upstream = self.upstream.clone();
            tokio::spawn(async move {
                let Ok(mut tcp) = TcpStream::connect(&*upstream).await else { return };
                let mut io = tokio::io::join(recv, send);
                tokio::io::copy_bidirectional(&mut io, &mut tcp).await.ok();
            });
        }
        Ok(())
    }
}

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
