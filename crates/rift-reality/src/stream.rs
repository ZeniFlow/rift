//! REALITY поверх tokio: `connect` (клиент) и `accept` (сервер с анти-зондированием).
//! Серверная логика — упрощённый `reality_server_handler` из shoes.

use std::io;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

use crate::crypto::tls_deframer::TlsDeframer;
use crate::crypto::{CryptoConnection, CryptoTlsStream, TlsReadMode};
use crate::reality::{
    DEFAULT_CIPHER_SUITES, RealityClientConfig, RealityClientConnection, RealityServerConfig,
    RealityServerConnection,
};

pub use crate::reality::{decode_private_key, decode_public_key, decode_short_id, generate_keypair};

/// Зашифрованный поток после рукопожатия REALITY.
pub type RealityStream = CryptoTlsStream<TcpStream>;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    /// SNI чужого сайта, под который маскируемся.
    pub server_name: String,
}

pub async fn connect(tcp: TcpStream, cfg: &ClientConfig) -> io::Result<RealityStream> {
    let conn = RealityClientConnection::new(RealityClientConfig {
        public_key: cfg.public_key,
        short_id: cfg.short_id,
        server_name: cfg.server_name.clone(),
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
    })?;
    CryptoTlsStream::handshake(tcp, CryptoConnection::new_reality_client(conn), TlsReadMode::Stream, &[]).await
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    /// Настоящий сайт с TLS 1.3, `host:port`. Чужие клиенты прозрачно проксируются на него.
    pub dest: String,
}

impl ServerConfig {
    fn dest_host(&self) -> &str {
        self.dest.rsplit_once(':').map_or(self.dest.as_str(), |(h, _)| h)
    }
}

const TLS_HEADER_LEN: usize = 5;
const CONTENT_HANDSHAKE: u8 = 22;

/// Принимает соединение. `Some` — свой клиент прошёл аутентификацию. `None` — чужой
/// (или сканер): его трафик уже проксируется на `dest` в фоне, как у обычного reverse-proxy.
pub async fn accept(mut client: TcpStream, cfg: &ServerConfig) -> io::Result<Option<RealityStream>> {
    // ponytail: ClientHello ждём одной TLS-записью (так шлют все браузеры и наш клиент).
    let mut header = [0u8; TLS_HEADER_LEN];
    client.read_exact(&mut header).await?;
    if header[0] != CONTENT_HANDSHAKE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "не TLS ClientHello"));
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut frame = header.to_vec();
    frame.resize(TLS_HEADER_LEN + len, 0);
    client.read_exact(&mut frame[TLS_HEADER_LEN..]).await?;

    // К dest подключаемся сразу, до проверки: тайминги как у обычного прокси.
    let mut dest = TcpStream::connect(&cfg.dest).await?;
    dest.write_all(&frame).await?;

    let mut conn = RealityServerConnection::new(RealityServerConfig {
        private_key: cfg.private_key,
        short_ids: cfg.short_ids.clone(),
        dest: cfg.dest_host().to_string(),
        max_time_diff: Some(60_000),
        min_client_version: None,
        max_client_version: None,
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
    })?;
    let auth = conn.validate_client_hello(&frame);

    // Читаем рукопожатие dest: ServerHello + CCS + зашифрованные записи (эвристика XTLS: 512 байт).
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut deframer = TlsDeframer::new();
    let mut records: Vec<Bytes> = Vec::new();
    let mut buf = vec![0u8; 8192];
    let mut complete = false;
    while !complete {
        // Есть ServerHello + CCS + зашифрованное и dest замолчал — рукопожатие отдано целиком
        // (маленький сертификат, всё в одной записи).
        let wait = if records.len() >= 3 { deadline.min(Instant::now() + Duration::from_millis(200)) } else { deadline };
        let n = match timeout_at(wait, dest.read(&mut buf)).await {
            Ok(Ok(0)) => return Err(io::Error::other("dest закрыл соединение во время рукопожатия")),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                complete = records.len() >= 3;
                break;
            }
        };
        deframer.feed(&buf[..n]);
        records.extend(deframer.next_records()?);
        complete = records.len() >= 6 || (records.len() >= 3 && records[2].len() > 512);
    }
    let remaining = deframer.into_remaining_data();

    if !complete || auth.is_err() {
        // Чужой или dest повёл себя странно: дальше мы просто прозрачный прокси до dest.
        tokio::spawn(async move {
            for r in records.iter().chain(std::iter::once(&remaining)) {
                if client.write_all(r).await.is_err() {
                    return;
                }
            }
            tokio::io::copy_bidirectional(&mut client, &mut dest).await.ok();
        });
        return Ok(None);
    }

    drop(dest);
    conn.build_server_response(records)?;
    let stream = CryptoTlsStream::handshake(
        client,
        CryptoConnection::new_reality_server(conn),
        TlsReadMode::Stream,
        &[],
    )
    .await?;
    Ok(Some(stream))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::net::TcpListener;
    use tokio_rustls::rustls;

    use super::*;

    /// Настоящий TLS 1.3 сайт: dest для REALITY. Отвечает "real-site" на любой запрос.
    async fn fake_site() -> (String, rustls::pki_types::CertificateDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec!["site.test".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        let mut buf = [0u8; 64];
                        let _ = tls.read(&mut buf).await;
                        let _ = tls.write_all(b"real-site").await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        (addr, der)
    }

    /// Мост: свои получают эхо, чужие уходят на dest.
    async fn bridge(cfg: ServerConfig) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Ok(Some(mut s)) = accept(tcp, &cfg).await {
                        let mut buf = [0u8; 64];
                        let n = s.read(&mut buf).await.unwrap();
                        s.write_all(&buf[..n]).await.unwrap();
                        s.flush().await.unwrap();
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn auth_client_tunnels_strangers_see_real_site() {
        let (dest, site_cert) = fake_site().await;
        let (private, public) = generate_keypair().unwrap();
        let short_id = decode_short_id("0123456789abcdef").unwrap();
        let bridge = bridge(ServerConfig {
            private_key: decode_private_key(&private).unwrap(),
            short_ids: vec![short_id],
            dest,
        })
        .await;
        let client = |public_key| ClientConfig { public_key, short_id, server_name: "site.test".into() };

        // Свой клиент: туннель работает.
        let tcp = TcpStream::connect(&bridge).await.unwrap();
        let mut s = connect(tcp, &client(decode_public_key(&public).unwrap())).await.unwrap();
        s.write_all(b"rift").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"rift");

        // Чужой ключ: рукопожатие не проходит.
        let (_, other_public) = generate_keypair().unwrap();
        let tcp = TcpStream::connect(&bridge).await.unwrap();
        assert!(connect(tcp, &client(decode_public_key(&other_public).unwrap())).await.is_err());

        // Сканер с обычным TLS видит настоящий сайт с его сертификатом.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(site_cert).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tcp = TcpStream::connect(&bridge).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("site.test").unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.unwrap();
        tls.write_all(b"GET /").await.unwrap();
        let mut got = Vec::new();
        tls.read_to_end(&mut got).await.ok();
        assert_eq!(got, b"real-site");
    }
}
