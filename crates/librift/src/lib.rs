//! librift — ядро Rift. Фаза 0: ключ ноды, соединения через iroh (relay + hole punching), ping.

use std::{
    fmt,
    io::{ErrorKind, Write},
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use iroh::{
    Endpoint,
    endpoint::{Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};

pub use url::Url;
pub use iroh::{EndpointAddr, EndpointId as NodeId, RelayMode, RelayUrl, SecretKey, TransportAddr};

pub const PING_ALPN: &[u8] = b"rift/ping/0";

/// Читает ключ ноды из файла или создаёт новый. Никогда не перезаписывает существующий файл.
pub fn load_or_create_key(path: &Path) -> Result<SecretKey> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("{}: ключ должен быть 32 байта", path.display()))?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let key = SecretKey::generate();
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            opts.open(path)
                .and_then(|mut f| f.write_all(&key.to_bytes()))
                .with_context(|| format!("не удалось записать ключ в {}", path.display()))?;
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("не удалось прочитать {}", path.display())),
    }
}

pub mod vpn;

/// Настройки ноды.
pub struct Config {
    pub key: SecretKey,
    /// `RelayMode::Default` — публичные relay n0, только для разработки.
    pub relay_mode: RelayMode,
    /// Искать ноды в локальной сети через mDNS.
    pub lan: bool,
    /// HTTP CONNECT-прокси для трафика к relay: сюда подключается маскирующий транспорт
    /// (Xray / sing-box / shoes с REALITY и т.п.). Прямые UDP-пути через прокси не идут.
    pub proxy: Option<url::Url>,
    pub vpn: Option<vpn::Vpn>,
}

impl Config {
    pub fn relay_mode(relays: Vec<RelayUrl>) -> RelayMode {
        if relays.is_empty() {
            RelayMode::Default
        } else {
            RelayMode::Custom(relays.into_iter().collect())
        }
    }
}

/// Нода Rift: iroh-endpoint + обработчики протоколов.
pub struct Node {
    router: Router,
}

impl Node {
    pub async fn bind(cfg: Config) -> Result<Self> {
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(cfg.key)
            .relay_mode(cfg.relay_mode);
        if let Some(proxy) = cfg.proxy {
            builder = builder.proxy_url(proxy);
        }
        #[cfg(test)]
        {
            builder = builder.ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify());
        }
        if cfg.lan {
            builder = builder.address_lookup(MdnsAddressLookup::builder().service_name("rift"));
        }
        let mut router = Router::builder(builder.bind().await?).accept(PING_ALPN, Pong);
        if let Some(vpn) = cfg.vpn {
            router = router.accept(vpn::VPN_ALPN, vpn);
        }
        Ok(Self { router: router.spawn() })
    }

    pub fn endpoint(&self) -> &Endpoint {
        self.router.endpoint()
    }

    pub fn id(&self) -> NodeId {
        self.endpoint().id()
    }

    pub async fn pinger(&self, addr: impl Into<EndpointAddr>) -> Result<Pinger> {
        let conn = self.endpoint().connect(addr, PING_ALPN).await?;
        let (send, recv) = conn.open_bi().await?;
        Ok(Pinger { conn, send, recv, seq: 0 })
    }

    pub async fn shutdown(self) -> Result<()> {
        self.router.shutdown().await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Direct,
    Relay,
    Unknown,
}

impl fmt::Display for PathKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PathKind::Direct => "напрямую",
            PathKind::Relay => "через relay",
            PathKind::Unknown => "?",
        })
    }
}

pub struct Pinger {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    seq: u64,
}

impl Pinger {
    /// Один ping: 8 байт туда, эхо обратно. Возвращает RTT и текущий путь.
    pub async fn ping(&mut self) -> Result<(Duration, PathKind)> {
        self.seq += 1;
        let out = self.seq.to_be_bytes();
        let start = Instant::now();
        self.send.write_all(&out).await?;
        let mut back = [0u8; 8];
        self.recv.read_exact(&mut back).await?;
        let rtt = start.elapsed();
        anyhow::ensure!(back == out, "эхо не совпало");
        Ok((rtt, self.path()))
    }

    pub fn path(&self) -> PathKind {
        let paths = self.conn.paths();
        match paths.iter().find(|p| p.is_selected()) {
            Some(p) if p.is_relay() => PathKind::Relay,
            Some(p) if p.is_ip() => PathKind::Direct,
            _ => PathKind::Unknown,
        }
    }

    pub fn close(mut self) {
        self.send.finish().ok();
        self.conn.close(0u32.into(), b"bye");
    }
}

/// Серверная сторона ping: эхо всего, что пришло в первый стрим.
#[derive(Debug, Clone)]
struct Pong;

impl ProtocolHandler for Pong {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        tokio::io::copy(&mut recv, &mut send).await?;
        send.finish()?;
        conn.closed().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ping_over_localhost() -> Result<()> {
        let cfg = || Config { key: SecretKey::generate(), relay_mode: RelayMode::Disabled, lan: false, proxy: None, vpn: None };
        let a = Node::bind(cfg()).await?;
        let b = Node::bind(cfg()).await?;
        let mut p = a.pinger(b.endpoint().addr()).await?;
        for _ in 0..3 {
            let (_, path) = p.ping().await?;
            assert_eq!(path, PathKind::Direct);
        }
        p.close();
        a.shutdown().await?;
        b.shutdown().await?;
        Ok(())
    }

    #[test]
    fn key_roundtrip() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("rift-key-{}", std::process::id()));
        let path = dir.join("key");
        let k1 = load_or_create_key(&path)?;
        let k2 = load_or_create_key(&path)?;
        assert_eq!(k1.public(), k2.public());
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    /// Весь трафик к relay должен идти через прокси — иначе маскировка дырявая.
    #[tokio::test]
    async fn relay_traffic_goes_through_proxy() -> Result<()> {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (relay_map, _url, _server) = iroh::test_utils::run_relay_server_with(false).await?;

        // Минимальный HTTP CONNECT-прокси, считает туннели.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy: url::Url = format!("http://{}", listener.local_addr()?).parse()?;
        let tunnels = Arc::new(AtomicUsize::new(0));
        let counter = tunnels.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut client = BufReader::new(client);
                    let mut line = String::new();
                    client.read_line(&mut line).await?;
                    let target = line.split_whitespace().nth(1).unwrap_or_default().to_string();
                    while line != "\r\n" {
                        line.clear();
                        client.read_line(&mut line).await?;
                    }
                    let mut upstream = tokio::net::TcpStream::connect(target).await?;
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mut client = client.into_inner();
                    client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                    anyhow::Ok(())
                });
            }
        });

        let node = Node::bind(Config {
            key: SecretKey::generate(),
            relay_mode: RelayMode::Custom(relay_map),
            lan: false,
            proxy: Some(proxy),
            vpn: None,
        })
        .await?;
        tokio::time::timeout(Duration::from_secs(10), node.endpoint().online()).await?;
        assert!(tunnels.load(Ordering::SeqCst) > 0, "relay подключился мимо прокси");
        node.shutdown().await
    }
}
