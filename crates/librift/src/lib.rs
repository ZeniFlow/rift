//! librift — ядро Rift. Фаза 0: ключ ноды, соединения через iroh (relay + hole punching), ping.

use std::{
    fmt,
    io::{ErrorKind, Write},
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey,
    endpoint::{Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};

pub use iroh::{EndpointId as NodeId, RelayUrl, TransportAddr};

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

/// Нода Rift: iroh-endpoint + обработчики протоколов.
pub struct Node {
    router: Router,
}

impl Node {
    /// `relays` пустой → публичные relay n0 (только для разработки).
    pub async fn bind(key: SecretKey, relays: Vec<RelayUrl>) -> Result<Self> {
        let mode = if relays.is_empty() {
            RelayMode::Default
        } else {
            RelayMode::Custom(relays.into_iter().collect())
        };
        Self::bind_with(key, mode).await
    }

    pub async fn bind_with(key: SecretKey, relay_mode: RelayMode) -> Result<Self> {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(relay_mode)
            .bind()
            .await?;
        let router = Router::builder(endpoint).accept(PING_ALPN, Pong).spawn();
        Ok(Self { router })
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
        let a = Node::bind_with(SecretKey::generate(), RelayMode::Disabled).await?;
        let b = Node::bind_with(SecretKey::generate(), RelayMode::Disabled).await?;
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
}
