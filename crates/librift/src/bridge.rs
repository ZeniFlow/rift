//! Мост REALITY: канал до relay маскируется под TLS к чужому сайту.
//!
//! Клиент: локальный HTTP CONNECT-прокси для iroh → REALITY → мост.
//! Мост: свои → upstream (relay), чужие и сканеры → настоящий сайт (`dest`).

use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, bail};
use rift_reality as reality;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

/// `reality://<публичный ключ>@host:port?sni=<сайт>&sid=<short id>`
#[derive(Debug, Clone)]
pub struct BridgeUrl {
    pub addr: String,
    pub client: reality::ClientConfig,
}

impl std::str::FromStr for BridgeUrl {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let url = url::Url::parse(s).context("кривая ссылка на мост")?;
        if url.scheme() != "reality" {
            bail!("ожидалась ссылка reality://…");
        }
        let query = |k: &str| url.query_pairs().find(|(q, _)| q == k).map(|(_, v)| v.into_owned());
        let host = url.host_str().ok_or_else(|| anyhow!("в ссылке нет адреса моста"))?;
        Ok(Self {
            addr: format!("{host}:{}", url.port().unwrap_or(443)),
            client: reality::ClientConfig {
                public_key: reality::decode_public_key(url.username())?,
                short_id: reality::decode_short_id(&query("sid").unwrap_or_default())?,
                server_name: query("sni").ok_or_else(|| anyhow!("в ссылке нет sni"))?,
            },
        })
    }
}

/// Поднимает локальный HTTP CONNECT-прокси, который заворачивает всё в мост.
/// Цель из CONNECT игнорируется: мост сам знает свой relay.
pub async fn spawn_client_proxy(bridge: BridgeUrl) -> Result<url::Url> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy = format!("http://{}", listener.local_addr()?).parse()?;
    tokio::spawn(async move {
        while let Ok((local, _)) = listener.accept().await {
            let bridge = bridge.clone();
            tokio::spawn(async move {
                if let Err(e) = client_tunnel(local, &bridge).await {
                    warn!("мост {}: {e:#}", bridge.addr);
                }
            });
        }
    });
    Ok(proxy)
}

async fn client_tunnel(local: TcpStream, bridge: &BridgeUrl) -> Result<()> {
    let mut local = BufReader::new(local);
    let mut line = String::new();
    loop {
        line.clear();
        if local.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    let tcp = TcpStream::connect(&bridge.addr).await?;
    let mut remote = reality::connect(tcp, &bridge.client).await.context("рукопожатие REALITY")?;
    let mut local = local.into_inner();
    local.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
    Ok(())
}

/// Сервер-мост: слушает `listen`, своих пропускает на `upstream`, остальных — на `cfg.dest`.
pub async fn serve(listen: SocketAddr, cfg: reality::ServerConfig, upstream: String) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    loop {
        let (tcp, peer) = listener.accept().await?;
        let (cfg, upstream) = (cfg.clone(), upstream.clone());
        tokio::spawn(async move {
            match reality::accept(tcp, &cfg).await {
                Ok(Some(mut client)) => match TcpStream::connect(&upstream).await {
                    Ok(mut up) => {
                        tokio::io::copy_bidirectional(&mut client, &mut up).await.ok();
                    }
                    Err(e) => warn!("мост: upstream {upstream}: {e}"),
                },
                Ok(None) => debug!("мост: {peer} не наш, отдан на {}", cfg.dest),
                Err(e) => debug!("мост: {peer}: {e}"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bridge_url() {
        let (_, public) = reality::generate_keypair().unwrap();
        let u: BridgeUrl = format!("reality://{public}@1.2.3.4:8443?sni=www.microsoft.com&sid=abcd")
            .parse()
            .unwrap();
        assert_eq!(u.addr, "1.2.3.4:8443");
        assert_eq!(u.client.server_name, "www.microsoft.com");
        assert!("https://x".parse::<BridgeUrl>().is_err());
        assert!(format!("reality://{public}@1.2.3.4").parse::<BridgeUrl>().is_err()); // нет sni
    }
}
