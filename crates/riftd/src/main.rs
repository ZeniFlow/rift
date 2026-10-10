use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use librift::{Node, NodeId, RelayUrl, TransportAddr, load_or_create_key};

#[derive(Parser)]
#[command(name = "riftd", version, about = "Нода сети Rift")]
struct Cli {
    /// Каталог с ключом ноды и данными.
    #[arg(long, env = "RIFT_HOME", global = true)]
    home: Option<PathBuf>,
    /// URL relay (можно несколько). Пусто → публичные relay n0, только для разработки.
    #[arg(long = "relay", env = "RIFT_RELAY", value_delimiter = ',', global = true)]
    relays: Vec<RelayUrl>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Показать NodeID этой ноды.
    Id,
    /// Принимать входящие соединения (ping) до Ctrl-C.
    Listen,
    /// Пинговать ноду по NodeID.
    Ping {
        node: NodeId,
        /// Relay, на котором сидит удалённая нода (по умолчанию — первый из --relay).
        #[arg(long)]
        via: Option<RelayUrl>,
        /// Прямые адреса удалённой ноды, если известны.
        #[arg(long = "addr")]
        addrs: Vec<SocketAddr>,
        #[arg(short, long, default_value_t = 5)]
        count: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    let cli = Cli::parse();

    let home = match cli.home {
        Some(h) => h,
        None => std::env::home_dir().context("не найден домашний каталог, укажи --home")?.join(".rift"),
    };
    let key = load_or_create_key(&home.join("key"))?;

    if let Cmd::Id = cli.cmd {
        println!("{}", key.public());
        return Ok(());
    }
    if cli.relays.is_empty() {
        eprintln!("внимание: --relay не задан, используются публичные relay n0 (только для разработки)");
    }

    let node = Node::bind(key, cli.relays.clone()).await?;
    match cli.cmd {
        Cmd::Id => unreachable!(),
        Cmd::Listen => {
            node.endpoint().online().await;
            let addr = node.endpoint().addr();
            println!("NodeID: {}", node.id());
            for relay in addr.relay_urls() {
                println!("relay:  {relay}");
            }
            for ip in addr.ip_addrs() {
                println!("addr:   {ip}");
            }
            let relay = addr.relay_urls().next().map(|r| format!(" --via {r}")).unwrap_or_default();
            println!("\nС другой ноды:\n  riftd ping {}{relay}\n\nCtrl-C — выход.", node.id());
            tokio::signal::ctrl_c().await?;
        }
        Cmd::Ping { node: target, via, addrs, count } => {
            let via = via.or_else(|| cli.relays.first().cloned());
            let parts = addrs
                .into_iter()
                .map(TransportAddr::Ip)
                .chain(via.map(TransportAddr::Relay));
            let mut pinger = node
                .pinger(iroh::EndpointAddr::from_parts(target, parts))
                .await
                .with_context(|| format!("не удалось соединиться с {target}"))?;
            for i in 1..=count {
                let (rtt, path) = pinger.ping().await?;
                println!("seq={i} rtt={:.1}ms {path}", rtt.as_secs_f64() * 1000.0);
                if i < count {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            pinger.close();
        }
    }
    node.shutdown().await
}
