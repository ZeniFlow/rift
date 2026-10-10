use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use librift::bridge::BridgeUrl;
use librift::{Config, EndpointAddr, Node, NodeId, RelayUrl, SecretKey, TransportAddr, Url, load_or_create_key, vpn};

#[derive(Parser)]
#[command(name = "riftd", version, about = "Нода сети Rift")]
struct Cli {
    /// Каталог с ключом ноды и данными.
    #[arg(long, env = "RIFT_HOME", global = true)]
    home: Option<PathBuf>,
    /// URL relay (можно несколько). Пусто → публичные relay n0, только для разработки.
    #[arg(long = "relay", env = "RIFT_RELAY", value_delimiter = ',', global = true)]
    relays: Vec<RelayUrl>,
    /// HTTP-прокси для трафика к relay (локальный маскирующий клиент: Xray, sing-box, shoes…).
    #[arg(long, env = "RIFT_PROXY", global = true)]
    proxy: Option<Url>,
    /// Мост REALITY (ссылка reality://… от `riftd bridge`): трафик к relay идёт через него.
    #[arg(long, env = "RIFT_BRIDGE", global = true)]
    bridge: Option<BridgeUrl>,
    /// PEM с корневым сертификатом своих relay: доверять только ему.
    #[arg(long, env = "RIFT_RELAY_CA", global = true)]
    relay_ca: Option<PathBuf>,
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
    /// Mesh-VPN с нодами из списка (нужны права root/администратора).
    Vpn {
        /// Нода, которой разрешено с нами говорить: NodeID или NodeID@relay-url.
        #[arg(long = "peer", env = "RIFT_PEERS", value_delimiter = ',', required = true)]
        peers: Vec<String>,
    },
    /// Мост REALITY перед relay: для DPI выглядит как TLS к `--dest`.
    Bridge {
        #[arg(long, default_value = "0.0.0.0:443")]
        listen: SocketAddr,
        /// Настоящий сайт с TLS 1.3, под который маскируемся (host:port).
        #[arg(long, default_value = "www.microsoft.com:443")]
        dest: String,
        /// Куда пускать своих: адрес relay (host:port).
        #[arg(long)]
        upstream: String,
        /// Публичный адрес моста для ссылки (IP или домен).
        #[arg(long)]
        public: String,
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

    if let Cmd::Bridge { listen, dest, upstream, public } = &cli.cmd {
        return run_bridge(&home, *listen, dest, upstream, public).await;
    }
    if let Cmd::Id = cli.cmd {
        println!("{}", key.public());
        return Ok(());
    }
    if cli.relays.is_empty() {
        eprintln!("внимание: --relay не задан, используются публичные relay n0 (только для разработки)");
    }

    let default_relay = cli.relays.first().cloned();
    let relay_mode = Config::relay_mode(cli.relays);

    if let Cmd::Vpn { peers } = cli.cmd {
        let peers = peers
            .iter()
            .map(|p| parse_peer(p, default_relay.clone()))
            .collect::<Result<Vec<_>>>()?;
        let me = vpn::addr_of(&key.public());
        let (ifname, from_tun, to_tun) =
            vpn::open_tun(me).context("не удалось создать TUN (нужен sudo / администратор)")?;
        let vpn = vpn::Vpn::new(key.public(), peers.clone(), to_tun);
        let node = Node::bind(Config { key, relay_mode, lan: true, proxy: cli.proxy, bridge: cli.bridge, relay_ca: cli.relay_ca, vpn: Some(vpn.clone()) }).await?;
        tokio::spawn(vpn.run(node.endpoint().clone(), from_tun));
        println!("NodeID: {}\nVPN:    {me} на {ifname}\n\nPeers:", node.id());
        for p in &peers {
            println!("  {}  {}", vpn::addr_of(&p.id), p.id);
        }
        println!("\nCtrl-C — выход.");
        tokio::signal::ctrl_c().await?;
        return node.shutdown().await;
    }

    let node = Node::bind(Config { key, relay_mode, lan: true, proxy: cli.proxy, bridge: cli.bridge, relay_ca: cli.relay_ca, vpn: None }).await?;
    match cli.cmd {
        Cmd::Id | Cmd::Vpn { .. } | Cmd::Bridge { .. } => unreachable!(),
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
            let via = via.or(default_relay);
            let parts = addrs
                .into_iter()
                .map(TransportAddr::Ip)
                .chain(via.map(TransportAddr::Relay));
            let mut pinger = node
                .pinger(EndpointAddr::from_parts(target, parts))
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

/// `NodeID` или `NodeID@relay-url`.
fn parse_peer(s: &str, default_relay: Option<RelayUrl>) -> Result<EndpointAddr> {
    let (id, relay) = match s.split_once('@') {
        Some((id, relay)) => (id, Some(relay.parse().context("кривой relay-url")?)),
        None => (s, default_relay),
    };
    let id: NodeId = id.parse().with_context(|| format!("кривой NodeID: {id}"))?;
    Ok(EndpointAddr::from_parts(id, relay.map(TransportAddr::Relay)))
}

/// Ключ моста хранится в `<home>/bridge`: приватный ключ, публичный ключ, short id — по строке.
async fn run_bridge(home: &std::path::Path, listen: SocketAddr, dest: &str, upstream: &str, public: &str) -> Result<()> {
    use rift_reality as reality;
    let path = home.join("bridge");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let (private, public_key) = reality::generate_keypair()?;
            let sid: String = SecretKey::generate().to_bytes()[..8].iter().map(|b| format!("{b:02x}")).collect();
            let t = format!("{private}\n{public_key}\n{sid}\n");
            std::fs::create_dir_all(home)?;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            std::io::Write::write_all(&mut opts.open(&path)?, t.as_bytes())?;
            t
        }
        Err(e) => return Err(e).with_context(|| format!("не удалось прочитать {}", path.display())),
    };
    let mut lines = text.lines();
    let (Some(private), Some(public_key), Some(sid)) = (lines.next(), lines.next(), lines.next()) else {
        anyhow::bail!("{}: ожидалось 3 строки", path.display());
    };
    let sni = dest.rsplit_once(':').map_or(dest, |(h, _)| h);
    println!("Мост слушает {listen}, маскируется под {dest}, пускает на {upstream}\n");
    println!("Ссылка для клиентов (--bridge):\n  reality://{public_key}@{public}:{}?sni={sni}&sid={sid}\n", listen.port());
    let cfg = reality::ServerConfig {
        private_key: reality::decode_private_key(private)?,
        short_ids: vec![reality::decode_short_id(sid)?],
        dest: dest.to_string(),
    };
    librift::bridge::serve(listen, cfg, upstream.to_string()).await
}
