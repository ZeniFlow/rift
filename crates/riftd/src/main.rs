use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use librift::bridge::BridgeUrl;
use librift::host::{HTTP_ALPN, Host};
use librift::logsvc::{self, LOG_ALPN, LogService, WITNESS_ALPN, WitnessService};
use librift::names::{self, NAMES_ALPN, NoticeCache, Request, Resolver};
use librift::{Config, EndpointAddr, Handler, Node, NodeId, RelayUrl, SecretKey, TransportAddr, Url, load_or_create_key, vpn};
use rift_trust::{Announcement, Bundle, PublicKey, Trust};

/// Кому верит клиент: root и свидетели логов. В приложении это вшито, здесь — флаги для разработки.
#[derive(clap::Args, Clone)]
struct TrustArgs {
    /// Публичный ключ root.
    #[arg(long, env = "RIFT_ROOT")]
    root: PublicKey,
    /// Свидетель логов (можно несколько).
    #[arg(long = "witness", env = "RIFT_WITNESSES", value_delimiter = ',')]
    witnesses: Vec<PublicKey>,
    /// Сколько свидетелей должны подписать голову лога. 0 — не требовать (только отладка).
    #[arg(long, default_value_t = 1, env = "RIFT_WITNESS_THRESHOLD")]
    threshold: usize,
}

impl TrustArgs {
    fn get(&self) -> Result<Trust> {
        anyhow::ensure!(
            self.threshold <= self.witnesses.len(),
            "порог {} больше числа свидетелей ({}): укажи --witness или --threshold 0",
            self.threshold,
            self.witnesses.len()
        );
        Ok(Trust { root: self.root, witnesses: self.witnesses.clone(), threshold: self.threshold })
    }
}

#[derive(Parser)]
#[command(name = "riftd", version, about = "Нода сети Rift")]
struct Cli {
    /// Каталог с ключом ноды и данными.
    #[arg(long, env = "RIFT_HOME", global = true)]
    home: Option<PathBuf>,
    /// Файл ключа вместо `<home>/key` (например, ключ из `rift-ca keygen`: у лога и свидетеля ключ ноды = ключ лога/свидетеля).
    #[arg(long, env = "RIFT_KEY", global = true)]
    key: Option<PathBuf>,
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
    /// Резолвер имён: недоверенный кэш цепочек (доверие — в подписях, нужен только root).
    Resolver {
        #[command(flatten)]
        trust: TrustArgs,
        /// Соседние резолверы (NodeID или NodeID@relay): объявления (заморозки, отзывы) подтягиваем у них.
        #[arg(long = "peer", env = "RIFT_PEERS_RESOLVERS", value_delimiter = ',')]
        peers: Vec<String>,
        /// Как часто спрашивать соседей, секунд.
        #[arg(long, default_value_t = 60)]
        sync_secs: u64,
    },
    /// Подтянуть объявления (заморозки, отзывы) в локальный кэш клиента `<home>/notices.json`.
    Notices {
        #[command(flatten)]
        trust: TrustArgs,
        #[arg(long = "resolver", env = "RIFT_RESOLVERS", value_delimiter = ',', required = true)]
        resolvers: Vec<String>,
    },
    /// Сетевой лог: ключ ноды (`--key`) = ключ лога. Сам подписывает головы и собирает подписи свидетелей.
    Log {
        /// Кому можно добавлять записи (NodeID; отдельный от ключа лога ключ). Можно несколько.
        #[arg(long = "appender", value_delimiter = ',', required = true)]
        appenders: Vec<PublicKey>,
        /// Свидетели: NodeID или NodeID@relay.
        #[arg(long = "witness", env = "RIFT_LOG_WITNESSES", value_delimiter = ',', required = true)]
        witnesses: Vec<String>,
        /// Сколько подписей нужно голове, чтобы выдавать по ней доказательства (по умолчанию — все свидетели).
        #[arg(long)]
        quorum: Option<usize>,
        /// Файл лога (по умолчанию `<home>/log.json`).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Свидетель: проверяет головы логов и подписывает. Ключ ноды (`--key`) = ключ свидетеля.
    Witness {
        /// Файл состояния — что свидетель видел (по умолчанию `<home>/witness.json`).
        #[arg(long)]
        state: Option<PathBuf>,
        /// Какие логи подписывать (NodeID лога). Без этого — любые, и состояние растёт.
        #[arg(long = "log")]
        logs: Vec<PublicKey>,
    },
    /// Добавить сертификат в сетевой лог (нужен ключ, разрешённый в `--appender`).
    LogAdd {
        #[arg(long)]
        log: String,
        /// zone, registrar или domain.
        #[arg(long)]
        kind: String,
        #[arg(long)]
        cert: PathBuf,
    },
    /// Получить доказательство включения (ждёт подписей свидетелей).
    LogProof {
        #[arg(long)]
        log: String,
        #[arg(long)]
        index: u64,
        /// Сколько секунд ждать подписей свидетелей.
        #[arg(long, default_value_t = 60)]
        wait: u64,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Опубликовать сайт: цепочка домена + туннель до локального приложения.
    Host {
        #[command(flatten)]
        trust: TrustArgs,
        /// bundle.json от `rift-ca bundle`.
        #[arg(long)]
        bundle: PathBuf,
        /// Локальное приложение (Node.js, nginx…): host:port, http://… или https://….
        #[arg(long, conflicts_with = "static_dir", required_unless_present = "static_dir")]
        upstream: Option<String>,
        /// Не проверять сертификат upstream (self-signed на localhost).
        #[arg(long)]
        upstream_insecure: bool,
        /// Вместо приложения отдавать собранный сайт из папки (React, Vue…): `rift deploy`.
        #[arg(long = "static", value_name = "DIR")]
        static_dir: Option<PathBuf>,
        #[arg(long = "resolver", env = "RIFT_RESOLVERS", value_delimiter = ',', required = true)]
        resolvers: Vec<String>,
    },
    /// Отправить цепочки / объявления резолверам.
    Publish {
        #[arg(long = "resolver", env = "RIFT_RESOLVERS", value_delimiter = ',', required = true)]
        resolvers: Vec<String>,
        #[arg(long)]
        bundle: Vec<PathBuf>,
        /// Объявление (freeze / отзыв) от `rift-ca notice`.
        #[arg(long)]
        notice: Vec<PathBuf>,
    },
    /// Открыть rift://имя.зона/путь и вывести ответ (как curl).
    Get {
        url: String,
        #[command(flatten)]
        trust: TrustArgs,
        #[arg(long = "resolver", env = "RIFT_RESOLVERS", value_delimiter = ',', required = true)]
        resolvers: Vec<String>,
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
    let key = load_or_create_key(&cli.key.clone().unwrap_or_else(|| home.join("key")))?;

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
    let log_svc = match &cli.cmd {
        Cmd::Log { file, appenders, quorum, witnesses, .. } => {
            let q = quorum.unwrap_or(witnesses.len());
            anyhow::ensure!(q <= witnesses.len(), "кворум {q} больше числа свидетелей {}", witnesses.len());
            Some(LogService::new(key.clone(), Some(file.clone().unwrap_or_else(|| home.join("log.json"))), appenders.clone(), q)?)
        }
        _ => None,
    };
    let witness_svc = match &cli.cmd {
        Cmd::Witness { state, logs } => Some(WitnessService::new(key.clone(), Some(state.clone().unwrap_or_else(|| home.join("witness.json"))), logs.clone())?),
        _ => None,
    };
    let resolver_svc = match &cli.cmd {
        Cmd::Resolver { trust, .. } => Some(Resolver::new(trust.get()?)),
        _ => None,
    };
    let extra: Vec<(Vec<u8>, Handler)> = match &cli.cmd {
        Cmd::Log { .. } => vec![(LOG_ALPN.to_vec(), Box::new(log_svc.clone().unwrap()))],
        Cmd::Witness { .. } => vec![(WITNESS_ALPN.to_vec(), Box::new(witness_svc.clone().unwrap()))],
        Cmd::Resolver { .. } => vec![(NAMES_ALPN.to_vec(), Box::new(resolver_svc.clone().unwrap()))],
        Cmd::Host { upstream: Some(u), upstream_insecure, .. } => vec![(HTTP_ALPN.to_vec(), Box::new(Host::proxy(u, *upstream_insecure)?))],
        Cmd::Host { static_dir: Some(d), .. } => vec![(HTTP_ALPN.to_vec(), Box::new(Host::static_dir(d)?))],
        _ => vec![],
    };

    if let Cmd::Vpn { peers } = cli.cmd {
        let peers = peers
            .iter()
            .map(|p| parse_peer(p, default_relay.clone()))
            .collect::<Result<Vec<_>>>()?;
        let me = vpn::addr_of(&key.public());
        let (ifname, from_tun, to_tun) =
            vpn::open_tun(me).context("не удалось создать TUN (нужен sudo / администратор)")?;
        let vpn = vpn::Vpn::new(key.public(), peers.clone(), to_tun);
        let node = Node::bind(Config { key, relay_mode, lan: true, proxy: cli.proxy, bridge: cli.bridge, relay_ca: cli.relay_ca, vpn: Some(vpn.clone()), extra: vec![] }).await?;
        tokio::spawn(vpn.run(node.endpoint().clone(), from_tun));
        println!("NodeID: {}\nVPN:    {me} на {ifname}\n\nPeers:", node.id());
        for p in &peers {
            println!("  {}  {}", vpn::addr_of(&p.id), p.id);
        }
        println!("\nCtrl-C — выход.");
        tokio::signal::ctrl_c().await?;
        return node.shutdown().await;
    }

    let node = Node::bind(Config { key, relay_mode, lan: true, proxy: cli.proxy, bridge: cli.bridge, relay_ca: cli.relay_ca, vpn: None, extra }).await?;
    match cli.cmd {
        Cmd::Id | Cmd::Vpn { .. } | Cmd::Bridge { .. } => unreachable!(),
        Cmd::Log { witnesses, .. } => {
            node.endpoint().online().await;
            let ws = parse_peers(&witnesses, &default_relay)?;
            let relay = node.endpoint().addr().relay_urls().next().map(|r| format!("@{r}")).unwrap_or_default();
            println!("Лог: {}{relay}\nэто ключ лога: им должны быть подписаны сертификаты, которые в него пишутся (control — зоны, владелец зоны — домены)\nСвидетелей: {}\n\nCtrl-C — выход.", node.id(), ws.len());
            let (svc, ep) = (log_svc.unwrap(), node.endpoint().clone());
            tokio::spawn(async move { svc.run(ep, ws).await });
            tokio::signal::ctrl_c().await?;
        }
        Cmd::Witness { .. } => {
            node.endpoint().online().await;
            let relay = node.endpoint().addr().relay_urls().next().map(|r| format!("@{r}")).unwrap_or_default();
            println!("Свидетель: {}{relay}\nклиенты доверяют ему так: --witness {}\n\nCtrl-C — выход.", node.id(), node.id());
            tokio::signal::ctrl_c().await?;
        }
        Cmd::LogAdd { log, kind, cert } => {
            let log = parse_peer(&log, default_relay.clone())?;
            let text = std::fs::read_to_string(&cert).with_context(|| format!("не удалось прочитать {}", cert.display()))?;
            let entry = rift_trust::log::entry_from_json(&kind, &text).map_err(anyhow::Error::msg)?;
            let (index, size) = logsvc::append(node.endpoint(), log, entry).await?;
            println!("{index}  (размер лога: {size})");
        }
        Cmd::LogProof { log, index, wait, out } => {
            let log = parse_peer(&log, default_relay.clone())?;
            let proof = logsvc::prove(node.endpoint(), log, index, Duration::from_secs(wait)).await?;
            std::io::Write::write_all(
                &mut std::fs::OpenOptions::new().write(true).create_new(true).open(&out).with_context(|| format!("{} уже существует", out.display()))?,
                rift_trust::to_json(&proof).as_bytes(),
            )?;
            println!("{}  (голова размера {}, подписей: {})", out.display(), proof.head.body.size, proof.cosigs.len());
        }
        Cmd::Notices { trust, resolvers } => {
            let trust = trust.get()?;
            let resolvers = parse_peers(&resolvers, &default_relay)?;
            let mut cache = NoticeCache::load(home.join("notices.json"), &trust.root)?;
            let added = names::sync_notices(node.endpoint(), &resolvers, &trust.root, &mut cache).await;
            println!("новых: {added}, всего в кэше: {}", cache.all().len());
            for n in cache.all() {
                println!("  {:?}", n.notice.body);
            }
        }
        Cmd::Resolver { peers, sync_secs, .. } => {
            node.endpoint().online().await;
            let relay = node.endpoint().addr().relay_urls().next().map(|r| format!("@{r}")).unwrap_or_default();
            println!("Резолвер: {}{relay}\nсоседей: {}\n\nCtrl-C — выход.", node.id(), peers.len());
            if !peers.is_empty() {
                let peers = parse_peers(&peers, &default_relay)?;
                let (svc, ep) = (resolver_svc.unwrap(), node.endpoint().clone());
                tokio::spawn(async move { svc.run_sync(ep, peers, Duration::from_secs(sync_secs.max(1))).await });
            }
            tokio::signal::ctrl_c().await?;
        }
        Cmd::Host { trust, bundle, resolvers, upstream, static_dir, .. } => {
            let trust = trust.get()?;
            let bundle: Bundle = read_json(&bundle)?;
            let name = rift_trust::verify(&trust, &bundle, &[], names::now())
                .context("цепочка не проходит проверку")
                .and_then(|r| {
                    anyhow::ensure!(r.hosts.contains(&node.id()), "в записях {} нет NodeID этой ноды ({}): перевыпусти dns с --host {}", r.name, node.id(), node.id());
                    Ok(r.name)
                })?;
            let resolvers = parse_peers(&resolvers, &default_relay)?;
            let target = upstream.or(static_dir.map(|d| d.display().to_string())).unwrap_or_default();
            println!("rift://{name} → {target} (NodeID {})\nCtrl-C — выход.", node.id());
            let mut tick = tokio::time::interval(Duration::from_secs(300));
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let n = names::publish(node.endpoint(), &resolvers, Request::PutBundle(bundle.clone())).await;
                        println!("опубликовано: {n}/{}", resolvers.len());
                    }
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
        }
        Cmd::Publish { resolvers, bundle, notice } => {
            let resolvers = parse_peers(&resolvers, &default_relay)?;
            for p in bundle {
                let n = names::publish(node.endpoint(), &resolvers, Request::PutBundle(read_json::<Bundle>(&p)?)).await;
                println!("{}: принято {n}/{}", p.display(), resolvers.len());
            }
            for p in notice {
                let n = names::publish(node.endpoint(), &resolvers, Request::PutNotice(read_json::<Announcement>(&p)?)).await;
                println!("{}: принято {n}/{}", p.display(), resolvers.len());
            }
        }
        Cmd::Get { url, trust, resolvers } => {
            let trust = trust.get()?;
            let rest = url.strip_prefix("rift://").context("ожидался rift://имя.зона/путь")?;
            let (name, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(n, p)| (n, format!("/{p}")));
            let resolvers = parse_peers(&resolvers, &default_relay)?;
            let mut cache = NoticeCache::load(home.join("notices.json"), &trust.root)?;
            let r = names::resolve(node.endpoint(), &resolvers, &trust, name, &mut cache).await?;
            let request = librift::host::get_request(name, &path);
            let mut last = None;
            for h in &r.hosts {
                let addr = EndpointAddr::from_parts(*h, default_relay.clone().map(TransportAddr::Relay));
                match librift::host::fetch(node.endpoint(), addr, &request).await {
                    Ok(body) => {
                        std::io::Write::write_all(&mut std::io::stdout(), &body)?;
                        last = None;
                        break;
                    }
                    Err(e) => last = Some(e),
                }
            }
            if let Some(e) = last {
                return Err(e).context("ни один хост не ответил");
            }
        }
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

fn parse_peers(list: &[String], default_relay: &Option<RelayUrl>) -> Result<Vec<EndpointAddr>> {
    list.iter().map(|p| parse_peer(p, default_relay.clone())).collect()
}

fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T> {
    rift_trust::from_json(&std::fs::read_to_string(path).with_context(|| format!("не удалось прочитать {}", path.display()))?)
        .with_context(|| format!("{}: не тот формат", path.display()))
}
