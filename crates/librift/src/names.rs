//! Имена `rift://имя.зона`. Резолвер — НЕДОВЕРЕННЫЙ кэш цепочек: он может только не ответить
//! или ответить устаревшим. Подлинность клиент проверяет сам по root-ключу (rift-trust),
//! поэтому резолвером может быть любая нода, а control в резолве не участвует.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow, bail};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use rift_trust::{Announcement, Bundle, Error as TrustError, PublicKey, Resolved, Time, Trust, newest, verify};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

pub const NAMES_ALPN: &[u8] = b"rift/names/0";
const MAX_MSG: usize = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);
/// Сколько объявлений в одном ответе `Notices` (иначе не влезет в сообщение).
const PAGE: usize = 100;
/// Потолок на число хранимых объявлений: защита памяти от потока валидных, но ненужных подписей.
const MAX_NOTICES: usize = 50_000;

pub fn now() -> Time {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Get { name: String },
    PutBundle(Bundle),
    PutNotice(Announcement),
    /// Объявления постранично, начиная с `skip` (для синхронизации резолверов и клиентов).
    Notices { skip: usize },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Found { bundle: Bundle, notices: Vec<Announcement> },
    NotFound,
    Ok,
    Rejected(String),
    Notices { items: Vec<Announcement>, total: usize },
}

// ---------------------------------------------------------------- набор объявлений

/// Объявления без повторов. Подлинность проверяет тот, кто вставляет.
#[derive(Debug, Default)]
pub struct NoticeSet {
    items: Vec<Announcement>,
    keys: HashSet<Vec<u8>>,
}

impl NoticeSet {
    pub fn insert(&mut self, a: Announcement) -> bool {
        if self.items.len() >= MAX_NOTICES {
            return false;
        }
        if !self.keys.insert(serde_json::to_vec(&a).expect("сериализуется")) {
            return false;
        }
        self.items.push(a);
        true
    }

    pub fn items(&self) -> &[Announcement] {
        &self.items
    }
}

/// Объявления, которые видел клиент. Однажды увиденная заморозка действует, даже если потом
/// резолвер промолчит (или к нему вообще не дойдёт): объявления нельзя «забыть», можно только не получить.
#[derive(Debug, Default)]
pub struct NoticeCache {
    set: NoticeSet,
    path: Option<PathBuf>,
}

impl NoticeCache {
    pub fn memory() -> Self {
        Self::default()
    }

    /// Читает файл; записи, не прошедшие проверку по `root`, отбрасываются (файл мог быть испорчен).
    pub fn load(path: PathBuf, root: &PublicKey) -> Result<Self> {
        let mut set = NoticeSet::default();
        match std::fs::read(&path) {
            Ok(bytes) => {
                let items: Vec<Announcement> = serde_json::from_slice(&bytes).map_err(|e| anyhow!("{}: повреждён: {e}", path.display()))?;
                let total = items.len();
                let ok = items.into_iter().filter(|a| a.valid(root)).filter(|a| set.insert(a.clone())).count();
                if ok < total {
                    warn!("{}: отброшено записей: {}", path.display(), total - ok);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow!("не удалось прочитать {}: {e}", path.display())),
        }
        Ok(Self { set, path: Some(path) })
    }

    pub fn all(&self) -> &[Announcement] {
        self.set.items()
    }

    /// Принимает только подписанное root или control, которого признаёт root. Возвращает число новых.
    pub fn merge(&mut self, root: &PublicKey, items: impl IntoIterator<Item = Announcement>) -> usize {
        let added = items.into_iter().filter(|a| a.valid(root)).filter(|a| self.set.insert(a.clone())).count();
        if added > 0 {
            if let Some(p) = &self.path {
                let saved = p
                    .parent()
                    .filter(|d| !d.as_os_str().is_empty())
                    .map_or(Ok(()), std::fs::create_dir_all)
                    .and_then(|()| std::fs::write(p.with_extension("tmp"), serde_json::to_vec_pretty(self.set.items()).expect("сериализуется")))
                    .and_then(|()| std::fs::rename(p.with_extension("tmp"), p));
                if let Err(e) = saved {
                    warn!("кэш объявлений не сохранён ({}): {e}; в памяти он действует", p.display());
                }
            }
        }
        added
    }
}

// ---------------------------------------------------------------- резолвер

#[derive(Debug, Clone)]
pub struct Resolver {
    trust: Trust,
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Default)]
struct State {
    bundles: HashMap<String, Bundle>,
    notices: NoticeSet,
}

impl Resolver {
    // ponytail: всё в памяти. После рестарта хосты перепубликуют цепочки сами (раз в 5 минут).
    pub fn new(trust: Trust) -> Self {
        Self { trust, state: Default::default() }
    }

    pub fn handle(&self, req: Request) -> Response {
        let mut st = self.state.lock().unwrap();
        match req {
            Request::Get { name } => match st.bundles.get(&name) {
                Some(b) => Response::Found {
                    bundle: b.clone(),
                    notices: st.notices.items().iter().filter(|n| n.concerns(b, &self.trust.root)).cloned().collect(),
                },
                None => Response::NotFound,
            },
            Request::PutBundle(b) => {
                // Хранить можно только то, что проходит проверку: мусор и подделки не накапливаются.
                let r = match verify(&self.trust, &b, st.notices.items(), now()) {
                    Ok(r) => r,
                    Err(e) => return Response::Rejected(e.to_string()),
                };
                if st.bundles.get(&r.name).is_some_and(|old| old.dns.body.seq >= r.seq) {
                    return Response::Ok; // не старее того, что есть — нечего обновлять
                }
                st.bundles.insert(r.name, b);
                Response::Ok
            }
            Request::PutNotice(n) => {
                if !n.valid(&self.trust.root) {
                    return Response::Rejected("объявление не подписано root или control, которого признаёт root".into());
                }
                st.notices.insert(n);
                Response::Ok
            }
            Request::Notices { skip } => {
                let all = st.notices.items();
                Response::Notices { items: all.iter().skip(skip).take(PAGE).cloned().collect(), total: all.len() }
            }
        }
    }
}

impl Resolver {
    /// Подтягивает объявления у соседних резолверов. Берёт только подлинные; возвращает число новых.
    pub async fn sync_from(&self, endpoint: &Endpoint, peers: &[EndpointAddr]) -> usize {
        let mut added = 0;
        for p in peers {
            match fetch_notices(endpoint, p.clone()).await {
                Ok(items) => {
                    let mut st = self.state.lock().unwrap();
                    added += items.into_iter().filter(|a| a.valid(&self.trust.root)).filter(|a| st.notices.insert(a.clone())).count();
                }
                Err(e) => warn!("сосед {}: {e:#}", p.id.fmt_short()),
            }
        }
        added
    }

    /// Фоновая синхронизация объявлений с соседями. Крутится, пока жива нода.
    pub async fn run_sync(&self, endpoint: Endpoint, peers: Vec<EndpointAddr>, every: Duration) {
        loop {
            let n = self.sync_from(&endpoint, &peers).await;
            if n > 0 {
                tracing::info!("объявлений получено от соседей: {n}");
            }
            tokio::time::sleep(every).await;
        }
    }
}

impl ProtocolHandler for Resolver {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let Ok((mut send, mut recv)) = conn.accept_bi().await else { return Ok(()) };
        let Ok(bytes) = recv.read_to_end(MAX_MSG).await else { return Ok(()) };
        let resp = match serde_json::from_slice(&bytes) {
            Ok(req) => self.handle(req),
            Err(e) => Response::Rejected(format!("не разобрал запрос: {e}")),
        };
        debug!("names: {resp:?}");
        if send.write_all(&serde_json::to_vec(&resp).unwrap()).await.is_ok() {
            send.finish().ok();
            conn.closed().await; // ждём клиента: иначе ответ может не дойти
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- клиент

pub async fn query(endpoint: &Endpoint, to: impl Into<EndpointAddr>, req: &Request) -> Result<Response> {
    let exchange = async {
        let conn = endpoint.connect(to, NAMES_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&serde_json::to_vec(req)?).await?;
        send.finish()?;
        let bytes = recv.read_to_end(MAX_MSG).await?;
        conn.close(0u32.into(), b"bye");
        anyhow::Ok(serde_json::from_slice(&bytes)?)
    };
    tokio::time::timeout(TIMEOUT, exchange).await.map_err(|_| anyhow!("резолвер не ответил за {TIMEOUT:?}"))?
}

/// Проверка ответа резолвера. `Ok(None)` — резолвер не знает имени.
/// Ответ с чужим именем — подмена, это ошибка, а не «не знаю».
///
/// `known` — объявления, которые клиент уже видел раньше: они действуют, даже если в этом ответе их нет.
pub fn check(trust: &Trust, name: &str, resp: Response, now: Time, known: &[Announcement]) -> Result<Option<Resolved>, TrustError> {
    match resp {
        Response::Found { bundle, notices } => {
            let all: Vec<Announcement> = notices.into_iter().chain(known.iter().cloned()).collect();
            let r = verify(trust, &bundle, &all, now)?;
            if r.name != name {
                return Err(TrustError::Mismatch("резолвер подсунул другое имя"));
            }
            Ok(Some(r))
        }
        _ => Ok(None),
    }
}

/// Домен заморожен или отозван — и это подтверждено подписью. Отдельный тип, чтобы прокси мог ответить 451, а не 502.
#[derive(Debug)]
pub struct Blocked(pub String);

impl std::fmt::Display for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Blocked {}

/// Резолвит имя. Берёт самую свежую (по `seq`) проверенную копию.
/// Заморозка/отзыв, подтверждённые подписью хотя бы от одного резолвера, действуют сразу:
/// отказ безопаснее, чем показать замороженный домен.
///
/// Объявления из ответов (подлинные) попадают в `cache` и действуют с этого момента всегда.
pub async fn resolve(
    endpoint: &Endpoint,
    resolvers: &[EndpointAddr],
    trust: &Trust,
    name: &str,
    cache: &mut NoticeCache,
) -> Result<Resolved> {
    let (mut found, mut last_err) = (vec![], None);
    for r in resolvers {
        match query(endpoint, r.clone(), &Request::Get { name: name.into() }).await {
            Ok(resp) => {
                if let Response::Found { notices, .. } = &resp {
                    cache.merge(&trust.root, notices.iter().cloned());
                }
                match check(trust, name, resp, now(), cache.all()) {
                    Ok(Some(x)) => found.push(x),
                    Ok(None) => {}
                    Err(e @ (TrustError::Frozen(_) | TrustError::Revoked(_))) => {
                    // «заморожен оператором сети» уже называет сайт; «отозван» — нет.
                    let text = if matches!(e, TrustError::Frozen(_)) { e.to_string() } else { format!("{name}: {e}") };
                    return Err(Blocked(text).into());
                }
                    Err(e) => last_err = Some(e.to_string()),
                }
            }
            Err(e) => last_err = Some(format!("{e:#}")),
        }
    }
    newest(found).ok_or_else(|| anyhow!("{name}: не найдено ({})", last_err.unwrap_or_else(|| "резолверы не знают имени".into())))
}

/// Все объявления резолвера (постранично).
pub async fn fetch_notices(endpoint: &Endpoint, resolver: impl Into<EndpointAddr> + Clone) -> Result<Vec<Announcement>> {
    let mut out: Vec<Announcement> = vec![];
    loop {
        match query(endpoint, resolver.clone(), &Request::Notices { skip: out.len() }).await? {
            Response::Notices { items, total } => {
                let empty = items.is_empty();
                out.extend(items);
                if empty || out.len() >= total {
                    return Ok(out);
                }
            }
            other => bail!("неожиданный ответ резолвера: {other:?}"),
        }
    }
}

/// Подтягивает объявления у резолверов в кэш клиента: заморозки доходят до клиента, даже если он давно ничего не открывал.
/// Возвращает число новых подлинных объявлений.
pub async fn sync_notices(endpoint: &Endpoint, resolvers: &[EndpointAddr], root: &PublicKey, cache: &mut NoticeCache) -> usize {
    let mut added = 0;
    for r in resolvers {
        match fetch_notices(endpoint, r.clone()).await {
            Ok(items) => added += cache.merge(root, items),
            Err(e) => warn!("резолвер {}: {e:#}", r.id.fmt_short()),
        }
    }
    added
}

/// Публикует цепочку. Возвращает, сколько резолверов приняли.
pub async fn publish(endpoint: &Endpoint, resolvers: &[EndpointAddr], req: Request) -> usize {
    let mut accepted = 0;
    for r in resolvers {
        match query(endpoint, r.clone(), &req).await {
            Ok(Response::Ok) => accepted += 1,
            Ok(other) => tracing::warn!("резолвер {}: {other:?}", r.id.fmt_short()),
            Err(e) => tracing::warn!("резолвер {}: {e:#}", r.id.fmt_short()),
        }
    }
    accepted
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;
    use rift_trust::{ControlCert, Notice, Signed};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{Node, host::{HTTP_ALPN, Host, fetch, get_request}};

    use crate::testutil::{DAY, bundle, node, trust};

    /// Приложение хоста: на любой запрос отвечает 200.
    async fn app() -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    c.read(&mut buf).await.ok();
                    c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nhello from node").await.ok();
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn site_opens_while_control_is_offline() {
        let (root, control, zone, owner) = (SecretKey::generate(), SecretKey::generate(), SecretKey::generate(), SecretKey::generate());
        let host = node(vec![(HTTP_ALPN.to_vec(), Box::new(Host::proxy(&app().await, false).unwrap()))]).await;
        let b = bundle(&root, &control, &zone, &owner, host.id(), 1);
        // Control выключен: его ключа больше нет, дальше работают только подписи в цепочке.
        drop((control, zone));

        let resolver = node(vec![(NAMES_ALPN.to_vec(), Box::new(Resolver::new(trust(&root))))]).await;
        let client = node(vec![]).await;
        let rs = [resolver.endpoint().addr()];

        assert_eq!(publish(host.endpoint(), &rs, Request::PutBundle(b)).await, 1);
        let r = resolve(client.endpoint(), &rs, &trust(&root), "shop.brand", &mut NoticeCache::memory()).await.unwrap();
        assert_eq!(r.hosts, vec![host.id()]);

        let resp = fetch(client.endpoint(), host.endpoint().addr(), &get_request("shop.brand", "/")).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).ends_with("hello from node"));

        // Неизвестное имя.
        assert!(resolve(client.endpoint(), &rs, &trust(&root), "nope.brand", &mut NoticeCache::memory()).await.is_err());
        // Клиент с чужим root не верит ничему, что есть у резолвера.
        let other = trust(&SecretKey::generate());
        assert!(resolve(client.endpoint(), &rs, &other, "shop.brand", &mut NoticeCache::memory()).await.is_err());
    }

    #[test]
    fn resolver_rejects_forgeries_and_stale_updates() {
        let k = SecretKey::generate;
        let (root, control, zone, owner, host) = (k(), k(), k(), k(), k().public());
        let res = Resolver::new(trust(&root));

        // Цепочка, подписанная не тем root.
        let fake = bundle(&k(), &control, &zone, &owner, host, 1);
        assert!(matches!(res.handle(Request::PutBundle(fake)), Response::Rejected(_)));
        assert!(matches!(res.handle(Request::Get { name: "shop.brand".into() }), Response::NotFound));

        // Настоящая принимается; старее по seq — не затирает.
        let seq = |n| bundle(&root, &control, &zone, &owner, host, n);
        assert!(matches!(res.handle(Request::PutBundle(seq(5))), Response::Ok));
        assert!(matches!(res.handle(Request::PutBundle(seq(3))), Response::Ok));
        let Response::Found { bundle, .. } = res.handle(Request::Get { name: "shop.brand".into() }) else { panic!() };
        assert_eq!(bundle.dns.body.seq, 5);

        // Объявление постороннего не принимается.
        let s = k();
        let n = Announcement { notice: Signed::sign(Notice::Freeze { name: "shop.brand".into(), since: 0 }, &s), control: None };
        assert!(matches!(res.handle(Request::PutNotice(n)), Response::Rejected(_)));
    }

    #[test]
    fn client_does_not_trust_resolver_answers() {
        let k = SecretKey::generate;
        let (root, control, zone, owner, host) = (k(), k(), k(), k(), k().public());
        let found = || Response::Found { bundle: bundle(&root, &control, &zone, &owner, host, 1), notices: vec![] };

        assert_eq!(check(&trust(&root), "shop.brand", found(), now(), &[]).unwrap().unwrap().hosts, vec![host]);
        // Спросили одно имя, резолвер подсунул цепочку другого (валидную!) — отказ.
        assert!(matches!(check(&trust(&root), "bank.brand", found(), now(), &[]), Err(TrustError::Mismatch(_))));
        // «Не знаю» — не ошибка.
        assert_eq!(check(&trust(&root), "shop.brand", Response::NotFound, now(), &[]), Ok(None));
    }

    #[test]
    fn freeze_published_to_resolver_reaches_clients_even_after_control_rotation() {
        let k = SecretKey::generate;
        let (root, control, zone, owner, host) = (k(), k(), k(), k(), k().public());
        let res = Resolver::new(trust(&root));
        let b = bundle(&root, &control, &zone, &owner, host, 1);
        assert!(matches!(res.handle(Request::PutBundle(b)), Response::Ok));

        // Новый control (ротация) замораживает домен из цепочки старого control.
        let (c2, t) = (k(), now());
        let cert2 = Signed::sign(ControlCert { key: c2.public(), issued_at: t - 10, expires_at: t + 90 * DAY }, &root);
        let freeze = Announcement {
            notice: Signed::sign(Notice::Freeze { name: "shop.brand".into(), since: t }, &c2),
            control: Some(cert2),
        };
        assert!(matches!(res.handle(Request::PutNotice(freeze)), Response::Ok));

        let resp = res.handle(Request::Get { name: "shop.brand".into() });
        assert!(matches!(check(&trust(&root), "shop.brand", resp, now() + 1, &[]), Err(TrustError::Frozen(_))));
    }

    // ------------------------------------------------------------ рассылка объявлений

    fn freeze_by_root(root: &SecretKey, name: &str) -> Announcement {
        Announcement { notice: Signed::sign(Notice::Freeze { name: name.into(), since: 0 }, root), control: None }
    }

    #[test]
    fn found_carries_only_notices_about_this_chain() {
        let k = SecretKey::generate;
        let (root, control, zone, owner, host) = (k(), k(), k(), k(), k().public());
        let res = Resolver::new(trust(&root));
        assert!(matches!(res.handle(Request::PutBundle(bundle(&root, &control, &zone, &owner, host, 1))), Response::Ok));
        // Чужие объявления: другой домен, другая зона, посторонний ключ.
        let stranger_key = k().public();
        for n in [
            freeze_by_root(&root, "other.brand"),
            Announcement { notice: Signed::sign(Notice::RevokeZone { zone: "elsewhere".into(), since: 0 }, &root), control: None },
            Announcement { notice: Signed::sign(Notice::RevokeKey { key: stranger_key, since: 0 }, &root), control: None },
        ] {
            assert!(matches!(res.handle(Request::PutNotice(n)), Response::Ok));
        }
        let Response::Found { notices, .. } = res.handle(Request::Get { name: "shop.brand".into() }) else { panic!() };
        assert!(notices.is_empty(), "лишнее в ответе: {}", notices.len());
        // А своё — приходит.
        assert!(matches!(res.handle(Request::PutNotice(freeze_by_root(&root, "shop.brand"))), Response::Ok));
        let Response::Found { notices, .. } = res.handle(Request::Get { name: "shop.brand".into() }) else { panic!() };
        assert_eq!(notices.len(), 1);
    }

    #[test]
    fn notice_set_and_cache_accept_only_authentic_and_survive_restarts() {
        let root = SecretKey::generate();
        let dir = std::env::temp_dir().join(format!("rift-notices-{}-{}", std::process::id(), now()));
        let path = dir.join("n.json"); // каталога ещё нет
        let mut cache = NoticeCache::load(path.clone(), &root.public()).unwrap();

        let real = freeze_by_root(&root, "a.brand");
        let forged = freeze_by_root(&SecretKey::generate(), "b.brand");
        assert_eq!(cache.merge(&root.public(), [real.clone(), forged.clone(), real.clone()]), 1, "подделка и повтор не считаются");
        assert_eq!(cache.all().len(), 1);

        // «Перезапуск»: файл читается; подделку, вписанную в файл руками, отбрасываем при загрузке.
        let mut on_disk: Vec<Announcement> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        on_disk.push(forged);
        std::fs::write(&path, serde_json::to_vec(&on_disk).unwrap()).unwrap();
        let again = NoticeCache::load(path.clone(), &root.public()).unwrap();
        assert_eq!(again.all().len(), 1);

        // Повреждённый файл — ошибка, а не молчаливый пустой кэш (иначе заморозки «забылись» бы).
        std::fs::write(&path, "not json").unwrap();
        assert!(NoticeCache::load(path, &root.public()).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn notices_are_paged_and_resolvers_gossip_them() {
        let k = SecretKey::generate;
        let root = k();
        let a = Resolver::new(trust(&root));
        for i in 0..(PAGE * 2 + 30) {
            assert!(matches!(a.handle(Request::PutNotice(freeze_by_root(&root, &format!("n{i}.brand")))), Response::Ok));
        }
        let Response::Notices { items, total } = a.handle(Request::Notices { skip: 0 }) else { panic!() };
        assert_eq!((items.len(), total), (PAGE, PAGE * 2 + 30));
        let Response::Notices { items, .. } = a.handle(Request::Notices { skip: PAGE * 2 }) else { panic!() };
        assert_eq!(items.len(), 30);

        // Сосед B подтягивает всё по сети; свои повторы не дублируются; подделок нет.
        let na = node_for(a.clone()).await;
        let b = Resolver::new(trust(&root));
        let nb = node_for(b.clone()).await;
        assert!(matches!(b.handle(Request::PutNotice(freeze_by_root(&root, "n0.brand"))), Response::Ok));
        assert_eq!(b.sync_from(nb.endpoint(), &[na.endpoint().addr()]).await, PAGE * 2 + 30 - 1);
        assert_eq!(b.sync_from(nb.endpoint(), &[na.endpoint().addr()]).await, 0, "повторная синхронизация ничего не добавляет");
        let Response::Notices { total, .. } = b.handle(Request::Notices { skip: 0 }) else { panic!() };
        assert_eq!(total, PAGE * 2 + 30);

        // Резолвер с другим root не принимает чужие объявления от соседа.
        let c = Resolver::new(trust(&SecretKey::generate()));
        let nc = node_for(c.clone()).await;
        assert_eq!(c.sync_from(nc.endpoint(), &[na.endpoint().addr()]).await, 0);
    }

    async fn node_for(r: Resolver) -> Node {
        node(vec![(NAMES_ALPN.to_vec(), Box::new(r))]).await
    }

    #[tokio::test]
    async fn freeze_reaches_clients_through_gossip_and_cannot_be_unlearned() {
        let k = SecretKey::generate;
        let (root, control, zone, owner) = (k(), k(), k(), k());
        let host = node(vec![]).await;
        let b = bundle(&root, &control, &zone, &owner, host.id(), 1);

        // Два резолвера; R2 берёт объявления у R1. Третий (R3) — «отстающий», связи с ними нет.
        let (r1, r2, r3) = (Resolver::new(trust(&root)), Resolver::new(trust(&root)), Resolver::new(trust(&root)));
        let (n1, n2, n3) = (node_for(r1.clone()).await, node_for(r2.clone()).await, node_for(r3.clone()).await);
        for r in [&r1, &r2, &r3] {
            assert!(matches!(r.handle(Request::PutBundle(b.clone())), Response::Ok));
        }
        let client = node(vec![]).await;
        let (a1, a2, a3) = (n1.endpoint().addr(), n2.endpoint().addr(), n3.endpoint().addr());
        let tr = trust(&root);

        // До заморозки домен открывается через любой.
        assert!(resolve(client.endpoint(), &[a2.clone()], &tr, "shop.brand", &mut NoticeCache::memory()).await.is_ok());

        // Control публикует заморозку ОДНОМУ резолверу (R1); R2 узнаёт через сплетню.
        assert_eq!(publish(host.endpoint(), &[a1.clone()], Request::PutNotice(freeze_by_root(&root, "shop.brand"))).await, 1);
        assert_eq!(r2.sync_from(n2.endpoint(), &[a1.clone()]).await, 1);
        let err = resolve(client.endpoint(), &[a2.clone()], &tr, "shop.brand", &mut NoticeCache::memory()).await.unwrap_err();
        assert!(err.to_string().contains("заморожен"), "{err}");

        // R3 о заморозке не знает: с чистым кэшем клиент домен откроет…
        assert!(resolve(client.endpoint(), &[a3.clone()], &tr, "shop.brand", &mut NoticeCache::memory()).await.is_ok());
        // …а клиент, который заморозку уже видел, — нет: отстающий или злонамеренный резолвер её не «отменит».
        let mut cache = NoticeCache::memory();
        assert!(resolve(client.endpoint(), &[a1], &tr, "shop.brand", &mut cache).await.is_err());
        assert_eq!(cache.all().len(), 1);
        let err = resolve(client.endpoint(), &[a3.clone()], &tr, "shop.brand", &mut cache).await.unwrap_err();
        assert!(err.to_string().contains("заморожен"), "{err}");

        // Клиент может подтянуть объявления заранее, не открывая сайтов.
        let mut fresh = NoticeCache::memory();
        assert_eq!(sync_notices(client.endpoint(), &[a2, a3], &root.public(), &mut fresh).await, 1);
        let err = resolve(client.endpoint(), &[n3.endpoint().addr()], &tr, "shop.brand", &mut fresh).await.unwrap_err();
        assert!(err.to_string().contains("заморожен"), "{err}");
    }
}

