//! Имена `rift://имя.зона`. Резолвер — НЕДОВЕРЕННЫЙ кэш цепочек: он может только не ответить
//! или ответить устаревшим. Подлинность клиент проверяет сам по root-ключу (rift-trust),
//! поэтому резолвером может быть любая нода, а control в резолве не участвует.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow, bail};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use rift_trust::{Announcement, Bundle, Error as TrustError, Resolved, Time, Trust, newest, verify};
use serde::{Deserialize, Serialize};
use tracing::debug;

pub const NAMES_ALPN: &[u8] = b"rift/names/0";
const MAX_MSG: usize = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

pub fn now() -> Time {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Get { name: String },
    PutBundle(Bundle),
    PutNotice(Announcement),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Found { bundle: Bundle, notices: Vec<Announcement> },
    NotFound,
    Ok,
    Rejected(String),
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
    notices: Vec<Announcement>,
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
                Some(b) => Response::Found { bundle: b.clone(), notices: st.notices.clone() },
                None => Response::NotFound,
            },
            Request::PutBundle(b) => {
                // Хранить можно только то, что проходит проверку: мусор и подделки не накапливаются.
                let r = match verify(&self.trust, &b, &st.notices, now()) {
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
                let same = |a: &Announcement| serde_json::to_vec(a).ok() == serde_json::to_vec(&n).ok();
                if !st.notices.iter().any(same) {
                    st.notices.push(n);
                }
                Response::Ok
            }
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
pub fn check(trust: &Trust, name: &str, resp: Response, now: Time) -> Result<Option<Resolved>, TrustError> {
    match resp {
        Response::Found { bundle, notices } => {
            let r = verify(trust, &bundle, &notices, now)?;
            if r.name != name {
                return Err(TrustError::Mismatch("резолвер подсунул другое имя"));
            }
            Ok(Some(r))
        }
        _ => Ok(None),
    }
}

/// Резолвит имя. Берёт самую свежую (по `seq`) проверенную копию.
/// Заморозка/отзыв, подтверждённые подписью хотя бы от одного резолвера, действуют сразу:
/// отказ безопаснее, чем показать замороженный домен.
pub async fn resolve(
    endpoint: &Endpoint,
    resolvers: &[EndpointAddr],
    trust: &Trust,
    name: &str,
) -> Result<Resolved> {
    let (mut found, mut last_err) = (vec![], None);
    for r in resolvers {
        match query(endpoint, r.clone(), &Request::Get { name: name.into() }).await {
            Ok(resp) => match check(trust, name, resp, now()) {
                Ok(Some(x)) => found.push(x),
                Ok(None) => {}
                Err(e @ (TrustError::Frozen(_) | TrustError::Revoked(_))) => bail!("{name}: {e}"),
                Err(e) => last_err = Some(e.to_string()),
            },
            Err(e) => last_err = Some(format!("{e:#}")),
        }
    }
    newest(found).ok_or_else(|| anyhow!("{name}: не найдено ({})", last_err.unwrap_or_else(|| "резолверы не знают имени".into())))
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
    use iroh::{RelayMode, SecretKey};
    use rift_trust::{ControlCert, DnsRecords, DomainRecord, Notice, PublicKey, Record, Signed, ZoneCert, log::logged_now};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{Config, Node, host::{HTTP_ALPN, Host, fetch, get_request}};

    const DAY: Time = 86_400;

    /// Единственный свидетель всех тестов.
    fn witness() -> &'static SecretKey {
        static W: std::sync::OnceLock<SecretKey> = std::sync::OnceLock::new();
        W.get_or_init(SecretKey::generate)
    }

    fn trust(root: &SecretKey) -> Trust {
        Trust { root: root.public(), witnesses: vec![witness().public()], threshold: 1 }
    }

    /// Цепочка root → control → зона `brand` (владелец зоны сам регистрирует) → shop.brand → хост.
    fn bundle(root: &SecretKey, control: &SecretKey, zone: &SecretKey, owner: &SecretKey, host: PublicKey, seq: u64) -> Bundle {
        let (t, name) = (now() - 60, "shop.brand".to_string());
        let zone_cert = Signed::sign(ZoneCert { zone: "brand".into(), owner: zone.public(), issued_at: t, expires_at: t + 700 * DAY }, control);
        let domain = Signed::sign(DomainRecord { name: name.clone(), owner: owner.public(), issued_at: t, expires_at: t + 300 * DAY }, zone);
        Bundle {
            control: Signed::sign(ControlCert { key: control.public(), issued_at: t, expires_at: t + 90 * DAY }, root),
            zone: logged_now(control, zone_cert, t + 1, &[witness()]),
            registrar: None,
            domain: logged_now(zone, domain, t + 1, &[witness()]),
            dns: Signed::sign(DnsRecords { name, seq, records: vec![Record::Host(host)], issued_at: t, expires_at: t + 30 * DAY }, owner),
        }
    }

    async fn node(extra: Vec<(Vec<u8>, crate::Handler)>) -> Node {
        Node::bind(Config {
            key: SecretKey::generate(),
            relay_mode: RelayMode::Disabled,
            lan: false,
            proxy: None,
            bridge: None,
            relay_ca: None,
            vpn: None,
            extra,
        })
        .await
        .unwrap()
    }

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
        let host = node(vec![(HTTP_ALPN.to_vec(), Box::new(Host::new(app().await)))]).await;
        let b = bundle(&root, &control, &zone, &owner, host.id(), 1);
        // Control выключен: его ключа больше нет, дальше работают только подписи в цепочке.
        drop((control, zone));

        let resolver = node(vec![(NAMES_ALPN.to_vec(), Box::new(Resolver::new(trust(&root))))]).await;
        let client = node(vec![]).await;
        let rs = [resolver.endpoint().addr()];

        assert_eq!(publish(host.endpoint(), &rs, Request::PutBundle(b)).await, 1);
        let r = resolve(client.endpoint(), &rs, &trust(&root), "shop.brand").await.unwrap();
        assert_eq!(r.hosts, vec![host.id()]);

        let resp = fetch(client.endpoint(), host.endpoint().addr(), &get_request("shop.brand", "/")).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).ends_with("hello from node"));

        // Неизвестное имя.
        assert!(resolve(client.endpoint(), &rs, &trust(&root), "nope.brand").await.is_err());
        // Клиент с чужим root не верит ничему, что есть у резолвера.
        let other = trust(&SecretKey::generate());
        assert!(resolve(client.endpoint(), &rs, &other, "shop.brand").await.is_err());
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

        assert_eq!(check(&trust(&root), "shop.brand", found(), now()).unwrap().unwrap().hosts, vec![host]);
        // Спросили одно имя, резолвер подсунул цепочку другого (валидную!) — отказ.
        assert!(matches!(check(&trust(&root), "bank.brand", found(), now()), Err(TrustError::Mismatch(_))));
        // «Не знаю» — не ошибка.
        assert_eq!(check(&trust(&root), "shop.brand", Response::NotFound, now()), Ok(None));
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
        assert!(matches!(check(&trust(&root), "shop.brand", resp, now() + 1), Err(TrustError::Frozen(_))));
    }
}
