//! Клиент Rift для браузера и приложений: имя → проверенная цепочка → хост → HTTP-запрос.
//!
//! * `RiftClient::request` — принимает обычный `http::Request` с хостом `shop.brand` (или `shop.brand.rift`) и
//!   возвращает потоковый ответ. На каждый запрос — новый QUIC-стрим по общему соединению с хостом
//!   (стримы дешёвые, поэтому keep-alive поверх одного стрима не нужен).
//! * `serve_proxy` — локальный HTTP-прокси: любой браузер открывает `http://shop.brand.rift/`.
//!
//! ponytail: HTTPS через прокси (CONNECT) не поддержан: для secure-контекста нужен локальный CA или
//! собственная схема в WebView (приложение). Апгрейды (WebSocket) через прокси тоже пока нет.

use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body as HttpBody, Incoming},
    header::{self, HeaderValue},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use iroh::{Endpoint, EndpointAddr, endpoint::Connection};
use rift_trust::{Resolved, Trust};
use tokio::{net::TcpListener, sync::Mutex as AsyncMutex};
use tracing::debug;

use crate::{
    NodeId, RelayUrl, TransportAddr,
    host::{Body, HTTP_ALPN},
    names::{Blocked, NoticeCache, now, resolve},
};

/// Сколько держим результат резолва. Заморозка после этого срока дойдёт до клиента при следующем резолве.
const NAME_TTL: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// `shop.brand.rift` → `shop.brand`; `control.rift` → `control.rift` (системная зона). Имена всегда из двух меток,
/// поэтому «3 метки с `.rift` на конце» и «2 метки `x.rift`» различимы однозначно.
pub fn rift_name(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    match labels.as_slice() {
        [label, "rift"] if rift_trust::valid_label(label) => Some(host),
        [label, zone, "rift"] if rift_trust::valid_label(label) && rift_trust::valid_label(zone) => Some(format!("{label}.{zone}")),
        _ => None,
    }
}

pub struct RiftClient {
    endpoint: Endpoint,
    trust: Trust,
    resolvers: Vec<EndpointAddr>,
    relay: Option<RelayUrl>,
    notices: AsyncMutex<NoticeCache>,
    /// Имя → (результат, когда получен, сколько объявлений было известно). Новое объявление делает запись устаревшей.
    names: Mutex<HashMap<String, (Resolved, Instant, usize)>>,
    conns: Mutex<HashMap<NodeId, Connection>>,
    hints: Mutex<HashMap<NodeId, EndpointAddr>>,
}

impl RiftClient {
    /// `relay` — подсказка, где искать хосты (они сидят на тех же relay). `notices` — кэш заморозок и отзывов.
    pub fn new(endpoint: Endpoint, trust: Trust, resolvers: Vec<EndpointAddr>, relay: Option<RelayUrl>, notices: NoticeCache) -> Self {
        Self {
            endpoint,
            trust,
            resolvers,
            relay,
            notices: AsyncMutex::new(notices),
            names: Default::default(),
            conns: Default::default(),
            hints: Default::default(),
        }
    }

    /// Известный адрес хоста (например, из mDNS или конфига): пробуется вместо «NodeID + relay».
    pub fn add_hint(&self, addr: EndpointAddr) {
        self.hints.lock().unwrap().insert(addr.id, addr);
    }

    pub async fn resolve(&self, name: &str) -> Result<Resolved> {
        let mut cache = self.notices.lock().await;
        if let Some((r, at, seen)) = self.names.lock().unwrap().get(name) {
            // Свежий результат годится, только пока не появилось ни одного нового объявления: заморозка не ждёт TTL.
            if at.elapsed() < NAME_TTL && now() < r.valid_until && *seen == cache.all().len() {
                return Ok(r.clone());
            }
        }
        let r = resolve(&self.endpoint, &self.resolvers, &self.trust, name, &mut cache).await;
        match &r {
            Ok(r) => {
                self.names.lock().unwrap().insert(name.to_string(), (r.clone(), Instant::now(), cache.all().len()));
            }
            // Заморозка действует сразу: из кэша имён выкидываем.
            Err(e) if e.downcast_ref::<Blocked>().is_some() => {
                self.names.lock().unwrap().remove(name);
            }
            Err(_) => {}
        }
        r
    }

    /// Подтягивает объявления (заморозки, отзывы) у резолверов. Возвращает число новых.
    pub async fn sync_notices(&self) -> usize {
        let mut cache = self.notices.lock().await;
        crate::names::sync_notices(&self.endpoint, &self.resolvers, &self.trust.root, &mut cache).await
    }

    async fn connection(&self, host: NodeId, fresh: bool) -> Result<Connection> {
        if !fresh {
            if let Some(c) = self.conns.lock().unwrap().get(&host).filter(|c| c.close_reason().is_none()) {
                return Ok(c.clone());
            }
        }
        let addr = self
            .hints
            .lock()
            .unwrap()
            .get(&host)
            .cloned()
            .unwrap_or_else(|| EndpointAddr::from_parts(host, self.relay.clone().map(TransportAddr::Relay)));
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, self.endpoint.connect(addr, HTTP_ALPN))
            .await
            .map_err(|_| anyhow!("хост {} не отвечает {CONNECT_TIMEOUT:?}", host.fmt_short()))??;
        self.conns.lock().unwrap().insert(host, conn.clone());
        Ok(conn)
    }

    /// Первый доступный хост из записей домена. Повтор на свежем соединении — если пулёное протухло.
    async fn open_stream(&self, hosts: &[NodeId]) -> Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream)> {
        let mut last: Option<anyhow::Error> = None;
        for h in hosts {
            for fresh in [false, true] {
                match self.connection(*h, fresh).await {
                    Ok(c) => match c.open_bi().await {
                        Ok(s) => return Ok(s),
                        Err(e) => {
                            self.conns.lock().unwrap().remove(h);
                            last = Some(e.into());
                        }
                    },
                    Err(e) => {
                        last = Some(e);
                        break; // свежее соединение не поднялось — этот хост недоступен
                    }
                }
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("в записях домена нет хостов")))
    }

    /// Выполняет запрос к `rift://`-сайту. Хост берётся из URI или заголовка `Host`; путь и тело — как есть.
    pub async fn request<B>(&self, req: Request<B>) -> Result<Response<Incoming>>
    where
        B: HttpBody + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let host = req
            .uri()
            .host()
            .map(str::to_string)
            .or_else(|| req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).map(|h| h.split(':').next().unwrap_or(h).to_string()))
            .context("в запросе нет хоста")?;
        let name = rift_name(&host).with_context(|| format!("{host}: это не имя Rift (ожидалось имя.зона или имя.зона.rift)"))?;
        self.request_to(&name, req).await
    }

    /// То же, но имя задано явно (для шлюза: там голое `shop.brand` — точно имя Rift, а не домен из интернета).
    pub async fn request_to<B>(&self, name: &str, mut req: Request<B>) -> Result<Response<Incoming>>
    where
        B: HttpBody + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let host = name;
        // На хост уходит origin-form; `Host` оставляем исходным: хост-прокси сам подставит нужный.
        let pq = req.uri().path_and_query().map_or_else(|| "/".to_string(), |p| p.as_str().to_string());
        *req.uri_mut() = pq.parse()?;
        req.headers_mut().insert(header::HOST, HeaderValue::from_str(&host)?);

        let resolved = self.resolve(name).await?;
        let (send, recv) = self.open_stream(&resolved.hosts).await?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tokio::io::join(recv, send))).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                debug!("клиент: поток закрыт: {e}");
            }
        });
        Ok(sender.send_request(req).await?)
    }

    pub fn trust(&self) -> &Trust {
        &self.trust
    }

    pub fn resolver_count(&self) -> usize {
        self.resolvers.len()
    }

    /// NodeID этого клиента: под ним он виден хостам (`Rift-Client-Id`).
    pub fn node_id(&self) -> NodeId {
        self.endpoint.id()
    }

    /// Сколько соединений с хостами сейчас в пуле (для тестов и диагностики).
    pub fn pooled(&self) -> usize {
        self.conns.lock().unwrap().len()
    }
}

// ---------------------------------------------------------------- прокси

fn text(status: StatusCode, msg: &str) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from(format!("{msg}\n"))).map_err(|never| match never {}).boxed());
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    r
}

/// Принимает соединения браузера. Не делает из тебя открытый прокси: всё, что не `*.rift`, получает 403.
pub async fn serve_proxy(client: Arc<RiftClient>, listener: TcpListener) -> Result<()> {
    loop {
        let (tcp, _) = listener.accept().await?;
        let client = client.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let client = client.clone();
                async move { Ok::<_, Infallible>(proxy_one(&client, req).await) }
            });
            hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await.ok();
        });
    }
}

async fn proxy_one(client: &RiftClient, mut req: Request<Incoming>) -> Response<Body> {
    if req.method() == Method::CONNECT {
        return text(StatusCode::NOT_IMPLEMENTED, "rift: HTTPS через прокси пока не поддержан, открывай http://имя.зона.rift/");
    }
    let host = req
        .uri()
        .host()
        .map(str::to_string)
        .or_else(|| req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).map(|h| h.split(':').next().unwrap_or(h).to_string()))
        .unwrap_or_default();
    if rift_name(&host).is_none() {
        return text(StatusCode::FORBIDDEN, "rift: этот прокси отдаёт только сайты *.rift, а не весь интернет");
    }
    req.headers_mut().remove("proxy-connection");
    match client.request(req).await {
        Ok(resp) => resp.map(|b| b.boxed()),
        Err(e) if e.downcast_ref::<Blocked>().is_some() => text(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS, &format!("rift: {e}")),
        Err(e) => text(StatusCode::BAD_GATEWAY, &format!("rift: {e:#}")),
    }
}

#[cfg(test)]
mod tests {
    use rift_trust::{Announcement, Notice, Signed};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{
        names::Request as NamesRequest,
        testutil::{Site, hello_app, site},
    };

    #[test]
    fn host_to_name() {
        for (host, want) in [
            ("shop.brand.rift", Some("shop.brand")),
            ("SHOP.Brand.RIFT", Some("shop.brand")),
            ("shop.brand.rift.", Some("shop.brand")),
            ("control.rift", Some("control.rift")),
            ("log.rift", Some("log.rift")),
            ("example.com", None),
            ("rift", None),
            ("a.b.c.rift", None),
            ("-x.brand.rift", None),
            ("shop.brand", None), // без .rift в прокси — не наше
            ("", None),
        ] {
            assert_eq!(rift_name(host).as_deref(), want, "{host:?}");
        }
    }

    type Setup = Site;

    /// Хост с приложением (отвечает «hello <путь>»), резолвер, клиент.
    async fn setup() -> Setup {
        site(&hello_app().await).await
    }

    async fn body_of(resp: Response<Incoming>) -> String {
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned()
    }

    fn get(uri: &str) -> Request<Full<Bytes>> {
        Request::get(uri).body(Full::new(Bytes::new())).unwrap()
    }

    #[tokio::test]
    async fn requests_use_pool_and_name_cache() {
        let s = setup().await;
        for path in ["/a", "/b?x=1", "/c"] {
            let resp = s.client.request(get(&format!("http://shop.brand.rift{path}"))).await.unwrap();
            assert_eq!(resp.status(), 200);
            assert_eq!(body_of(resp).await, format!("hello {path}"));
        }
        assert_eq!(s.client.pooled(), 1, "все запросы по одному QUIC-соединению");

        // Чужое, неизвестное и не-rift.
        assert!(s.client.request(get("http://example.com/")).await.is_err());
        assert!(s.client.request(get("http://nope.brand.rift/")).await.is_err());

        // Резолвер пропал — имя в кэше, запросы идут дальше.
        s.resolver_node.shutdown().await.unwrap();
        let resp = s.client.request(get("http://shop.brand.rift/after")).await.unwrap();
        assert_eq!(body_of(resp).await, "hello /after");
    }

    #[tokio::test]
    async fn frozen_domain_is_blocked_and_dropped_from_name_cache() {
        let s = setup().await;
        assert!(s.client.request(get("http://shop.brand.rift/")).await.is_ok());

        // Заморозка пришла на резолвер. Кэш имён (60 с) ещё свеж, но клиент узнаёт об объявлении, и запись устаревает сразу.
        let freeze = Announcement { notice: Signed::sign(Notice::Freeze { name: "shop.brand".into(), since: 0 }, &s.root), control: None };
        s.resolver.handle(NamesRequest::PutNotice(freeze));
        assert!(s.client.request(get("http://shop.brand.rift/")).await.is_ok(), "пока клиент не знает об объявлении, кэш действует");
        assert_eq!(s.client.sync_notices().await, 1);
        let err = s.client.request(get("http://shop.brand.rift/")).await.unwrap_err();
        assert!(err.downcast_ref::<Blocked>().is_some(), "{err:#}");
        assert!(s.client.names.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn proxy_serves_rift_and_refuses_everything_else() {
        let s = setup().await;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve_proxy(s.client.clone(), l));

        let raw = async |req: &str| {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            c.write_all(req.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            c.read_to_end(&mut out).await.unwrap();
            String::from_utf8_lossy(&out).into_owned()
        };
        let line = |r: &str| r.lines().next().unwrap_or("").to_string();

        let ok = raw("GET http://shop.brand.rift/page?q=1 HTTP/1.1\r\nHost: shop.brand.rift\r\nProxy-Connection: close\r\nConnection: close\r\n\r\n").await;
        assert_eq!(line(&ok), "HTTP/1.1 200 OK", "{ok}");
        assert!(ok.ends_with("hello /page?q=1"), "{ok}");

        // Не открытый прокси в интернет.
        let r = raw("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").await;
        assert!(line(&r).contains("403"), "{r}");
        let r = raw("GET http://127.0.0.1:22/ HTTP/1.1\r\nHost: 127.0.0.1:22\r\nConnection: close\r\n\r\n").await;
        assert!(line(&r).contains("403"), "{r}");
        // HTTPS пока не поддержан — честно говорим.
        let r = raw("CONNECT shop.brand.rift:443 HTTP/1.1\r\nHost: shop.brand.rift:443\r\nConnection: close\r\n\r\n").await;
        assert!(line(&r).contains("501"), "{r}");
        // Неизвестное имя.
        let r = raw("GET http://nope.brand.rift/ HTTP/1.1\r\nHost: nope.brand.rift\r\nConnection: close\r\n\r\n").await;
        assert!(line(&r).contains("502"), "{r}");

        // Заморозка → 451.
        let freeze = Announcement { notice: Signed::sign(Notice::Freeze { name: "shop.brand".into(), since: 0 }, &s.root), control: None };
        s.resolver.handle(NamesRequest::PutNotice(freeze));
        s.client.names.lock().unwrap().clear();
        let r = raw("GET http://shop.brand.rift/ HTTP/1.1\r\nHost: shop.brand.rift\r\nConnection: close\r\n\r\n").await;
        assert!(line(&r).contains("451"), "{r}");
    }
}
