//! Шлюз для WebView: `http://<имя>.<метка>.localhost:ПОРТ/` → `RiftClient` → rift-сайт.
//!
//! Зачем так, а не схема `rift://` (проверено в WKWebView, см. docs/browser.md): у кастомной схемы нет cookie и
//! Service Worker, а `*.localhost` — безопасный контекст сразу, без TLS и локального CA, и у каждого сайта свой origin.
//!
//! Шлюз виден любой программе на этой машине (например, странице в другом браузере), поэтому адрес защищён
//! **секретной меткой**: `метка = HMAC(секрет установки, имя)`. Чужая страница не знает метки: подбор адреса
//! (DNS-rebinding) и запросы «от лица пользователя» не проходят. Метка своя у каждого сайта, значит сайты друг для
//! друга cross-site, и SameSite-cookie защищают их так же, как в обычном вебе.
//!
//! Шлюз приводит запрос к тому, что ждёт приложение: `Host` = имя, `Origin`/`Referer` = `https://имя`, из
//! `Set-Cookie` убирается `Domain`, абсолютные `Location` на имя возвращаются на адрес шлюза, а из CSP и HSTS
//! убирается то, что сломало бы http-адрес (`upgrade-insecure-requests`, `Strict-Transport-Security`).
//!
//! ponytail: тела не переписываются: абсолютные ссылки `https://имя/…` внутри HTML остаются как есть (приложению
//! нужны относительные пути).

use std::{collections::HashMap, convert::Infallible, sync::{Arc, Mutex}};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hmac::{Hmac, Mac};
use hyper::{
    Request, Response, StatusCode,
    body::Incoming,
    header::{self, HeaderMap, HeaderName, HeaderValue},
    service::service_fn,
    upgrade,
};
use hyper_util::rt::TokioIo;
use sha2::Sha256;
use tokio::net::TcpListener;
use tracing::debug;

use crate::{
    client::RiftClient,
    host::Body,
    pages::{self, Kind},
};

/// Длина метки в байтах (в адресе — 2 hex-символа на байт; 80 бит подбором не взять).
const LABEL_BYTES: usize = 10;

pub struct Gateway {
    client: Arc<RiftClient>,
    secret: [u8; 32],
    /// Встроенные страницы приложения под системными именами (`start.rift`): отдаются локально, в сеть не ходят.
    pages: Mutex<HashMap<String, Bytes>>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (s.len() % 2 == 0 && s.is_ascii()).then(|| ()).and_then(|()| (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect())
}

fn page(status: StatusCode, html: String) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from(html)).map_err(|never| match never {}).boxed());
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn text(status: StatusCode, msg: &str) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from(format!("{msg}\n"))).map_err(|never| match never {}).boxed());
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    r
}

impl Gateway {
    /// `secret` — случайный 32-байтный секрет установки (хранится приложением; от него зависят адреса сайтов,
    /// а значит и их origin: при смене секрета локальные данные сайтов в WebView «потеряются»).
    pub fn new(client: Arc<RiftClient>, secret: [u8; 32]) -> Self {
        Self { client, secret, pages: Default::default() }
    }

    /// Регистрирует встроенную страницу под именем (`start.rift`). Открывается как обычный сайт, но живёт в приложении.
    pub fn add_page(&self, name: &str, html: String) {
        self.pages.lock().unwrap().insert(name.to_string(), Bytes::from(html));
    }

    fn mac(&self, name: &str) -> Hmac<Sha256> {
        let mut m = Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC принимает ключ любой длины");
        m.update(b"rift-gateway/v1\0");
        m.update(name.as_bytes());
        m
    }

    /// Хост сайта в адресной строке WebView: `shop.brand.<метка>.localhost`.
    pub fn host_for(&self, name: &str) -> String {
        let tag = self.mac(name).finalize().into_bytes();
        format!("{name}.{}.localhost", hex(&tag[..LABEL_BYTES]))
    }

    /// Полный адрес страницы сайта на шлюзе, слушающем `port`. `path` — с ведущим `/`.
    pub fn url_for(&self, name: &str, path: &str, port: u16) -> String {
        format!("http://{}:{port}{path}", self.host_for(name))
    }

    /// Имя сайта по `Host` запроса, если метка верна. Порт отбрасывается.
    pub fn name_from_host(&self, host: &str) -> Option<String> {
        let host = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(h, _)| h);
        let rest = host.to_ascii_lowercase().strip_suffix(".localhost")?.to_string();
        let (name, label) = rest.rsplit_once('.')?;
        rift_trust::split_name(name)?;
        // Сравнение за постоянное время: верный префикс не должен быть заметен по времени ответа.
        self.mac(name).verify_truncated_left(&unhex(label).filter(|b| b.len() == LABEL_BYTES)?).ok()?;
        Some(name.to_string())
    }

    /// Принимает соединения WebView. Слушать нужно на loopback.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        while let Ok((tcp, _)) = listener.accept().await {
            let gw = self.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let gw = gw.clone();
                    async move { Ok::<_, Infallible>(gw.handle(req).await) }
                });
                hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).with_upgrades().await.ok();
            });
        }
    }

    async fn handle(&self, mut req: Request<Incoming>) -> Response<Body> {
        let authority = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or_default().to_string();
        // Страницу ошибки с оформлением показываем только навигации браузера; `fetch`/XHR получают короткий текст.
        let html = req.headers().get(header::ACCEPT).and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("text/html"));
        let Some(name) = self.name_from_host(&authority) else {
            // Неверная метка — тот же ответ, что и на «нет такого сайта»: ничего не подсказываем.
            return if html {
                page(StatusCode::FORBIDDEN, pages::error_page(403, Kind::Forbidden, "Адрес не принадлежит этому устройству", "Этот адрес шлюза создан другой установкой Rift или подделан. Откройте сайт через адресную строку приложения.", "", ""))
            } else {
                text(StatusCode::FORBIDDEN, "rift: неверный адрес шлюза")
            };
        };
        if let Some(body) = self.pages.lock().unwrap().get(&name).cloned() {
            return match *req.method() {
                hyper::Method::GET | hyper::Method::HEAD => {
                    let mut r = page(StatusCode::OK, String::from_utf8_lossy(&body).into_owned());
                    r.headers_mut().insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"));
                    r
                }
                _ => text(StatusCode::METHOD_NOT_ALLOWED, "rift: только GET и HEAD"),
            };
        }

        let wants_upgrade = req.headers().contains_key(header::UPGRADE)
            && req.headers().get_all(header::CONNECTION).iter().filter_map(|v| v.to_str().ok()).any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")));
        let browser_upgrade = upgrade::on(&mut req);

        let gateway_origin = format!("http://{authority}");
        let site_origin = format!("https://{name}");
        let (mut parts, body) = req.into_parts();
        // Приложение должно видеть то, что видело бы в обычном вебе: своё имя, свой origin.
        parts.headers.remove(header::HOST);
        for h in [header::ORIGIN, header::REFERER] {
            if let Some(v) = parts.headers.get(&h).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix(&gateway_origin)) {
                let v = HeaderValue::from_str(&format!("{site_origin}{v}")).ok();
                if let Some(v) = v {
                    parts.headers.insert(h, v);
                }
            }
        }
        let outgoing = Request::from_parts(parts, body);

        let mut resp = match self.client.request_to(&name, outgoing).await {
            Ok(r) => r,
            Err(e) if e.downcast_ref::<crate::names::Blocked>().is_some() => {
                return if html {
                    page(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS, pages::error_page(
                        451, Kind::Blocked, "Сайт заморожен",
                        &format!("Доступ к {name} закрыт решением оператора сети. Решение подписано и публично, поэтому действует на всех устройствах."),
                        &e.to_string(),
                        "Заморозка снимается отдельным публичным объявлением. Если вы владелец домена, свяжитесь с оператором сети.",
                    ))
                } else {
                    text(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS, &format!("rift: {e}"))
                };
            }
            Err(e) => {
                return if html {
                    page(StatusCode::BAD_GATEWAY, pages::error_page(
                        502, Kind::Unreachable, "Сайт недоступен",
                        &format!("Не удалось открыть {name}. Имя не найдено у резолверов, либо хост сайта сейчас не отвечает."),
                        &format!("{e:#}"),
                        "Проверьте адрес. Если сайт должен работать, попробуйте позже: хост мог выключиться.",
                    ))
                } else {
                    text(StatusCode::BAD_GATEWAY, &format!("rift: {e:#}"))
                };
            }
        };

        if resp.status() == StatusCode::SWITCHING_PROTOCOLS && wants_upgrade {
            let site_upgrade = upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(b), Ok(s)) = (browser_upgrade.await, site_upgrade.await) {
                    if let Err(e) = tokio::io::copy_bidirectional(&mut TokioIo::new(b), &mut TokioIo::new(s)).await {
                        debug!("шлюз: апгрейд закрыт: {e}");
                    }
                }
            });
        }
        let (mut parts, incoming) = resp.into_parts();
        rewrite_response_headers(&mut parts.headers, &name, &gateway_origin);
        Response::from_parts(parts, incoming.boxed())
    }
}

/// Приводит заголовки ответа сайта к http-адресу шлюза.
fn rewrite_response_headers(h: &mut HeaderMap, name: &str, gateway_origin: &str) {
    // Cookie: `Domain=имя` браузер на адресе шлюза отверг бы; без Domain cookie привязывается к хосту шлюза (host-only).
    let cookies: Vec<HeaderValue> = h
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| {
            let s = v.to_str().unwrap_or_default();
            let kept: Vec<&str> = s.split(';').filter(|a| !a.trim().to_ascii_lowercase().starts_with("domain=")).collect();
            HeaderValue::from_str(&kept.join(";")).unwrap_or_else(|_| v.clone())
        })
        .collect();
    if h.contains_key(header::SET_COOKIE) {
        h.remove(header::SET_COOKIE);
        for c in cookies {
            h.append(header::SET_COOKIE, c);
        }
    }
    // Редиректы на собственное имя возвращаем на шлюз.
    if let Some(loc) = h.get(header::LOCATION).and_then(|v| v.to_str().ok()).map(str::to_string) {
        for prefix in [format!("https://{name}"), format!("http://{name}"), format!("//{name}"), format!("https://{name}.rift"), format!("http://{name}.rift")] {
            if let Some(rest) = loc.strip_prefix(&prefix) {
                if rest.is_empty() || rest.starts_with(['/', '?', '#']) {
                    if let Ok(v) = HeaderValue::from_str(&format!("{gateway_origin}{rest}")) {
                        h.insert(header::LOCATION, v);
                    }
                    break;
                }
            }
        }
    }
    // Эти заголовки ломают http-адрес шлюза: HSTS и принудительное повышение до https.
    h.remove(header::STRICT_TRANSPORT_SECURITY);
    for name in [header::CONTENT_SECURITY_POLICY, HeaderName::from_static("content-security-policy-report-only")] {
        let fixed: Vec<HeaderValue> = h
            .get_all(&name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|v| v.split(';').filter(|d| d.trim().to_ascii_lowercase() != "upgrade-insecure-requests").collect::<Vec<_>>().join(";"))
            .filter_map(|v| HeaderValue::from_str(&v).ok())
            .collect();
        if h.contains_key(&name) {
            h.remove(&name);
            for v in fixed {
                h.append(&name, v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::testutil::{echo_app, site};

    fn gw_with(client: Arc<RiftClient>, secret: [u8; 32]) -> Arc<Gateway> {
        Arc::new(Gateway::new(client, secret))
    }

    #[tokio::test]
    async fn addresses_are_per_site_secret_and_checked() {
        let s = site(&echo_app().await).await;
        let g = gw_with(s.client.clone(), [7; 32]);
        let other = gw_with(s.client.clone(), [8; 32]);

        let host = g.host_for("shop.brand");
        assert_eq!(host, g.host_for("shop.brand"), "стабильно между запусками");
        assert!(host.starts_with("shop.brand.") && host.ends_with(".localhost"));
        assert_ne!(host, g.host_for("two.brand"), "у каждого сайта своя метка (изоляция сайтов)");
        assert_ne!(host, other.host_for("shop.brand"), "метка зависит от секрета установки");
        assert_eq!(g.url_for("shop.brand", "/a?b=1", 7878), format!("http://{host}:7878/a?b=1"));

        // Принимаем свой адрес (с портом и без, в любом регистре).
        for h in [host.clone(), format!("{host}:7878"), host.to_uppercase()] {
            assert_eq!(g.name_from_host(&h).as_deref(), Some("shop.brand"), "{h}");
        }
        // Всё остальное — нет: чужой секрет, чужая метка, подмена имени, не тот суффикс, голые адреса.
        let tag = host.split('.').nth(2).unwrap().to_string();
        for bad in [
            other.host_for("shop.brand"),
            format!("two.brand.{tag}.localhost"), // метка от другого имени
            format!("shop.brand.{}.localhost", "0".repeat(20)),
            format!("shop.brand.{}.localhost", &tag[..18]),
            format!("shop.brand.{tag}00.localhost"),
            format!("shop.brand.{tag}.example.com"),
            format!("shop.brand.{tag}"),
            "shop.brand.localhost".into(),
            "localhost".into(),
            "127.0.0.1:7878".into(),
            "".into(),
            format!("a.b.c.{tag}.localhost"),
        ] {
            assert_eq!(g.name_from_host(&bad), None, "{bad}");
        }
    }

    /// Запрос «браузера» к шлюзу: сырой HTTP, чтобы видеть ровно то, что вернётся.
    async fn raw(addr: std::net::SocketAddr, req: String) -> (String, String) {
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).await.unwrap();
        let s = String::from_utf8_lossy(&out).into_owned();
        let (head, body) = s.split_once("\r\n\r\n").unwrap_or((&s, ""));
        (head.to_string(), body.to_string())
    }

    async fn running() -> (Arc<Gateway>, std::net::SocketAddr, crate::testutil::Site) {
        let s = site(&echo_app().await).await;
        let g = gw_with(s.client.clone(), [3; 32]);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(g.clone().serve(l));
        (g, addr, s)
    }

    fn get(host: &str, path: &str, extra: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n")
    }

    #[tokio::test]
    async fn serves_site_with_rewritten_request_and_refuses_bad_addresses() {
        let (g, addr, _s) = running().await;
        let host = format!("{}:{}", g.host_for("shop.brand"), addr.port());
        let origin = format!("http://{host}");

        let (head, body) = raw(addr, get(&host, "/headers?x=1", &format!("Origin: {origin}\r\nReferer: {origin}/page?q\r\nCookie: sid=abc\r\n"))).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        // Приложение видит имя сайта, а не адрес шлюза: Host (через прокси хоста) и Origin/Referer как у https://имя.
        assert!(body.contains("xfh=shop.brand"), "{body}");
        assert!(body.contains("origin=https://shop.brand"), "{body}");
        assert!(body.contains("referer=https://shop.brand/page?q"), "{body}");
        assert!(body.contains("cookie=sid=abc"), "{body}");
        assert!(body.contains("path=/headers?x=1"), "{body}");

        // Чужая метка, голый loopback, чужой Host (DNS-rebinding) — 403 и никакого похода в сеть.
        for bad in [format!("shop.brand.{}.localhost:{}", "ab".repeat(10), addr.port()), format!("127.0.0.1:{}", addr.port()), format!("evil.example:{}", addr.port())] {
            let (head, body) = raw(addr, get(&bad, "/headers", "")).await;
            assert!(head.starts_with("HTTP/1.1 403"), "{bad}: {head}");
            assert!(!body.contains("xfh="), "{bad}");
        }
    }

    #[tokio::test]
    async fn response_headers_fit_the_gateway_address() {
        let (g, addr, _s) = running().await;
        let host = format!("{}:{}", g.host_for("shop.brand"), addr.port());

        // Cookie: Domain убран, остальное цело; несколько cookie не склеиваются.
        let (head, _) = raw(addr, get(&host, "/cookie", "")).await;
        let cookies: Vec<&str> = head.lines().filter(|l| l.to_lowercase().starts_with("set-cookie:")).collect();
        assert_eq!(cookies.len(), 2, "{head}");
        assert!(cookies[0].contains("sid=1") && cookies[0].contains("HttpOnly") && cookies[0].contains("Path=/"), "{head}");
        assert!(!head.to_lowercase().contains("domain="), "{head}");

        // Редирект на собственное имя возвращается на адрес шлюза; чужие остаются.
        let (head, _) = raw(addr, get(&host, "/redir", "")).await;
        assert!(head.starts_with("HTTP/1.1 302"), "{head}");
        assert!(head.contains(&format!("location: http://{host}/landing?a=1")), "{head}");
        let (head, _) = raw(addr, get(&host, "/redir-other", "")).await;
        assert!(head.contains("location: https://shop.brand.evil.com/x"), "имя-префикс чужого домена не трогаем: {head}");

        // HSTS и upgrade-insecure-requests убраны, остальная CSP цела.
        let (head, _) = raw(addr, get(&host, "/csp", "")).await;
        let lower = head.to_lowercase();
        assert!(!lower.contains("strict-transport-security"), "{head}");
        assert!(!lower.contains("upgrade-insecure-requests"), "{head}");
        assert!(lower.contains("default-src 'self'"), "{head}");
    }

    #[tokio::test]
    async fn websocket_style_upgrade_passes_through() {
        let (g, addr, _s) = running().await;
        let host = format!("{}:{}", g.host_for("shop.brand"), addr.port());
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(format!("GET /ws HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 256];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tokio::time::timeout(std::time::Duration::from_secs(5), c.read(&mut b)).await.expect("ответ шлюза").unwrap();
            assert!(n > 0, "закрыто до ответа: {}", String::from_utf8_lossy(&head));
            head.extend_from_slice(&b[..n]);
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
        c.write_all(b"ping").await.unwrap();
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), c.read(&mut b)).await.expect("эхо").unwrap();
        assert_eq!(&b[..n], b"ping");
    }

    #[tokio::test]
    async fn error_pages_are_html_for_navigation_and_text_for_fetch() {
        use rift_trust::{Announcement, Notice, Signed};
        let (g, addr, s) = running().await;
        let host = format!("{}:{}", g.host_for("shop.brand"), addr.port());
        s.resolver.handle(crate::names::Request::PutNotice(Announcement {
            notice: Signed::sign(Notice::Freeze { name: "shop.brand".into(), since: 0 }, &s.root),
            control: None,
        }));
        let nav = "Accept: text/html,application/xhtml+xml\r\n";

        let (head, body) = raw(addr, get(&host, "/", nav)).await;
        assert!(head.starts_with("HTTP/1.1 451") && head.to_lowercase().contains("text/html"), "{head}");
        assert!(body.contains("<h1>Сайт заморожен</h1>") && body.contains("shop.brand"), "{body}");
        assert!(!body.contains('\u{1F512}'), "эмодзи в оформлении");
        // fetch/XHR: без оформления.
        let (_, body) = raw(addr, get(&host, "/", "Accept: application/json\r\n")).await;
        assert!(body.starts_with("rift: ") && !body.contains("<h1>"), "{body}");

        // 502 и 403 тоже оформлены; техническая причина экранирована.
        let nope = format!("{}:{}", g.host_for("nope.brand"), addr.port());
        let (head, body) = raw(addr, get(&nope, "/", nav)).await;
        assert!(head.starts_with("HTTP/1.1 502") && body.contains("<h1>Сайт недоступен</h1>"), "{head}\n{body}");
        let (head, body) = raw(addr, get(&format!("127.0.0.1:{}", addr.port()), "/", nav)).await;
        assert!(head.starts_with("HTTP/1.1 403") && body.contains("Адрес не принадлежит"), "{head}\n{body}");
    }

    #[tokio::test]
    async fn builtin_pages_are_served_locally_and_only_read() {
        let (g, addr, s) = running().await;
        g.add_page("start.rift", "<h1>Старт</h1>".into());
        let host = format!("{}:{}", g.host_for("start.rift"), addr.port());
        let (head, body) = raw(addr, get(&host, "/", "")).await;
        assert!(head.starts_with("HTTP/1.1 200") && head.to_lowercase().contains("content-security-policy"), "{head}");
        assert_eq!(body, "<h1>Старт</h1>");
        let (head, _) = raw(addr, format!("POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")).await;
        assert!(head.starts_with("HTTP/1.1 405"), "{head}");
        // Встроенная страница — это приложение, а не сайт: клиенту в сеть за ней ходить не пришлось.
        assert_eq!(s.client.pooled(), 0);
        // Той же метки у обычного сайта нет: страница не «подменяет» чужие имена.
        let other = format!("{}:{}", g.host_for("shop.brand"), addr.port());
        let (_, body) = raw(addr, get(&other, "/headers", "")).await;
        assert!(!body.contains("Старт"), "{body}");
    }

    #[tokio::test]
    async fn frozen_site_is_451_and_unknown_site_is_502() {
        use rift_trust::{Announcement, Notice, Signed};
        let (g, addr, s) = running().await;
        let host = format!("{}:{}", g.host_for("shop.brand"), addr.port());
        s.resolver.handle(crate::names::Request::PutNotice(Announcement {
            notice: Signed::sign(Notice::Freeze { name: "shop.brand".into(), since: 0 }, &s.root),
            control: None,
        }));
        let (head, _) = raw(addr, get(&host, "/", "")).await;
        assert!(head.starts_with("HTTP/1.1 451"), "{head}");

        let nope = format!("{}:{}", g.host_for("nope.brand"), addr.port());
        let (head, _) = raw(addr, get(&nope, "/", "")).await;
        assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    }
}
