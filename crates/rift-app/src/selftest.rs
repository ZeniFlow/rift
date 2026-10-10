//! Самопроверка браузера: настоящий WebView открывает rift-сайт через шлюз и сеть Rift (в одном процессе).
//!
//! Сайт — маленькое приложение с cookie-сессией, редиректом, Service Worker и WebSocket. Страница сама проверяет,
//! что работает, и присылает отчёт на loopback-приёмник. Запуск: `cargo run -p rift-app -- selftest`.

use std::{convert::Infallible, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn, upgrade};
use hyper_util::rt::TokioIo;
use librift::{
    client::RiftClient,
    devnet::{bundle, node, trust},
    host::{HTTP_ALPN, Host},
    names::{NAMES_ALPN, NoticeCache, Request as NamesRequest, Resolver, publish},
};
use rift_trust::{Announcement, Notice, SecretKey, Signed};
use sha1::{Digest, Sha1};
use tauri::{Listener, Manager, WebviewUrl, WebviewWindowBuilder};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};

const PAGE: &str = include_str!("../ui/selftest.html");
type B = BoxBody<Bytes, Infallible>;

fn full(s: impl Into<Bytes>) -> B {
    Full::new(s.into()).boxed()
}

fn hv(r: &Request<Incoming>, n: &str) -> String {
    r.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

fn ws_accept(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// Эхо по WebSocket: браузер шлёт замаскированные кадры, отвечаем простым текстовым кадром.
async fn ws_echo<I: AsyncReadExt + AsyncWriteExt + Unpin>(mut io: I) {
    loop {
        let mut h = [0u8; 2];
        if io.read_exact(&mut h).await.is_err() || h[0] & 0x0f == 0x8 {
            return;
        }
        let len = (h[1] & 0x7f) as usize;
        if len >= 126 {
            return; // ponytail: для проверки хватает коротких кадров
        }
        let mut mask = [0u8; 4];
        let mut payload = vec![0u8; len];
        if io.read_exact(&mut mask).await.is_err() || io.read_exact(&mut payload).await.is_err() {
            return;
        }
        payload.iter_mut().enumerate().for_each(|(i, b)| *b ^= mask[i % 4]);
        let mut out = vec![0x81, len as u8];
        out.extend(payload);
        if io.write_all(&out).await.is_err() {
            return;
        }
    }
}

/// «Приложение сайта»: то, что обычно запускают на Node.js за `riftd host --upstream`.
async fn app() -> Result<String> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let addr = l.local_addr()?.to_string();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|mut r: Request<Incoming>| async move {
                    let mut resp = Response::new(full(""));
                    let path = r.uri().path().to_string();
                    match path.as_str() {
                        "/" => {
                            *resp.body_mut() = full(PAGE);
                            resp.headers_mut().insert("content-type", "text/html; charset=utf-8".parse().unwrap());
                            // Что обычно присылают настоящие приложения и что нельзя пропустить как есть.
                            resp.headers_mut().insert("content-security-policy", "upgrade-insecure-requests".parse().unwrap());
                            resp.headers_mut().insert("strict-transport-security", "max-age=31536000".parse().unwrap());
                        }
                        "/login" => {
                            *resp.status_mut() = StatusCode::NO_CONTENT;
                            resp.headers_mut().append("set-cookie", "sid=s3cr3t; Domain=shop.brand; Path=/; HttpOnly; SameSite=Lax".parse().unwrap());
                        }
                        "/whoami" => {
                            let body = serde_json::json!({
                                "cookie": hv(&r, "cookie"), "origin": hv(&r, "origin"), "host": hv(&r, "host"),
                                "xfh": hv(&r, "x-forwarded-host"), "xfp": hv(&r, "x-forwarded-proto"), "id": hv(&r, "rift-client-id"),
                            });
                            *resp.body_mut() = full(body.to_string());
                            resp.headers_mut().insert("content-type", "application/json".parse().unwrap());
                        }
                        "/redirect" => {
                            *resp.status_mut() = StatusCode::FOUND;
                            resp.headers_mut().insert("location", "https://shop.brand/landing".parse().unwrap());
                        }
                        "/landing" => *resp.body_mut() = full("landed"),
                        "/sw.js" => {
                            *resp.body_mut() = full("self.addEventListener('fetch', () => {});");
                            resp.headers_mut().insert("content-type", "text/javascript".parse().unwrap());
                        }
                        "/ws" if hv(&r, "upgrade").eq_ignore_ascii_case("websocket") => {
                            let accept = ws_accept(&hv(&r, "sec-websocket-key"));
                            let on = upgrade::on(&mut r);
                            tokio::spawn(async move {
                                if let Ok(up) = on.await {
                                    ws_echo(TokioIo::new(up)).await;
                                }
                            });
                            *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                            let h = resp.headers_mut();
                            h.insert("upgrade", "websocket".parse().unwrap());
                            h.insert("connection", "Upgrade".parse().unwrap());
                            h.insert("sec-websocket-accept", accept.parse().unwrap());
                        }
                        _ => *resp.status_mut() = StatusCode::NOT_FOUND,
                    }
                    Ok::<_, Infallible>(resp)
                });
                hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).with_upgrades().await.ok();
            });
        }
    });
    Ok(addr)
}

/// Приёмник отчёта: страница присылает его картинкой (запрос без CORS).
async fn sink(tx: mpsc::UnboundedSender<String>) -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let port = l.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = l.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                let n = tcp.read(&mut buf).await.unwrap_or(0);
                let line = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string();
                if let Some(d) = line.split("?d=").nth(1).and_then(|r| r.split(' ').next()) {
                    tx.send(percent_decode(d)).ok();
                }
                tcp.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await.ok();
            });
        }
    });
    Ok(port)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() + 1 && s.is_char_boundary(i + 1) && s.is_char_boundary((i + 3).min(s.len())) && i + 3 <= s.len() {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(b'?'));
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Сеть Rift в одном процессе: сайт за хостом, резолвер, клиент.
struct Net {
    client: Arc<RiftClient>,
    resolver: Resolver,
    root: SecretKey,
    sink_port: u16,
    _keep: (librift::Node, librift::Node, librift::Node),
}

async fn network(tx: mpsc::UnboundedSender<String>) -> Result<Net> {
    let k = SecretKey::generate;
    let (root, control, zone, owner) = (k(), k(), k(), k());
    let upstream = app().await?;
    let host = node(vec![(HTTP_ALPN.to_vec(), Box::new(Host::proxy(&upstream, false)?))]).await;
    let resolver = Resolver::new(trust(&root));
    let resolver_node = node(vec![(NAMES_ALPN.to_vec(), Box::new(resolver.clone()))]).await;
    let b = bundle(&root, &control, &zone, &owner, host.id(), 1);
    anyhow::ensure!(publish(host.endpoint(), &[resolver_node.endpoint().addr()], NamesRequest::PutBundle(b)).await == 1, "резолвер не принял цепочку");

    let me = node(vec![]).await;
    let client = Arc::new(RiftClient::new(me.endpoint().clone(), trust(&root), vec![resolver_node.endpoint().addr()], None, NoticeCache::memory()));
    client.add_hint(host.endpoint().addr());
    let sink_port = sink(tx).await?;
    Ok(Net { client, resolver, root, sink_port, _keep: (host, resolver_node, me) })
}

fn print_report(json: &str) {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(m)) => m.iter().for_each(|(k, v)| println!("  {k:15} {v}")),
        _ => println!("  {json}"),
    }
}

/// Окно без панели: WebView открывает сайт через шлюз и сообщает, что работает.
pub fn run() -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let net = tauri::async_runtime::block_on(network(tx))?;
    let core = tauri::async_runtime::block_on(crate::browser::serve_gateway(net.client.clone(), [9; 32]))?;
    let url = core.gateway.url_for("shop.brand", &format!("/?sink=http://127.0.0.1:{}", net.sink_port), core.port);
    println!("SELFTEST открываю rift://shop.brand/ через шлюз: {url}");
    tauri::Builder::default()
        .setup(move |app| {
            WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url.parse()?)).title("Rift selftest").inner_size(560.0, 360.0).build()?;
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let _net = net;
                match tokio::time::timeout(Duration::from_secs(40), rx.recv()).await {
                    Ok(Some(json)) => print_report(&json),
                    _ => println!("  нет отчёта от страницы за 40 с"),
                }
                handle.exit(0);
            });
            Ok(())
        })
        .run(crate::context())
        .context("tauri")?;
    Ok(())
}

// ---------------------------------------------------------------- проверка через панель

type States = mpsc::UnboundedReceiver<serde_json::Value>;

async fn wait_state(states: &mut States, what: &str, pred: impl Fn(&serde_json::Value) -> bool) -> Result<serde_json::Value> {
    let mut seen = vec![];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout_at(deadline, states.recv()).await {
            Ok(Some(s)) => {
                if pred(&s) {
                    return Ok(s);
                }
                seen.push(format!("{}|{}|{}|panel={}", s["what"].as_str().unwrap_or("?"), s["url"].as_str().unwrap_or(""), s["state"].as_str().unwrap_or(""), s["panel"]));
            }
            _ => anyhow::bail!("не дождались: {what}. Состояния панели: {seen:?}"),
        }
    }
}

fn url_is(s: &serde_json::Value, prefix: &str) -> bool {
    s["url"].as_str().is_some_and(|u| u.starts_with(prefix))
}

fn type_js(addr: &str) -> String {
    format!(
        "(()=>{{const u=document.getElementById('url');u.value={};document.getElementById('addr').requestSubmit();}})()",
        serde_json::to_string(addr).unwrap()
    )
}

async fn scenario(app: &tauri::AppHandle, states: &mut States, mut report: mpsc::UnboundedReceiver<String>, net: &Net, core: &crate::browser::Core) -> Result<()> {
    let ui = app.get_webview("ui").context("нет панели")?;
    let step = |s: &str| println!("  • {s}");
    let state = |s: &serde_json::Value| s["state"].as_str().unwrap_or("").to_string();

    let ready = wait_state(states, "панель загрузилась", |s| s["what"] == "ready").await?;
    step("панель загрузилась");

    // Раскладка: панель сверху, страница под ней. Ловит ошибки, которых события не видят (страница поверх панели).
    let layout = |what: &str| crate::browser::check_layout(app).map_err(|e| anyhow::anyhow!("раскладка ({what}): {e}"));
    tokio::time::sleep(Duration::from_millis(400)).await;
    println!("  окно: {}", crate::native::window_info(app).unwrap_or_default());
    layout("при запуске")?;
    // Рамка окна: на macOS родные кнопки лежат в левой части панели, по её высоте, и не налезают на кнопки навигации.
    let frame = ready["frame"].as_str().unwrap_or("");
    anyhow::ensure!(frame == crate::browser::FRAME, "панель знает рамку «{frame}», приложение — «{}»", crate::browser::FRAME);
    let back = ready["backLeft"].as_f64().unwrap_or(0.0);
    let lights = |what: &str| -> Result<()> {
        if frame != "mac" {
            return Ok(());
        }
        let (right, center) = crate::native::traffic_lights(app).context("не нашёл кнопки окна")?;
        anyhow::ensure!(back >= right + 6.0, "кнопки окна налезают на панель ({what}): правый край {right:.0}, «назад» с {back:.0}");
        anyhow::ensure!((center - crate::browser::TOOLBAR_H / 2.0).abs() <= 3.0, "кнопки окна не по центру панели ({what}): {center:.0} вместо {:.0}", crate::browser::TOOLBAR_H / 2.0);
        Ok(())
    };
    if frame == "mac" {
        lights("при запуске")?;
        let info = crate::native::window_info(app).unwrap_or_default();
        anyhow::ensure!(info.contains("fullSizeContentView=true") && info.contains("titlebarTransparent=true"), "заголовок окна не прозрачный: {info}");
    }
    step("рамка окна: кнопки на месте и не налезают на панель");
    let win = app.get_window("main").context("нет окна")?;
    // 1200x3000 заведомо больше экрана: macOS ужмёт окно сама, и дочерние виды сдвигаются системой, а не нами.
    for (w, h) in [(820.0, 560.0), (480.0, 700.0), (1200.0, 3000.0), (1280.0, 800.0)] {
        win.set_size(tauri::LogicalSize::new(w, h))?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        layout(&format!("после изменения размера до {w}x{h}"))?;
        lights(&format!("после изменения размера до {w}x{h}"))?;
    }
    step("раскладка верна при запуске и при изменении размера окна");

    // 1. Адрес со схемой rift:// → сайт открылся, адресная строка показывает rift://, состояние «проверен».
    ui.eval(type_js(&format!("rift://shop.brand/?sink=http://127.0.0.1:{}", net.sink_port)))?;
    wait_state(states, "rift://shop.brand/ открыт и проверен", |s| url_is(s, "rift://shop.brand/") && state(s) == "ok").await?;
    step("rift://shop.brand/ открыт, состояние «проверен»");
    let r = tokio::time::timeout(Duration::from_secs(40), report.recv()).await.context("страница не прислала отчёт")?.context("приёмник закрыт")?;
    print_report(&r);
    let r: serde_json::Value = serde_json::from_str(&r)?;
    anyhow::ensure!(r["secure"] == true && r["subtle"] == 32, "нет безопасного контекста: {r}");
    anyhow::ensure!(r["cookies"]["server_saw_cookie"].as_str().is_some_and(|c| c.contains("sid=s3cr3t") && c.contains("js=1")), "cookie не дошли: {r}");
    anyhow::ensure!(r["serviceWorker"] == "registered", "Service Worker: {r}");
    anyhow::ensure!(r["webSocket"].as_str().is_some_and(|w| w.starts_with("echo:")), "WebSocket: {r}");
    anyhow::ensure!(r["redirect"].as_str().is_some_and(|x| x.contains("redirected=true /landing")), "редирект: {r}");
    anyhow::ensure!(r["ipc"].as_str().is_some_and(|x| !x.contains("РАЗРЕШЕНО")), "страница сайта получила доступ к командам приложения: {r}");

    // 2. Панель сведений: раскрывается по значку, закрывается по Escape.
    ui.eval("document.getElementById('chip').click()")?;
    wait_state(states, "панель сведений раскрылась", |s| s["what"] == "panel" && s["panel"] == true).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    layout("при раскрытой панели сведений")?;
    ui.eval("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}))")?;
    wait_state(states, "панель сведений закрылась", |s| s["what"] == "panel" && s["panel"] == false).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    layout("после закрытия панели сведений")?;
    step("панель сведений раскрывается и закрывается по Escape");

    // 3. Без схемы: сначала Rift (P7).
    ui.eval(type_js("shop.brand/landing"))?;
    wait_state(states, "shop.brand/landing → rift://", |s| s["url"] == "rift://shop.brand/landing" && state(s) == "ok").await?;
    step("«shop.brand/landing» без схемы открылся как rift://shop.brand/landing");

    // 4. Назад / вперёд.
    ui.eval("document.getElementById('back').click()")?;
    wait_state(states, "назад", |s| url_is(s, "rift://shop.brand/?sink")).await?;
    ui.eval("document.getElementById('fwd').click()")?;
    wait_state(states, "вперёд", |s| s["url"] == "rift://shop.brand/landing").await?;
    step("назад и вперёд ведут по истории");

    // 5. Неизвестный сайт: страница ошибки, состояние «не проверен».
    ui.eval(type_js("rift://nope.brand/"))?;
    wait_state(states, "неизвестный сайт", |s| url_is(s, "rift://nope.brand") && state(s) == "unverified").await?;
    step("неизвестный сайт: «не проверен»");

    // 6. Непонятный адрес: ошибка в панели, страница не меняется.
    ui.eval(type_js("???"))?;
    wait_state(states, "ошибка адреса", |s| state(s) == "error" && s["panel"] == true).await?;
    step("непонятный адрес: ошибка с объяснением");

    // 7. Заморозка: клиент узнаёт об объявлении и сразу отказывает, не дожидаясь конца кэша имён.
    net.resolver.handle(NamesRequest::PutNotice(Announcement {
        notice: Signed::sign(Notice::Freeze { name: "shop.brand".into(), since: 0 }, &net.root),
        control: None,
    }));
    anyhow::ensure!(core.client.sync_notices().await == 1, "клиент не получил объявление");
    ui.eval(type_js("rift://shop.brand/x"))?;
    wait_state(states, "заморозка", |s| url_is(s, "rift://shop.brand/x") && state(s) == "blocked").await?;
    step("после заморозки: «заморожен»");
    Ok(())
}

/// То же через панель браузера: ввод адреса, история, статус, заморозка. Печатает `SELFTEST-UI OK` или причину.
pub fn run_ui() -> Result<()> {
    let (tx, rx) = mpsc::unbounded_channel::<String>();
    let net = tauri::async_runtime::block_on(network(tx))?;
    let core = tauri::async_runtime::block_on(crate::browser::serve_gateway(net.client.clone(), [9; 32]))?;
    static FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    println!("SELFTEST-UI");
    let c = core.clone();
    crate::browser::launch(core, None, move |app| {
        let (states_tx, mut states) = mpsc::unbounded_channel::<serde_json::Value>();
        app.listen_any("ui-state", move |e| {
            if let Ok(v) = serde_json::from_str(e.payload()) {
                states_tx.send(v).ok();
            }
        });
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            match scenario(&app, &mut states, rx, &net, &c).await {
                Ok(()) => println!("SELFTEST-UI OK"),
                Err(e) => {
                    FAILED.store(true, std::sync::atomic::Ordering::SeqCst);
                    println!("SELFTEST-UI FAIL: {e:#}");
                }
            }
            app.exit(0);
        });
    })?;
    anyhow::ensure!(!FAILED.load(std::sync::atomic::Ordering::SeqCst), "самопроверка не прошла");
    Ok(())
}

/// Демо: сеть Rift и сайт в одном процессе, окно браузера остаётся открытым.
pub fn run_demo() -> Result<()> {
    let (tx, _rx) = mpsc::unbounded_channel::<String>();
    let net = tauri::async_runtime::block_on(network(tx))?;
    let core = tauri::async_runtime::block_on(crate::browser::serve_gateway(net.client.clone(), [9; 32]))?;
    println!("DEMO открыто rift://shop.brand/ (Ctrl-C — выход)");
    crate::browser::launch(core, Some("rift://shop.brand/".into()), move |_| {
        std::mem::forget(net); // сеть должна жить, пока открыто окно
    })
}

/// Служебная команда: записывает страницы приложения в папку, чтобы посмотреть их глазами (`rift-app pages <папка>`).
pub fn dump_pages(dir: &str) -> Result<()> {
    use librift::pages::{Kind, error_page};
    std::fs::create_dir_all(dir)?;
    let pages = [
        ("error-451.html", error_page(451, Kind::Blocked, "Сайт заморожен", "Доступ к shop.brand закрыт решением оператора сети. Решение подписано и публично, поэтому действует на всех устройствах.", "shop.brand: shop.brand заморожен оператором сети", "Заморозка снимается отдельным публичным объявлением. Если вы владелец домена, свяжитесь с оператором сети.")),
        ("error-502.html", error_page(502, Kind::Unreachable, "Сайт недоступен", "Не удалось открыть nope.brand. Имя не найдено у резолверов, либо хост сайта сейчас не отвечает.", "nope.brand: не найдено (резолверы не знают имени)", "Проверьте адрес. Если сайт должен работать, попробуйте позже: хост мог выключиться.")),
        ("error-403.html", error_page(403, Kind::Forbidden, "Адрес не принадлежит этому устройству", "Этот адрес шлюза создан другой установкой Rift или подделан. Откройте сайт через адресную строку приложения.", "", "")),
    ];
    for (name, html) in pages {
        std::fs::write(format!("{dir}/{name}"), html)?;
    }
    println!("записано в {dir}");
    Ok(())
}
