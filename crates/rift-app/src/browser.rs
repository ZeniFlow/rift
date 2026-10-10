//! Окно браузера: две WebView в одном окне.
//!
//! * `ui` — панель (адрес, назад/вперёд, статус). Только она получает доступ к командам приложения.
//! * `content` — страница сайта. Это чужой код: IPC к приложению у него нет (см. capabilities/default.json).
//!
//! Rift-сайты открываются через шлюз (`http://имя.метка.localhost:порт`, см. librift::gateway), а в адресной строке
//! всегда показываются как `rift://имя.зона/путь`.

use std::{
    path::Path,
    sync::{Arc, atomic::{AtomicU32, Ordering}},
};

use anyhow::{Context, Result, bail};
use librift::{
    Node, RelayUrl,
    client::{RiftClient, rift_name},
    gateway::Gateway,
    names::{Blocked, NoticeCache},
    pages::{self, icon},
    parse_peer,
};
use rift_trust::{PublicKey, Trust};
use serde::Deserialize;
use tauri::{
    AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, Rect, State, Url, WebviewUrl, WindowEvent,
    webview::{PageLoadEvent, WebviewBuilder},
    window::WindowBuilder,
};

pub const TOOLBAR_H: f64 = 44.0;
/// Левый край кнопок окна macOS внутри панели (панель оставляет под них место).
pub const TRAFFIC_X: f64 = 16.0;

/// Какая рамка окна: `mac` — родные кнопки поверх прозрачного заголовка, `custom` — свои кнопки (Windows), `native` — системная рамка.
/// Linux остаётся на системной: у безрамочного окна GTK нет границ для изменения размера, а Tauri их там не добавляет.
pub const FRAME: &str = if cfg!(target_os = "macos") { "mac" } else if cfg!(windows) { "custom" } else { "native" };
/// Порт шлюза по умолчанию. Он часть origin сайта в WebView (localStorage, IndexedDB), поэтому держим его постоянным.
pub const DEFAULT_PORT: u16 = 47878;

/// Что известно приложению о сети: `<каталог данных>/config.json`.
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub root: PublicKey,
    #[serde(default)]
    pub witnesses: Vec<PublicKey>,
    #[serde(default = "one")]
    pub threshold: usize,
    /// `NodeID` или `NodeID@relay-url`.
    pub resolvers: Vec<String>,
    #[serde(default)]
    pub relay: Option<String>,
}

fn one() -> usize {
    1
}

/// Встроенные страницы: живут в приложении, в сеть за ними не ходим.
const BUILTIN: [&str; 1] = ["start.rift"];

pub struct Core {
    pub client: Arc<RiftClient>,
    pub gateway: Arc<Gateway>,
    pub port: u16,
    /// Высота, которую панель сведений добавляет к строке адреса (логические px). Страница сайта сдвигается вниз.
    chrome: AtomicU32,
}

/// Куда вести: что показать в адресной строке и что загрузить в WebView.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub shown: String,
    pub load: String,
    pub rift: bool,
}

/// Имя Rift из того, что набрано как хост (с `.rift` или без).
fn name_of(host: &str) -> Option<String> {
    rift_name(host).or_else(|| rift_trust::split_name(&host.to_ascii_lowercase()).map(|_| host.to_ascii_lowercase()))
}

fn split_host(rest: &str) -> (&str, &str) {
    match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    }
}

fn norm_path(p: &str) -> String {
    if p.is_empty() { "/".into() } else if p.starts_with('/') { p.into() } else { format!("/{p}") }
}

impl Core {
    /// Разбор набранного. `rift://…` — только Rift. `http(s)://…` — обычный веб. Без схемы — сначала Rift (P7),
    /// а если такого имени нет в сети — обычный адрес.
    pub async fn target(&self, input: &str) -> Result<Target> {
        let input = input.trim();
        if let Some(rest) = input.strip_prefix("rift://") {
            let (host, path) = split_host(rest);
            let name = name_of(host).with_context(|| format!("«{host}» — не имя Rift (ожидалось имя.зона)"))?;
            return Ok(self.rift_target(&name, &norm_path(path)));
        }
        if input.starts_with("http://") || input.starts_with("https://") {
            return Ok(Target { shown: input.into(), load: input.into(), rift: false });
        }
        let (host, path) = split_host(input);
        if let Some(name) = name_of(host) {
            match self.client.resolve(&name).await {
                Ok(_) => return Ok(self.rift_target(&name, &norm_path(path))),
                Err(e) if e.downcast_ref::<Blocked>().is_some() => return Ok(self.rift_target(&name, &norm_path(path))),
                Err(_) => {} // в сети Rift такого нет — обычный DNS
            }
        }
        if host.contains('.') || host.contains(':') {
            let url = format!("https://{input}");
            return Ok(Target { shown: url.clone(), load: url, rift: false });
        }
        bail!("не понял адрес «{input}»: нужен адрес вида имя.зона или https://…")
    }

    fn rift_target(&self, name: &str, path: &str) -> Target {
        Target { shown: format!("rift://{name}{path}"), load: self.gateway.url_for(name, path, self.port), rift: true }
    }

    /// Адрес стартовой страницы на шлюзе.
    pub fn start_url(&self) -> String {
        self.gateway.url_for("start.rift", "/", self.port)
    }

    /// Адрес из WebView → то, что показать пользователю. Шлюз скрывается за `rift://`;
    /// у встроенных страниц адреса нет (строка пустая, видна подсказка).
    pub fn shown(&self, url: &Url) -> (String, Option<String>) {
        if let Some(name) = url.host_str().and_then(|h| self.gateway.name_from_host(h)) {
            if BUILTIN.contains(&name.as_str()) {
                return (String::new(), Some(name));
            }
            let mut path = url.path().to_string();
            if let Some(q) = url.query() {
                path = format!("{path}?{q}");
            }
            return (format!("rift://{name}{path}"), Some(name));
        }
        (url.to_string(), None)
    }
}

// ---------------------------------------------------------------- команды панели

/// Открывает набранное в `content`. Возвращает адрес, который нужно показать.
async fn go(app: &AppHandle, core: &Arc<Core>, input: &str) -> Result<String, String> {
    let t = core.target(input).await.map_err(|e| format!("{e:#}"))?;
    let content = app.get_webview("content").ok_or("нет окна страницы")?;
    content.navigate(t.load.parse().map_err(|e| format!("{e}"))?).map_err(|e| e.to_string())?;
    Ok(t.shown)
}

#[tauri::command]
async fn navigate(input: String, core: State<'_, Arc<Core>>, app: AppHandle) -> Result<String, String> {
    go(&app, &core, &input).await
}

#[tauri::command]
fn history(delta: i32, app: AppHandle) {
    if let Some(w) = app.get_webview("content") {
        w.eval(format!("history.go({delta})")).ok();
    }
}

#[tauri::command]
fn reload(app: AppHandle) {
    if let Some(w) = app.get_webview("content") {
        w.eval("location.reload()").ok();
    }
}

/// Панель сведений о сайте раздвигает окно: страница сайта — отдельный WebView и под нашу вёрстку не заходит.
#[tauri::command]
fn set_panel(height: f64, core: State<'_, Arc<Core>>, app: AppHandle) {
    core.chrome.store(height.clamp(0.0, 420.0) as u32, Ordering::Relaxed);
    layout(&app);
}

// ---------------------------------------------------------------- окно

/// Сообщает панели новый адрес и результат проверки сайта.
fn announce(app: &AppHandle, core: &Arc<Core>, url: &Url) {
    let (shown, name) = core.shown(url);
    app.emit_to("ui", "location", shown).ok();
    let (app, core, web) = (app.clone(), core.clone(), matches!(url.scheme(), "http" | "https") && name.is_none());
    tauri::async_runtime::spawn(async move {
        let status = match name {
            Some(n) if BUILTIN.contains(&n.as_str()) => serde_json::json!({ "rift": false }),
            None => serde_json::json!({ "rift": false, "web": web }),
            Some(name) => match core.client.resolve(&name).await {
                Ok(r) => {
                    let t = core.client.trust();
                    serde_json::json!({
                        "ok": true, "rift": true, "name": name, "owner": r.owner.to_string(), "hosts": r.hosts.len(), "seq": r.seq,
                        "root": t.root.to_string(), "quorum": format!("{} из {}", t.threshold, t.witnesses.len()),
                    })
                }
                Err(e) => {
                    let blocked = e.downcast_ref::<Blocked>().is_some();
                    serde_json::json!({ "ok": false, "rift": true, "blocked": blocked, "name": name, "error": format!("{e:#}") })
                }
            },
        };
        app.emit_to("ui", "status", status).ok();
    });
}

/// Раскладка двух WebView в окне. Границы задаются разом (`set_bounds`): на macOS пересчёт координат зависит от
/// текущей высоты вида. Сверху оставляем место под заголовок окна: при `fullSizeContentView` содержимое заходит под него
/// и панель иначе оказывается наполовину спрятанной, а страница поверх неё.
fn layout(app: &AppHandle) {
    let Some(w) = app.get_window("main") else { return };
    let (Ok(size), Ok(scale)) = (w.inner_size(), w.scale_factor()) else { return };
    let s = size.to_logical::<f64>(scale);
    let top = TOOLBAR_H + app.try_state::<Arc<Core>>().map_or(0.0, |c| f64::from(c.chrome.load(Ordering::Relaxed)));
    let rect = |y: f64, h: f64| Rect { position: LogicalPosition::new(0.0, y).into(), size: LogicalSize::new(s.width, h.max(1.0)).into() };
    if let Some(ui) = app.get_webview("ui") {
        ui.set_bounds(rect(0.0, top)).ok();
    }
    if let Some(c) = app.get_webview("content") {
        c.set_bounds(rect(top, s.height - top)).ok();
    }
    crate::native::place_traffic_lights(app, TRAFFIC_X, TOOLBAR_H);
}

/// Проверка раскладки по настоящим границам WebView: панель сверху, страница сразу под ней, обе на всю ширину окна.
/// Возвращает описание нарушения.
pub fn check_layout(app: &AppHandle) -> Result<(), String> {
    let w = app.get_window("main").ok_or("нет окна")?;
    let (inner, scale) = (w.inner_size().map_err(|e| e.to_string())?, w.scale_factor().map_err(|e| e.to_string())?);
    let (ui, c) = (app.get_webview("ui").ok_or("нет панели")?, app.get_webview("content").ok_or("нет страницы")?);
    let (up, us, cp, cs) = (ui.position().map_err(|e| e.to_string())?, ui.size().map_err(|e| e.to_string())?, c.position().map_err(|e| e.to_string())?, c.size().map_err(|e| e.to_string())?);
    let chrome = app.try_state::<Arc<Core>>().map_or(0.0, |c| f64::from(c.chrome.load(Ordering::Relaxed)));
    let want_ui = ((TOOLBAR_H + chrome) * scale).round() as i64;
    let near = |a: i64, b: i64| (a - b).abs() <= 2;
    let desc = format!("окно {}x{}, панель {:?} {}x{}, страница {:?} {}x{}, ждали высоту панели {want_ui}", inner.width, inner.height, (up.x, up.y), us.width, us.height, (cp.x, cp.y), cs.width, cs.height);
    let ok = near(up.x.into(), 0) && near(up.y.into(), 0) && near(us.width.into(), inner.width.into()) && near(us.height.into(), want_ui)
        && near(cp.x.into(), 0) && near(cp.y.into(), us.height.into()) && near(cs.width.into(), inner.width.into())
        && near(i64::from(cs.height), i64::from(inner.height) - i64::from(us.height));
    if !ok {
        return Err(desc);
    }
    // То же по настоящим рамкам нативных видов: Tauri-обёртка считает границы через ту же формулу, что и задаёт их,
    // поэтому перекрытие панели и страницы на экране она не видит.
    if let (Some(u), Some(c)) = (crate::native::frame(app, "ui"), crate::native::frame(app, "content")) {
        let (ut, ub) = u.top_bottom();
        let (ct, cb) = c.top_bottom();
        let want = TOOLBAR_H + chrome;
        let near = |a: f64, b: f64| (a - b).abs() <= 1.5;
        if !(near(ut, 0.0) && near(ub, want) && near(ct, ub) && near(cb, c.parent_h) && near(u.parent_h, c.parent_h)) {
            return Err(format!("нативные рамки: панель сверху {ut:.0} снизу {ub:.0} (ждали {:.0}), страница сверху {ct:.0} снизу {cb:.0}, высота окна {:.0}", want, c.parent_h));
        }
    }
    Ok(())
}

/// Стартовая страница: что это за приложение, как открыть сайт, сведения об узле.
pub fn start_page(core: &Core) -> String {
    let short = |h: String| if h.len() > 14 { format!("{}…{}", &h[..8], &h[h.len() - 4..]) } else { h };
    let t = core.client.trust();
    let row = |ico: &str, k: &str, v: String| format!("<dt>{ico}{k}</dt><dd>{}</dd>", pages::esc(&v));
    let node = [
        row(icon::KEY, "Корневой ключ", short(t.root.to_string())),
        row(icon::SHIELD_CHECK, "Свидетели", format!("{} из {}", t.threshold, t.witnesses.len())),
        row(icon::SERVER, "Резолверы", core.client.resolver_count().to_string()),
        row(icon::WAYPOINTS, "Шлюз", format!("127.0.0.1:{}", core.port)),
        row(icon::GLOBE, "Этот узел", short(core.client.node_id().to_string())),
    ]
    .concat();
    pages::shell(
        "Rift",
        &format!(
            r#"<main class="page"><div class="mark">{}</div><h1>Rift</h1>
<p class="lead">Открывайте сайты по имени вида <code>имя.зона</code>. Подлинность адреса проверяется подписями, а не доверием к посреднику.</p>
<div class="grid">
<section aria-labelledby="h-open"><h2 id="h-open">Как открыть сайт</h2><div class="card"><ul class="plain">
<li><span>Введите адрес в строке сверху</span><code>имя.зона</code></li>
<li><span>Адрес в обычном интернете</span><code>https://…</code></li>
<li><span>Перейти к адресной строке</span><span><span class="kbd">Cmd</span> <span class="kbd">L</span></span></li>
</ul></div></section>
<section aria-labelledby="h-node"><h2 id="h-node">Этот узел</h2><div class="card"><dl>{node}</dl></div></section>
</div></main>"#,
            icon::WAYPOINTS
        ),
    )
}

/// Открывает окно. `start` — первая страница (адрес как его набрал бы пользователь); без него — стартовая.
pub fn launch(core: Arc<Core>, start: Option<String>, setup: impl FnOnce(&AppHandle) + Send + 'static) -> Result<()> {
    core.gateway.add_page("start.rift", start_page(&core));
    let first = match &start {
        Some(s) => tauri::async_runtime::block_on(core.target(s))?.load,
        None => core.start_url(),
    };
    tauri::Builder::default()
        .manage(core.clone())
        .invoke_handler(tauri::generate_handler![navigate, history, reload, set_panel])
        .setup(move |app| {
            let builder = WindowBuilder::new(app, "main").title("Rift").inner_size(1100.0, 760.0).min_inner_size(320.0, 240.0);
            // Рамка как у Chrome: панель занимает место заголовка. macOS: родные кнопки поверх прозрачного заголовка.
            #[cfg(target_os = "macos")]
            let builder = builder.title_bar_style(tauri::TitleBarStyle::Overlay).hidden_title(true);
            // Windows: без системной рамки, кнопки окна рисует панель; границы и тень окна обрабатывает сам Tauri.
            #[cfg(windows)]
            let builder = builder.decorations(false).shadow(true);
            let window = builder.build()?;
            let s = window.inner_size()?.to_logical::<f64>(window.scale_factor()?);
            window.add_child(
                WebviewBuilder::new("ui", WebviewUrl::App("index.html".into())).initialization_script(format!("window.__RIFT_FRAME__ = '{FRAME}';")),
                LogicalPosition::new(0.0, 0.0),
                LogicalSize::new(s.width, TOOLBAR_H),
            )?;
            let (handle, nav_core) = (app.handle().clone(), core.clone());
            let (link_handle, link_core) = (app.handle().clone(), core.clone());
            window.add_child(
                WebviewBuilder::new("content", WebviewUrl::External(first.parse()?))
                    // Ссылки `rift://…` внутри страниц открываем сами: WebView такой схемы не знает.
                    .on_navigation(move |url| {
                        if url.scheme() == "rift" {
                            let (app, core, input) = (link_handle.clone(), link_core.clone(), url.as_str().to_string());
                            tauri::async_runtime::spawn(async move {
                                go(&app, &core, &input).await.ok();
                            });
                            return false;
                        }
                        true
                    })
                    // `on_page_load`, а не `on_navigation`, для адреса: он срабатывает и при переходе назад/вперёд.
                    .on_page_load(move |_, payload| match payload.event() {
                        PageLoadEvent::Started => {
                            handle.emit_to("ui", "loading", true).ok();
                            announce(&handle, &nav_core, payload.url());
                        }
                        PageLoadEvent::Finished => {
                            handle.emit_to("ui", "loading", false).ok();
                        }
                    }),
                LogicalPosition::new(0.0, TOOLBAR_H),
                LogicalSize::new(s.width, (s.height - TOOLBAR_H).max(1.0)),
            )?;
            layout(app.handle()); // заголовок окна мог занять верх: выкладываем с учётом отступа
            let h = app.handle().clone();
            window.on_window_event(move |e| {
                if matches!(e, WindowEvent::Resized(_) | WindowEvent::ScaleFactorChanged { .. }) {
                    layout(&h);
                }
            });
            setup(app.handle());
            Ok(())
        })
        .run(crate::context())
        .context("tauri")?;
    Ok(())
}

// ---------------------------------------------------------------- запуск с настоящей сетью

/// Поднимает ноду, клиента и шлюз по `config.json` из каталога данных.
pub fn boot(dir: &Path) -> Result<(Arc<Core>, Node)> {
    let cfg: AppConfig = serde_json::from_slice(
        &std::fs::read(dir.join("config.json")).with_context(|| format!("нет {}: см. docs/browser.md", dir.join("config.json").display()))?,
    )
    .context("config.json")?;
    anyhow::ensure!(cfg.threshold <= cfg.witnesses.len(), "threshold {} больше числа свидетелей {}", cfg.threshold, cfg.witnesses.len());
    std::fs::create_dir_all(dir)?;
    tauri::async_runtime::block_on(async {
        let key = librift::load_or_create_key(&dir.join("key"))?;
        let relay: Option<RelayUrl> = cfg.relay.as_deref().map(str::parse).transpose().context("relay")?;
        let node = Node::bind(librift::Config {
            key,
            relay_mode: librift::Config::relay_mode(relay.clone().into_iter().collect()),
            lan: true,
            proxy: None,
            bridge: None,
            relay_ca: None,
            vpn: None,
            extra: vec![],
        })
        .await?;
        let resolvers = cfg.resolvers.iter().map(|r| parse_peer(r, relay.clone())).collect::<Result<Vec<_>>>()?;
        let cache = NoticeCache::load(dir.join("notices.json"), &cfg.root)?;
        let trust = Trust { root: cfg.root, witnesses: cfg.witnesses, threshold: cfg.threshold };
        let client = Arc::new(RiftClient::new(node.endpoint().clone(), trust, resolvers, relay, cache));
        let core = serve_gateway(client, secret(&dir.join("gateway-secret"))?).await?;
        Ok((core, node))
    })
}

/// Секрет установки: от него зависят адреса сайтов, поэтому он хранится и переживает перезапуск.
fn secret(path: &Path) -> Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(b) => b.try_into().map_err(|_| anyhow::anyhow!("{}: ожидалось 32 байта", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let s = rift_trust::SecretKey::generate().to_bytes();
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            std::io::Write::write_all(&mut opts.open(path)?, &s)?;
            Ok(s)
        }
        Err(e) => Err(e).with_context(|| format!("не удалось прочитать {}", path.display())),
    }
}

pub async fn serve_gateway(client: Arc<RiftClient>, secret: [u8; 32]) -> Result<Arc<Core>> {
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", DEFAULT_PORT)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("порт {DEFAULT_PORT} занят ({e}): беру случайный, локальные данные сайтов не сохранятся между запусками");
            tokio::net::TcpListener::bind("127.0.0.1:0").await?
        }
    };
    let port = listener.local_addr()?.port();
    // Заморозки и отзывы должны доходить до клиента сами, не дожидаясь, пока он откроет сайт.
    let syncer = client.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            syncer.sync_notices().await;
        }
    });
    let gateway = Arc::new(Gateway::new(client.clone(), secret));
    tokio::spawn(gateway.clone().serve(listener));
    Ok(Arc::new(Core { client, gateway, port, chrome: AtomicU32::new(0) }))
}
