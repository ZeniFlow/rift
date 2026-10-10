//! Окно браузера: несколько WebView в одном окне.
//!
//! * `ui` — панель (вкладки, адрес, назад/вперёд, статус). Получает доступ к командам приложения.
//! * `tab-<id>` — страница сайта, по WebView на вкладку, виден один. Это чужой код: IPC к приложению у него нет (см. capabilities/default.json).
//! * `overlay` — прозрачный слой поверх всего: меню, окна, уведомления.
//!
//! Rift-сайты открываются через шлюз (`http://имя.метка.localhost:порт`, см. librift::gateway), а в адресной строке
//! всегда показываются как `rift://имя.зона/путь`.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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

use crate::{settings::Settings, store::Store};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tauri::{
    AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, Rect, State, Url, WebviewUrl, WindowEvent,
    webview::{NewWindowResponse, PageLoadEvent, WebviewBuilder},
    window::WindowBuilder,
};

/// Строка вкладок (в ней же кнопки окна) и строка с адресом: панель `ui` занимает обе.
use tauri::window::Color;
const BLACK: Color = Color(0, 0, 0, 255);
const WHITE: Color = Color(255, 255, 255, 255);

pub const TAB_H: f64 = 36.0;
pub const TOOLBAR_H: f64 = 42.0;
pub const CHROME_H: f64 = TAB_H + TOOLBAR_H;
/// Левый край кнопок окна macOS внутри строки вкладок (панель оставляет под них место).
pub const TRAFFIC_X: f64 = 16.0;
/// Отступ плашки уведомлений от правого края окна.
pub const OVERLAY_MARGIN: f64 = 12.0;

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
/// Внутренние страницы `browser://…`: файлы приложения (`ui/<имя>.html`). Зона `browser` не принадлежит сети Rift.
const INTERNAL: [&str; 5] = ["settings", "newtab", "history", "bookmarks", "wallet"];

/// Страница приложения (`tauri://localhost/…`, на Windows `http://tauri.localhost/…`) → её имя для `browser://`.
fn internal_page(url: &Url) -> Option<&'static str> {
    let local = (url.scheme() == "tauri" && url.host_str() == Some("localhost")) || (url.scheme() == "http" && url.host_str() == Some("tauri.localhost"));
    let stem = url.path().strip_prefix('/')?.strip_suffix(".html")?;
    local.then(|| INTERNAL.iter().copied().find(|p| *p == stem)).flatten()
}

/// Адрес файла страницы приложения: тот же источник, что у панели.
fn internal_url(app: &AppHandle, page: &str) -> Result<Url, String> {
    let base = app.get_webview("ui").ok_or("нет панели")?.url().map_err(|e| e.to_string())?;
    base.join(&format!("{page}.html")).map_err(|e| e.to_string())
}

pub struct Core {
    pub client: Arc<RiftClient>,
    pub gateway: Arc<Gateway>,
    pub port: u16,
    /// Настройки и файл, куда их сохраняем (`None` — только в памяти: самопроверки).
    settings: Mutex<Settings>,
    settings_path: Option<PathBuf>,
    /// Диалоги слоя, ждущие ответа: id → получатель.
    asks: Mutex<HashMap<u64, oneshot::Sender<Value>>>,
    /// Режим слоя `overlay` сейчас (`None` — скрыт).
    overlay: Mutex<Option<OverlayMode>>,
    tabs: Mutex<Tabs>,
    store: Mutex<Store>,
    pub wallet: crate::wallet::WalletState,
}

/// Где стоит слой: на всё окно, плашка справа под панелью (уведомления) или плашка в заданном месте (подсказки адреса).
/// Вне плашки слой клики не перехватывает: его WebView просто меньше.
#[derive(Debug, Clone, Copy)]
enum OverlayMode {
    Full,
    Right(f64, f64),
    At(f64, f64, f64, f64),
}

/// Вкладка = отдельный WebView `tab-<id>`; виден только активный.
#[derive(Debug, Clone)]
pub struct Tab {
    pub id: u32,
    pub title: String,
    /// Адрес для пользователя (`rift://…`, `https://…`, `browser://…`; у стартовой и новой вкладки пусто).
    pub shown: String,
    pub loading: bool,
    pub status: Value,
}

#[derive(Debug, Default)]
pub struct Tabs {
    list: Vec<Tab>,
    active: u32,
    next: u32,
}

fn label(id: u32) -> String {
    format!("tab-{id}")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
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
        if let Some(page) = input.strip_prefix("browser://") {
            let page = page.trim_end_matches('/');
            anyhow::ensure!(INTERNAL.contains(&page), "нет страницы browser://{page}");
            return Ok(Target { shown: input.trim_end_matches('/').into(), load: input.trim_end_matches('/').into(), rift: false });
        }
        if let Some(rest) = input.strip_prefix("rift://") {
            let (host, path) = split_host(rest);
            let name = name_of(host).with_context(|| format!("«{host}» — не имя Rift (ожидалось имя.зона)"))?;
            return Ok(self.rift_target(&name, &norm_path(path)));
        }
        if input.starts_with("http://") || input.starts_with("https://") {
            return Ok(Target { shown: input.into(), load: input.into(), rift: false });
        }
        let (host, path) = split_host(input);
        if let Some(name) = name_of(host).filter(|_| self.settings().rift_first) {
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
    pub fn new(client: Arc<RiftClient>, gateway: Arc<Gateway>, port: u16, dir: Option<&Path>) -> Result<Self> {
        let settings_path = dir.map(|d| d.join("settings.json"));
        let settings = match &settings_path {
            Some(p) => Settings::load(p).unwrap_or_else(|e| {
                eprintln!("настройки не прочитаны, беру стандартные: {e:#}");
                Settings::default()
            }),
            None => Settings::default(),
        };
        Ok(Self { client, gateway, port, settings: Mutex::new(settings), settings_path, asks: Mutex::default(), overlay: Mutex::new(None), tabs: Mutex::default(), store: Mutex::new(Store::load(dir)), wallet: crate::wallet::WalletState::new(dir) })
    }

    pub fn active_label(&self) -> Option<String> {
        let t = self.tabs.lock().unwrap();
        t.list.iter().any(|x| x.id == t.active).then(|| label(t.active))
    }

    pub fn tab_labels(&self) -> Vec<String> {
        self.tabs.lock().unwrap().list.iter().map(|t| label(t.id)).collect()
    }

    pub fn active_tab(&self) -> Option<Tab> {
        let t = self.tabs.lock().unwrap();
        t.list.iter().find(|x| x.id == t.active).cloned()
    }

    pub fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap()
    }

    pub fn tab_count(&self) -> usize {
        self.tabs.lock().unwrap().list.len()
    }

    pub fn settings_file(&self) -> Option<&Path> {
        self.settings_path.as_deref()
    }

    pub fn settings(&self) -> Settings {
        self.settings.lock().unwrap().clone()
    }

    /// Применяет изменение, сохраняет на диск. Возвращает новые настройки.
    pub fn update(&self, f: impl FnOnce(&mut Settings) -> Result<(), String>) -> Result<Settings, String> {
        let mut g = self.settings.lock().unwrap();
        let mut next = g.clone();
        f(&mut next)?;
        if let Some(p) = &self.settings_path {
            next.save(p).map_err(|e| format!("{e:#}"))?;
        }
        *g = next.clone();
        Ok(next)
    }

    pub fn start_url(&self) -> String {
        self.gateway.url_for("start.rift", "/", self.port)
    }

    /// Адрес из WebView → то, что показать пользователю. Шлюз скрывается за `rift://`;
    /// у встроенных страниц адреса нет (строка пустая, видна подсказка).
    pub fn shown(&self, url: &Url) -> (String, Option<String>) {
        if let Some(page) = internal_page(url) {
            // Новая вкладка без адреса: строка пустая, видна подсказка.
            return (if page == "newtab" { String::new() } else { format!("browser://{page}") }, None);
        }
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

/// Разбор набранного в адрес для WebView.
fn load_url(app: &AppHandle, t: &Target) -> Result<Url, String> {
    match t.load.strip_prefix("browser://") {
        Some(page) => internal_url(app, page),
        None => t.load.parse().map_err(|e| format!("{e}")),
    }
}

/// Открывает набранное во вкладке `tab` (`None` — в активной). Возвращает адрес, который нужно показать.
async fn go(app: &AppHandle, core: &Arc<Core>, tab: Option<u32>, input: &str) -> Result<String, String> {
    let t = core.target(input).await.map_err(|e| format!("{e:#}"))?;
    let id = tab.or_else(|| core.active_tab().map(|t| t.id)).ok_or("нет вкладки")?;
    let wv = app.get_webview(&label(id)).ok_or("вкладка закрыта")?;
    wv.navigate(load_url(app, &t)?).map_err(|e| e.to_string())?;
    Ok(t.shown)
}

fn active_webview(app: &AppHandle) -> Option<tauri::Webview> {
    app.try_state::<Arc<Core>>()?.active_label().and_then(|l| app.get_webview(&l))
}

#[tauri::command]
async fn navigate(input: String, core: State<'_, Arc<Core>>, app: AppHandle) -> Result<String, String> {
    go(&app, &core, None, &input).await
}

#[tauri::command]
fn history(delta: i32, app: AppHandle) {
    if let Some(w) = active_webview(&app) {
        w.eval(format!("history.go({delta})")).ok();
    }
}

#[tauri::command]
fn reload(app: AppHandle) {
    if let Some(w) = active_webview(&app) {
        w.eval("location.reload()").ok();
    }
}

// ---- вкладки

fn emit_tabs(app: &AppHandle, core: &Core) {
    let t = core.tabs.lock().unwrap();
    let list: Vec<Value> = t.list.iter().map(|x| json!({ "id": x.id, "title": x.title, "shown": x.shown, "loading": x.loading })).collect();
    app.emit_to("ui", "tabs", json!({ "tabs": list, "active": t.active })).ok();
}

/// Повторяет панели то, что известно об активной вкладке: адрес, проверку сайта, загрузку.
fn emit_active(app: &AppHandle, core: &Core) {
    let Some(a) = core.active_tab() else { return };
    app.emit_to("ui", "location", &a.shown).ok();
    app.emit_to("ui", "status", &a.status).ok();
    app.emit_to("ui", "loading", a.loading).ok();
}

/// Меняет вкладку и сообщает панели. Активной вкладки касается и событиями адреса.
fn set_tab(app: &AppHandle, core: &Core, id: u32, f: impl FnOnce(&mut Tab)) {
    let active = {
        let mut t = core.tabs.lock().unwrap();
        let active = t.active == id;
        let Some(tab) = t.list.iter_mut().find(|x| x.id == id) else { return };
        f(tab);
        active
    };
    emit_tabs(app, core);
    if active {
        emit_active(app, core);
    }
}

fn switch_to(app: &AppHandle, core: &Core, id: u32) {
    let labels = {
        let mut t = core.tabs.lock().unwrap();
        if !t.list.iter().any(|x| x.id == id) {
            return;
        }
        t.active = id;
        t.list.iter().map(|x| x.id).collect::<Vec<_>>()
    };
    for i in labels {
        if let Some(w) = app.get_webview(&label(i)) {
            if i == id { w.show().ok() } else { w.hide().ok() };
        }
    }
    layout(app);
    emit_tabs(app, core);
    emit_active(app, core);
}

fn build_tab(app: &AppHandle, core: &Arc<Core>, id: u32, load: Url) -> WebviewBuilder<tauri::Wry> {
    let (nav_app, nav_core) = (app.clone(), core.clone());
    let (win_app, win_core) = (app.clone(), core.clone());
    let (title_app, title_core) = (app.clone(), core.clone());
    let (load_app, load_core) = (app.clone(), core.clone());
    WebviewBuilder::new(label(id), WebviewUrl::External(load))
        .background_color(BLACK)
        .on_navigation(move |url| {
            // Файлы приложения в странице сайта: только страницы `browser://` (остальное — команды приложения для панели).
            if (url.scheme() == "tauri" || url.host_str() == Some("tauri.localhost")) && internal_page(url).is_none() {
                return false;
            }
            // Ссылки `rift://…` и `browser://…` внутри страниц открываем сами: WebView таких схем не знает.
            if matches!(url.scheme(), "rift" | "browser") {
                let (app, core, input) = (nav_app.clone(), nav_core.clone(), url.as_str().to_string());
                tauri::async_runtime::spawn(async move {
                    go(&app, &core, Some(id), &input).await.ok();
                });
                return false;
            }
            true
        })
        // `target=_blank` и `window.open`: новая вкладка вместо окна.
        .on_new_window(move |url, _| {
            let (app, core, input) = (win_app.clone(), win_core.clone(), url.as_str().to_string());
            tauri::async_runtime::spawn(async move {
                open_input(&app, &core, &input).await.ok();
            });
            NewWindowResponse::Deny
        })
        .on_document_title_changed(move |_, title| set_tab(&title_app, &title_core, id, |t| t.title = title))
        // `on_page_load`, а не `on_navigation`, для адреса: он срабатывает и при переходе назад/вперёд.
        .on_page_load(move |wv, payload| match payload.event() {
            PageLoadEvent::Started => {
                // Свои страницы чёрные с первого кадра (без белой вспышки), чужие сайты — на обычном белом фоне.
                let ours = internal_page(payload.url()).is_some() || load_core.shown(payload.url()).1.is_some_and(|n| BUILTIN.contains(&n.as_str()));
                wv.set_background_color(Some(if ours { BLACK } else { WHITE })).ok();
                set_tab(&load_app, &load_core, id, |t| {
                    t.loading = true;
                    t.title.clear();
                });
                announce(&load_app, &load_core, id, payload.url());
            }
            PageLoadEvent::Finished => {
                set_tab(&load_app, &load_core, id, |t| t.loading = false);
                let (app, core) = (load_app.clone(), load_core.clone());
                tauri::async_runtime::spawn(record_visit(app, core, id));
            }
        })
}

/// Создаёт вкладку. Слой `overlay` после этого поднимается наверх: новый WebView иначе ляжет поверх него.
fn open_tab(app: &AppHandle, core: &Arc<Core>, load: Url, activate: bool) -> Result<u32, String> {
    let window = app.get_window("main").ok_or("нет окна")?;
    let s = window.inner_size().map_err(|e| e.to_string())?.to_logical::<f64>(window.scale_factor().map_err(|e| e.to_string())?);
    let id = {
        let mut t = core.tabs.lock().unwrap();
        t.next += 1;
        let id = t.next;
        t.list.push(Tab { id, title: String::new(), shown: String::new(), loading: false, status: json!({ "rift": false }) });
        id
    };
    let first = core.tab_count() == 1;
    let made = window.add_child(build_tab(app, core, id, load), LogicalPosition::new(0.0, CHROME_H), LogicalSize::new(s.width, (s.height - CHROME_H).max(1.0)));
    let wv = match made {
        Ok(w) => w,
        Err(e) => {
            core.tabs.lock().unwrap().list.retain(|t| t.id != id);
            return Err(e.to_string());
        }
    };
    if let Some(o) = app.get_webview("overlay") {
        if let Err(e) = o.reparent(&window) {
            eprintln!("не удалось поднять слой над вкладкой: {e}");
        }
    }
    if activate || first {
        switch_to(app, core, id);
    } else {
        wv.hide().ok();
        layout(app);
        emit_tabs(app, core);
    }
    Ok(id)
}

/// Открывает набранное в новой вкладке. Пустое — страница новой вкладки.
async fn open_input(app: &AppHandle, core: &Arc<Core>, input: &str) -> Result<u32, String> {
    let input = if input.trim().is_empty() { "browser://newtab" } else { input };
    let t = core.target(input).await.map_err(|e| format!("{e:#}"))?;
    open_tab(app, core, load_url(app, &t)?, true)
}

#[tauri::command]
async fn tab_new(input: Option<String>, core: State<'_, Arc<Core>>, app: AppHandle) -> Result<u32, String> {
    open_input(&app, &core, input.as_deref().unwrap_or("")).await
}

#[tauri::command]
fn tab_switch(id: u32, core: State<'_, Arc<Core>>, app: AppHandle) {
    switch_to(&app, &core, id);
}

#[tauri::command]
fn tab_close(id: u32, core: State<'_, Arc<Core>>, app: AppHandle) {
    close_tab(&app, &core, id);
}

fn close_tab(app: &AppHandle, core: &Core, id: u32) {
    let next = {
        let mut t = core.tabs.lock().unwrap();
        let Some(i) = t.list.iter().position(|x| x.id == id) else { return };
        t.list.remove(i);
        (t.active == id).then(|| t.list.get(i).or_else(|| t.list.last()).map(|x| x.id)).flatten()
    };
    if let Some(w) = app.get_webview(&label(id)) {
        w.close().ok();
    }
    if core.tab_count() == 0 {
        // Последняя вкладка закрыта: закрывается и окно, как в Chrome.
        if let Some(w) = app.get_window("main") {
            w.close().ok();
        }
        return;
    }
    match next {
        Some(n) => switch_to(app, core, n),
        None => emit_tabs(app, core),
    }
}

#[tauri::command]
fn tabs_state(core: State<'_, Arc<Core>>, app: AppHandle) {
    emit_tabs(&app, &core);
    emit_active(&app, &core);
}

// ---- история и закладки

/// Записывает посещение, когда страница загрузилась. Сайты Rift, чьё имя не проверилось, и страницы приложения не пишем.
async fn record_visit(app: AppHandle, core: Arc<Core>, id: u32) {
    let Some(tab) = core.tabs.lock().unwrap().list.iter().find(|t| t.id == id).cloned() else { return };
    if tab.shown.is_empty() || tab.shown.starts_with("browser://") || !core.settings().save_history {
        return;
    }
    if let Some(name) = tab.shown.strip_prefix("rift://").map(|r| split_host(r).0.to_string()) {
        if core.client.resolve(&name).await.is_err() {
            return;
        }
    }
    let title = if tab.title.is_empty() { tab.shown.clone() } else { tab.title };
    core.store.lock().unwrap().visit(&tab.shown, &title, now_ms());
    app.emit("history", ()).ok();
}

#[tauri::command]
fn history_list(query: String, limit: usize, core: State<'_, Arc<Core>>) -> Vec<crate::store::Entry> {
    core.store.lock().unwrap().history(&query, limit.min(1000))
}

#[tauri::command]
fn history_forget(urls: Vec<String>, core: State<'_, Arc<Core>>, app: AppHandle) {
    core.store.lock().unwrap().forget(&urls);
    app.emit("history", ()).ok();
}

#[tauri::command]
fn history_clear(core: State<'_, Arc<Core>>, app: AppHandle) {
    core.store.lock().unwrap().clear_history();
    app.emit("history", ()).ok();
}

#[tauri::command]
fn top_sites(n: usize, core: State<'_, Arc<Core>>) -> Vec<Value> {
    core.store.lock().unwrap().top(n.min(50)).into_iter().map(|(url, title, visits)| json!({ "url": url, "title": title, "visits": visits })).collect()
}

/// Подсказки под адресной строкой: закладки, потом история по частоте и свежести.
#[tauri::command]
fn suggest(query: String, core: State<'_, Arc<Core>>) -> Vec<Value> {
    core.store().suggest(&query, 6).into_iter().map(|(e, kind)| json!({ "url": e.url, "title": e.title, "kind": kind })).collect()
}

#[tauri::command]
fn bookmarks_list(core: State<'_, Arc<Core>>) -> Vec<crate::store::Entry> {
    core.store.lock().unwrap().marks()
}

#[tauri::command]
fn bookmark_state(url: String, core: State<'_, Arc<Core>>) -> bool {
    core.store.lock().unwrap().is_marked(&url)
}

/// Звёздочка в адресной строке: закладка на открытую страницу. Страницы приложения и пустая вкладка в закладки не идут.
#[tauri::command]
fn bookmark_toggle(core: State<'_, Arc<Core>>, app: AppHandle) -> Result<bool, String> {
    let t = core.active_tab().filter(|t| !t.shown.is_empty() && !t.shown.starts_with("browser://")).ok_or("эту страницу нельзя добавить в закладки")?;
    let title = if t.title.is_empty() { t.shown.clone() } else { t.title };
    let on = core.store.lock().unwrap().toggle_mark(&t.shown, &title, now_ms());
    app.emit("bookmarks", ()).ok();
    Ok(on)
}

#[tauri::command]
fn bookmark_remove(url: String, core: State<'_, Arc<Core>>, app: AppHandle) {
    core.store.lock().unwrap().remove_mark(&url);
    app.emit("bookmarks", ()).ok();
}

// ---- настройки

#[tauri::command]
fn get_settings(core: State<'_, Arc<Core>>) -> Settings {
    core.settings()
}

fn broadcast(app: &AppHandle, s: &Settings) {
    app.emit("settings", s).ok();
}

#[tauri::command]
fn set_settings(patch: Value, core: State<'_, Arc<Core>>, app: AppHandle) -> Result<Settings, String> {
    let s = core.update(|s| s.patch(&patch))?;
    broadcast(&app, &s);
    Ok(s)
}

#[tauri::command]
fn reset_settings(core: State<'_, Arc<Core>>, app: AppHandle) -> Result<Settings, String> {
    let s = core.update(|s| {
        *s = Settings::default();
        Ok(())
    })?;
    broadcast(&app, &s);
    Ok(s)
}

#[tauri::command]
fn get_caps() -> Value {
    json!({ "blur": cfg!(target_os = "macos") })
}

#[tauri::command]
fn get_info(core: State<'_, Arc<Core>>) -> Value {
    let t = core.client.trust();
    json!({
        "version": env!("CARGO_PKG_VERSION"), "root": t.root.to_string(), "quorum": format!("{} из {}", t.threshold, t.witnesses.len()),
        "resolvers": core.client.resolver_count(), "gateway": format!("127.0.0.1:{}", core.port), "node": core.client.node_id().to_string(),
        "data_dir": core.settings_path.as_deref().and_then(Path::parent).map_or_else(|| "только в памяти".into(), |p| p.display().to_string()),
    })
}

#[tauri::command]
async fn sync_notices(core: State<'_, Arc<Core>>) -> Result<usize, String> {
    Ok(core.client.sync_notices().await)
}

// ---- слой `overlay`: меню, окна, уведомления поверх страницы сайта

/// Показать компонент слоя (без ответа).
#[tauri::command]
fn overlay_open(spec: Value, app: AppHandle) {
    app.emit_to("overlay", "overlay:open", spec).ok();
}

/// Показать диалог и дождаться ответа пользователя (`null` — закрыт без выбора).
#[tauri::command]
async fn overlay_ask(mut spec: Value, core: State<'_, Arc<Core>>, app: AppHandle) -> Result<Value, String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (tx, rx) = oneshot::channel();
    core.asks.lock().unwrap().insert(id, tx);
    spec["id"] = id.into();
    app.emit_to("overlay", "overlay:open", spec).map_err(|e| e.to_string())?;
    rx.await.map_err(|_| "слой закрыт".to_string())
}

#[tauri::command]
fn overlay_result(id: u64, value: Value, core: State<'_, Arc<Core>>) {
    if let Some(tx) = core.asks.lock().unwrap().remove(&id) {
        tx.send(value).ok();
    }
}

/// Слой: `full` — на всё окно (модальные окна, меню); `rect` — плашка справа сверху (уведомления); `at` — плашка в заданном месте
/// (подсказки адреса). Возвращает размер окна: по нему слой считает положение меню, не дожидаясь, пока WebView узнает свой размер.
#[tauri::command]
fn overlay_mode(mode: String, w: Option<f64>, h: Option<f64>, x: Option<f64>, y: Option<f64>, core: State<'_, Arc<Core>>, app: AppHandle) -> Value {
    let (w, h) = (w.unwrap_or(360.0), h.unwrap_or(80.0));
    *core.overlay.lock().unwrap() = Some(match mode.as_str() {
        "rect" => OverlayMode::Right(w, h),
        "at" => OverlayMode::At(x.unwrap_or(0.0), y.unwrap_or(CHROME_H), w, h),
        _ => OverlayMode::Full,
    });
    layout(&app);
    if let Some(o) = app.get_webview("overlay") {
        o.show().ok();
    }
    let size = app.get_window("main").and_then(|w| Some(w.inner_size().ok()?.to_logical::<f64>(w.scale_factor().ok()?)));
    json!({ "w": size.map(|s| s.width), "h": size.map(|s| s.height) })
}

#[tauri::command]
fn overlay_hide(core: State<'_, Arc<Core>>, app: AppHandle) {
    *core.overlay.lock().unwrap() = None;
    if let Some(o) = app.get_webview("overlay") {
        o.hide().ok();
    }
    crate::native::hide_blur(&app);
}

/// Размытие под слоем: уровень берётся из настроек, скорость затухания — из режима анимаций.
#[tauri::command]
fn overlay_blur(region: Option<Value>, core: State<'_, Arc<Core>>, app: AppHandle) {
    let s = core.settings();
    let region = region.filter(|_| s.blur != "off").and_then(|r| {
        let f = |k: &str| r[k].as_f64();
        Some(crate::native::Region { x: f("x")?, y: f("y")?, w: f("w")?, h: f("h")?, r: f("r").unwrap_or(0.0) })
    });
    let fade = if s.motion == "off" { 0 } else if s.motion == "reduced" { 80 } else { 180 };
    let material = if s.blur == "strong" { crate::native::MATERIAL_STRONG } else { crate::native::MATERIAL_SOFT };
    match region {
        Some(r) => crate::native::set_blur(&app, Some(r), material, fade),
        None => {
            crate::native::set_blur(&app, None, material, fade);
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(fade + 40)).await;
                crate::native::hide_blur(&app);
            });
        }
    }
}

// ---------------------------------------------------------------- окно

/// Сообщает панели новый адрес и результат проверки сайта.
fn announce(app: &AppHandle, core: &Arc<Core>, id: u32, url: &Url) {
    let (shown, name) = core.shown(url);
    set_tab(app, core, id, |t| {
        t.shown = shown.clone();
        t.status = json!({ "rift": false });
    });
    let (app, core, web) = (app.clone(), core.clone(), matches!(url.scheme(), "http" | "https") && name.is_none());
    tauri::async_runtime::spawn(async move {
        let status = match name {
            Some(n) if BUILTIN.contains(&n.as_str()) => json!({ "rift": false }),
            None => json!({ "rift": false, "web": web }),
            Some(name) => match core.client.resolve(&name).await {
                Ok(r) => {
                    let t = core.client.trust();
                    json!({
                        "ok": true, "rift": true, "name": name, "owner": r.owner.to_string(), "hosts": r.hosts.len(), "seq": r.seq,
                        "root": t.root.to_string(), "quorum": format!("{} из {}", t.threshold, t.witnesses.len()),
                    })
                }
                Err(e) => {
                    let blocked = e.downcast_ref::<Blocked>().is_some();
                    json!({ "ok": false, "rift": true, "blocked": blocked, "name": name, "error": format!("{e:#}") })
                }
            },
        };
        // Вкладка могла уйти на другую страницу, пока шла проверка: тогда результат устарел.
        set_tab(&app, &core, id, |t| {
            if t.shown == shown {
                t.status = status;
            }
        });
    });
}

/// Раскладка WebView в окне. Границы задаются разом (`set_bounds`): на macOS пересчёт координат зависит от
/// текущей высоты вида. Сверху оставляем место под заголовок окна: при `fullSizeContentView` содержимое заходит под него
/// и панель иначе оказывается наполовину спрятанной, а страница поверх неё. Слой `overlay` лежит поверх всего.
fn layout(app: &AppHandle) {
    let Some(w) = app.get_window("main") else { return };
    let (Ok(size), Ok(scale)) = (w.inner_size(), w.scale_factor()) else { return };
    let s = size.to_logical::<f64>(scale);
    let rect = |x: f64, y: f64, w: f64, h: f64| Rect { position: LogicalPosition::new(x, y).into(), size: LogicalSize::new(w.max(1.0), h.max(1.0)).into() };
    if let Some(ui) = app.get_webview("ui") {
        ui.set_bounds(rect(0.0, 0.0, s.width, CHROME_H)).ok();
    }
    let core = app.try_state::<Arc<Core>>();
    for l in core.as_ref().map(|c| c.tab_labels()).unwrap_or_default() {
        if let Some(c) = app.get_webview(&l) {
            c.set_bounds(rect(0.0, CHROME_H, s.width, s.height - CHROME_H)).ok();
        }
    }
    if let Some(o) = app.get_webview("overlay") {
        let mode = core.as_ref().and_then(|c| *c.overlay.lock().unwrap());
        let r = match mode {
            Some(OverlayMode::Right(w, h)) => rect((s.width - w - OVERLAY_MARGIN).max(0.0), CHROME_H + 8.0, w.min(s.width), h),
            Some(OverlayMode::At(x, y, w, h)) => rect(x, y, w, h),
            _ => rect(0.0, 0.0, s.width, s.height),
        };
        o.set_bounds(r).ok();
    }
    crate::native::place_traffic_lights(app, TRAFFIC_X, TAB_H);
}

/// Проверка раскладки по настоящим границам WebView: панель сверху, страница сразу под ней, обе на всю ширину окна.
/// Возвращает описание нарушения.
pub fn check_layout(app: &AppHandle) -> Result<(), String> {
    let w = app.get_window("main").ok_or("нет окна")?;
    let (inner, scale) = (w.inner_size().map_err(|e| e.to_string())?, w.scale_factor().map_err(|e| e.to_string())?);
    let core = app.try_state::<Arc<Core>>().ok_or("нет ядра")?;
    let active = core.active_label().ok_or("нет активной вкладки")?;
    let (ui, c) = (app.get_webview("ui").ok_or("нет панели")?, app.get_webview(&active).ok_or("нет страницы")?);
    let (up, us, cp, cs) = (ui.position().map_err(|e| e.to_string())?, ui.size().map_err(|e| e.to_string())?, c.position().map_err(|e| e.to_string())?, c.size().map_err(|e| e.to_string())?);
    let want_ui = (CHROME_H * scale).round() as i64;
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
    if let (Some(u), Some(c)) = (crate::native::frame(app, "ui"), crate::native::frame(app, &active)) {
        let (ut, ub) = u.top_bottom();
        let (ct, cb) = c.top_bottom();
        let want = CHROME_H;
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

/// Меню приложения. На macOS оно и есть источник сочетаний клавиш (⌘T, ⌘W…); без него не работают даже ⌘C и ⌘V.
fn app_menu(app: &AppHandle) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem as P, Submenu};
    let item = |id: &str, text: &str, key: &str| MenuItem::with_id(app, id, text, true, Some(key));
    let sep = || P::separator(app);
    let (new, close, addr, reload, settings, hist, mark, back, fwd) = (
        item("tab-new", "Новая вкладка", "CmdOrCtrl+T")?, item("tab-close", "Закрыть вкладку", "CmdOrCtrl+W")?, item("addr", "Перейти к адресу", "CmdOrCtrl+L")?,
        item("reload", "Обновить страницу", "CmdOrCtrl+R")?, item("settings", "Настройки…", "CmdOrCtrl+,")?, item("history", "История", "CmdOrCtrl+Y")?,
        item("bookmark", "Добавить в закладки", "CmdOrCtrl+D")?, item("back", "Назад", "CmdOrCtrl+[")?, item("forward", "Вперёд", "CmdOrCtrl+]")?,
    );
    Menu::with_items(app, &[
        &Submenu::with_items(app, "Rift", true, &[&settings, &sep()?, &P::hide(app, None)?, &P::hide_others(app, None)?, &P::show_all(app, None)?, &sep()?, &P::quit(app, None)?])?,
        &Submenu::with_items(app, "Файл", true, &[&new, &close])?,
        &Submenu::with_items(app, "Правка", true, &[&P::undo(app, None)?, &P::redo(app, None)?, &sep()?, &P::cut(app, None)?, &P::copy(app, None)?, &P::paste(app, None)?, &P::select_all(app, None)?])?,
        &Submenu::with_items(app, "Вид", true, &[&addr, &reload, &sep()?, &back, &fwd, &sep()?, &hist, &mark])?,
        &Submenu::with_items(app, "Окно", true, &[&P::minimize(app, None)?, &P::maximize(app, None)?])?,
    ])
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
        .menu(app_menu)
        .on_menu_event(|app, e| {
            // Пункты меню macOS работают, даже когда фокус в странице сайта; выполняет их панель (как и сочетания клавиш в ней).
            let id = e.id().as_ref();
            if matches!(id, "tab-new" | "addr") {
                if let Some(ui) = app.get_webview("ui") {
                    ui.set_focus().ok();
                }
            }
            app.emit_to("ui", "menu", id).ok();
        })
        .invoke_handler(tauri::generate_handler![
            navigate, history, reload, tab_new, tab_switch, tab_close, tabs_state, history_list, history_forget, history_clear, top_sites, suggest,
            crate::wallet::wallet_status, crate::wallet::wallet_create, crate::wallet::wallet_import, crate::wallet::wallet_unlock, crate::wallet::wallet_lock,
            crate::wallet::wallet_reveal, crate::wallet::wallet_balances, crate::wallet::wallet_history, crate::wallet::wallet_check_send, crate::wallet::wallet_send,
            crate::wallet::wallet_add_token, crate::wallet::wallet_forget,
            bookmarks_list, bookmark_state, bookmark_toggle, bookmark_remove, get_settings, set_settings, reset_settings, get_caps, get_info, sync_notices,
            overlay_open, overlay_ask, overlay_result, overlay_mode, overlay_hide, overlay_blur
        ])
        .setup(move |app| {
            let builder = WindowBuilder::new(app, "main").title("Rift").inner_size(1100.0, 760.0).min_inner_size(320.0, 240.0).background_color(BLACK);
            // Рамка как у Chrome: панель занимает место заголовка. macOS: родные кнопки поверх прозрачного заголовка.
            #[cfg(target_os = "macos")]
            let builder = builder.title_bar_style(tauri::TitleBarStyle::Overlay).hidden_title(true);
            // Windows: без системной рамки, кнопки окна рисует панель; границы и тень окна обрабатывает сам Tauri.
            #[cfg(windows)]
            let builder = builder.decorations(false).shadow(true);
            let window = builder.build()?;
            let s = window.inner_size()?.to_logical::<f64>(window.scale_factor()?);
            window.add_child(
                WebviewBuilder::new("ui", WebviewUrl::App("index.html".into())).background_color(BLACK).initialization_script(format!("window.__RIFT_FRAME__ = '{FRAME}';")),
                LogicalPosition::new(0.0, 0.0),
                LogicalSize::new(s.width, CHROME_H),
            )?;
            // Слой поверх всего (добавлен последним): прозрачный, пока ничего не показывает.
            let overlay = window.add_child(
                WebviewBuilder::new("overlay", WebviewUrl::App("overlay.html".into())).transparent(true),
                LogicalPosition::new(0.0, 0.0),
                LogicalSize::new(s.width, s.height),
            )?;
            overlay.hide()?;
            open_tab(app.handle(), &core, first.parse()?, true)?;
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
        let core = serve_gateway(client, secret(&dir.join("gateway-secret"))?, Some(dir)).await?;
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

pub async fn serve_gateway(client: Arc<RiftClient>, secret: [u8; 32], dir: Option<&Path>) -> Result<Arc<Core>> {
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
    Ok(Arc::new(Core::new(client, gateway, port, dir)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_pages_only_from_app_origin() {
        let p = |s: &str| internal_page(&s.parse().unwrap());
        assert_eq!(p("tauri://localhost/settings.html"), Some("settings"));
        assert_eq!(p("http://tauri.localhost/settings.html"), Some("settings"));
        // Другие файлы приложения (панель, слой) и чужие источники в `browser://` не превращаются.
        assert_eq!(p("tauri://localhost/index.html"), None);
        assert_eq!(p("tauri://localhost/overlay.html"), None);
        assert_eq!(p("https://evil.example/settings.html"), None);
        assert_eq!(p("http://tauri.localhost.evil.example/settings.html"), None);
        assert_eq!(p("http://localhost:47878/settings.html"), None);
    }
}
