//! Rift: браузер.
//!
//!     rift-app                  — окно браузера (сеть и доверие из <каталог данных>/config.json)
//!     rift-app selftest         — проверка WebView на сайте в сети Rift (cookie, Service Worker, WebSocket…)
//!     rift-app selftest-ui      — то же через панель: ввод адреса, назад/вперёд, статус
//!     rift-app demo             — окно браузера с сайтом в сети Rift, поднятой в процессе

mod browser;
mod native;
mod selftest;
mod settings;
mod store;

/// `generate_context!` можно вызвать в бинарнике только один раз.
pub fn context() -> tauri::Context {
    tauri::generate_context!()
}

fn data_dir() -> std::path::PathBuf {
    std::env::var_os("RIFT_APP_HOME").map(Into::into).unwrap_or_else(|| {
        std::env::home_dir().expect("не найден домашний каталог: задай RIFT_APP_HOME").join(".rift-app")
    })
}

fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("selftest") => selftest::run(),
        Some("selftest-ui") => selftest::run_ui(),
        Some("demo") => selftest::run_demo(),
        Some("pages") => selftest::dump_pages(&std::env::args().nth(2).unwrap_or_else(|| "pages".into())),
        None => {
            let (core, _node) = browser::boot(&data_dir())?;
            browser::launch(core, None, |_| {})
        }
        Some(other) => anyhow::bail!("неизвестная команда {other}: selftest, selftest-ui или без аргументов"),
    }
}
