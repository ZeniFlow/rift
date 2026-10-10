//! Страницы, которые показывает сам Rift: ошибки шлюза и системные страницы приложения.
//! Один набор дизайн-токенов с панелью браузера: тёмная тема, плоские цвета, радиусы 4–8 px, SVG-иконки.

/// Иконки (24x24, обводка `currentColor`, без заливки). Набор в духе Lucide.
pub mod icon {
    macro_rules! icon {
        ($name:ident, $body:literal) => {
            pub const $name: &str = concat!(
                r#"<svg class="ico" viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">"#,
                $body,
                "</svg>"
            );
        };
    }
    icon!(SHIELD_CHECK, r#"<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>"#);
    icon!(SHIELD_ALERT, r#"<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/>"#);
    icon!(BAN, r#"<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>"#);
    icon!(GLOBE, r#"<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>"#);
    icon!(LOCK, r#"<rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>"#);
    icon!(UNPLUG, r#"<path d="m19 5 3-3"/><path d="m2 22 3-3"/><path d="M6.3 20.3a2.4 2.4 0 0 0 3.4 0L12 18l-6-6-2.3 2.3a2.4 2.4 0 0 0 0 3.4Z"/><path d="M7.5 13.5 10 11"/><path d="M10.5 16.5 13 14"/><path d="m12 6 6 6 2.3-2.3a2.4 2.4 0 0 0 0-3.4l-2.6-2.6a2.4 2.4 0 0 0-3.4 0Z"/>"#);
    icon!(SERVER, r#"<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01"/><path d="M6 18h.01"/>"#);
    icon!(KEY, r#"<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>"#);
    icon!(WAYPOINTS, r#"<circle cx="12" cy="4.5" r="2.5"/><path d="m10.2 6.3-3.9 3.9"/><circle cx="4.5" cy="12" r="2.5"/><path d="M7 12h10"/><circle cx="19.5" cy="12" r="2.5"/><path d="m13.8 17.7 3.9-3.9"/><circle cx="12" cy="19.5" r="2.5"/>"#);
    icon!(COMMAND, r#"<path d="M15 6v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3V6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3"/>"#);
    icon!(CHECK, r#"<path d="M20 6 9 17l-5-5"/>"#);
    icon!(X, r#"<path d="M18 6 6 18"/><path d="m6 6 12 12"/>"#);
}

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Дизайн-токены и базовые стили страниц Rift. Только тёмная тема, радиусы 4/6/8, плоские цвета.
pub const CSS: &str = r#"
:root{color-scheme:dark;
 --bg:#000;--surface:#000;--field:#0a0a0c;--raised:#131316;--raised-2:#1b1b20;--line:#1f1f24;--line-2:#2e2e35;
 --text:#f2f2f5;--text-2:#a8a8b2;--text-3:#7b7b86;
 --accent:#6aa5e8;--ok:#4cc38a;--warn:#e0a84a;--bad:#e5645c;
 --r-s:6px;--r-m:10px;--r-l:14px;--r-full:999px;
 --font:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
 --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;--ease:cubic-bezier(.2,.7,.2,1)}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 var(--font);-webkit-font-smoothing:antialiased}
.page{max-width:680px;margin:0 auto;padding:clamp(24px,7vh,72px) clamp(20px,5vw,40px) 48px;animation:rise .32s var(--ease) both}
.ico{width:20px;height:20px;flex:none}
h1{margin:0 0 10px;font-size:clamp(20px,3.2vw,26px);line-height:1.25;font-weight:600;letter-spacing:-.01em}
h2{margin:0 0 10px;font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--text-3)}
p{margin:0 0 14px}.lead{color:var(--text-2);max-width:56ch}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
a:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:var(--r-s)}
.btn{display:inline-flex;align-items:center;gap:8px;height:36px;padding:0 16px;border:1px solid var(--line-2);border-radius:var(--r-full);background:var(--raised);color:var(--text);font:500 13px/1 var(--font);transition:background-color .12s var(--ease),transform .12s var(--ease)}.btn:hover{background:var(--raised-2);text-decoration:none}.btn:active{transform:scale(.97)}
code,.mono{font-family:var(--mono);font-size:.9em}
.mark{display:grid;place-items:center;width:48px;height:48px;margin-bottom:22px;border:1px solid var(--line);border-radius:var(--r-full);background:var(--field)}
.mark .ico{width:22px;height:22px}
.mark.bad{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 40%,var(--line))}
.mark.warn{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 40%,var(--line))}
.mark.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,var(--line))}
.code{margin:0 0 6px;color:var(--text-3);font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase}
.detail{margin:20px 0;padding:14px 16px;border:1px solid var(--line);border-radius:var(--r-l);background:var(--field);color:var(--text-2);font:13px/1.5 var(--mono);overflow-wrap:anywhere}
.hint{color:var(--text-3);font-size:13px}
.card{border:1px solid var(--line);border-radius:var(--r-l);background:var(--field);overflow:hidden}
dl{display:grid;grid-template-columns:minmax(110px,max-content) 1fr;margin:0}
dt,dd{margin:0;padding:11px 16px;border-top:1px solid var(--line)}
dt:first-of-type,dt:first-of-type+dd{border-top:0}
dt{display:flex;align-items:center;gap:8px;color:var(--text-3);font-size:13px}
dt .ico{width:16px;height:16px}
dd{font-size:13px;overflow-wrap:anywhere}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;margin-top:28px}
.kbd{display:inline-block;min-width:24px;padding:1px 7px;border:1px solid var(--line-2);border-bottom-width:2px;border-radius:var(--r-s);background:var(--raised);color:var(--text-2);font:12px/1.5 var(--mono);text-align:center}
ul.plain{margin:0;padding:0;list-style:none}ul.plain li{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 16px;border-top:1px solid var(--line);color:var(--text-2);font-size:13px}
ul.plain li:first-child{border-top:0}
@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@media (max-width:520px){dl{grid-template-columns:1fr}dt{padding-bottom:0}dt,dd{border-top:0}dd{padding-top:2px;padding-bottom:12px;border-bottom:1px solid var(--line)}dd:last-of-type{border-bottom:0}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"#;

/// Оболочка страницы: заголовок, адаптивный viewport, общие стили.
pub fn shell(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>{}</title><style>{CSS}</style></head><body>{body}</body></html>"#,
        esc(title)
    )
}

/// Вид страницы ошибки: определяет цвет и иконку.
#[derive(Clone, Copy)]
pub enum Kind {
    /// Решение оператора: заморожено или отозвано.
    Blocked,
    /// Не найдено / не отвечает.
    Unreachable,
    /// Чужой или неверный адрес.
    Forbidden,
}

/// Страница ошибки шлюза. `detail` — техническая причина (показывается как есть, экранируется).
pub fn error_page(code: u16, kind: Kind, title: &str, lead: &str, detail: &str, hint: &str) -> String {
    let (class, ico) = match kind {
        Kind::Blocked => ("bad", icon::BAN),
        Kind::Unreachable => ("warn", icon::UNPLUG),
        Kind::Forbidden => ("bad", icon::LOCK),
    };
    let detail = if detail.is_empty() { String::new() } else { format!(r#"<div class="detail" role="note">{}</div>"#, esc(detail)) };
    let hint = if hint.is_empty() { String::new() } else { format!(r#"<p class="hint">{}</p>"#, esc(hint)) };
    shell(
        title,
        &format!(
            r#"<main class="page"><div class="mark {class}">{ico}</div><p class="code">Ошибка {code}</p><h1>{}</h1><p class="lead">{}</p>{detail}{hint}</main>"#,
            esc(title),
            esc(lead)
        ),
    )
}
