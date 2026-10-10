//! Настоящие рамки нативных видов. Нужны самопроверке: Tauri считает границы через ту же обёртку, которой их и задаёт,
//! поэтому перекрытие панели и страницы на экране он не замечает.

use tauri::{AppHandle, Manager};

/// Рамка вида в координатах родителя (macOS: начало внизу слева) и размер родителя.
#[derive(Debug, Clone, Copy)]
pub struct Frame {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    pub parent_h: f64,
    pub flipped: bool,
}

impl Frame {
    /// Верхняя и нижняя кромки вида, считая от верха родителя, вниз.
    pub fn top_bottom(&self) -> (f64, f64) {
        if self.flipped {
            (self.y, self.y + self.h)
        } else {
            (self.parent_h - self.y - self.h, self.parent_h - self.y)
        }
    }
}

#[cfg(target_os = "macos")]
pub fn frame(app: &AppHandle, label: &str) -> Option<Frame> {
    use objc2_app_kit::NSView;
    let (tx, rx) = std::sync::mpsc::channel();
    app.get_webview(label)?
        .with_webview(move |w| {
            // Безопасно: указатель принадлежит живому WKWebView (подкласс NSView) и используется в главном потоке.
            let view: &NSView = unsafe { &*(w.inner() as *const NSView) };
            let f = view.frame();
            let parent = unsafe { view.superview() };
            let (parent_h, flipped) = parent.map_or((0.0, false), |p| (p.frame().size.height, p.isFlipped()));
            tx.send(Frame { x: f.origin.x, y: f.origin.y, w: f.size.width, h: f.size.height, parent_h, flipped }).ok();
        })
        .ok()?;
    rx.recv_timeout(std::time::Duration::from_secs(2)).ok()
}

#[cfg(not(target_os = "macos"))]
pub fn frame(_: &AppHandle, _: &str) -> Option<Frame> {
    None
}

/// Для диагностики: рамка окна, область содержимого и стиль (полноразмерное содержимое заходит под заголовок).
#[cfg(target_os = "macos")]
pub fn window_info(app: &AppHandle) -> Option<String> {
    use objc2_app_kit::{NSWindow, NSWindowStyleMask};
    let (tx, rx) = std::sync::mpsc::channel();
    app.get_webview("ui")?
        .with_webview(move |w| {
            let win: &NSWindow = unsafe { &*(w.ns_window() as *const NSWindow) };
            let (f, layout) = (win.frame(), win.contentLayoutRect());
            let cv = win.contentView().map(|v| v.frame());
            tx.send(format!(
                "frame {:.0}x{:.0}  contentView {:?}  contentLayoutRect {:.0}x{:.0} @ y={:.0}  fullSizeContentView={}  titlebarTransparent={}",
                f.size.width, f.size.height, cv.map(|c| (c.size.width.round(), c.size.height.round())),
                layout.size.width, layout.size.height, layout.origin.y,
                win.styleMask().contains(NSWindowStyleMask::FullSizeContentView),
                win.titlebarAppearsTransparent(),
            ))
            .ok();
        })
        .ok()?;
    rx.recv_timeout(std::time::Duration::from_secs(2)).ok()
}

/// Кнопки окна macOS (закрыть / свернуть / развернуть) переносятся на середину панели высотой `bar_h`, первая — на `x` от левого края.
/// Тот же приём, что у tao (`traffic_light_position`), которого у окна с несколькими WebView нет. AppKit сбрасывает
/// положение при изменении размера окна, поэтому вызывается и из обработчика `Resized`.
#[cfg(target_os = "macos")]
pub fn place_traffic_lights(app: &AppHandle, x: f64, bar_h: f64) {
    use objc2_app_kit::{NSWindow, NSWindowButton};
    let Some(ui) = app.get_webview("ui") else { return };
    let _ = ui.with_webview(move |w| {
        let win: &NSWindow = unsafe { &*(w.ns_window() as *const NSWindow) };
        let (Some(close), Some(mini), Some(zoom)) = (
            win.standardWindowButton(NSWindowButton::CloseButton),
            win.standardWindowButton(NSWindowButton::MiniaturizeButton),
            win.standardWindowButton(NSWindowButton::ZoomButton),
        ) else {
            return;
        };
        let Some(bar) = (unsafe { close.superview() }) else { return };
        let Some(container) = (unsafe { bar.superview() }) else { return };
        let win_h = win.frame().size.height;
        // Контейнер заголовка — на всю высоту панели, прижат к верху окна.
        let mut c = container.frame();
        c.size.height = bar_h;
        c.origin.y = win_h - bar_h;
        container.setFrame(c);
        let mut b = bar.frame();
        b.size.height = bar_h;
        b.origin.y = 0.0;
        bar.setFrame(b);
        let step = mini.frame().origin.x - close.frame().origin.x;
        for (i, btn) in [&close, &mini, &zoom].into_iter().enumerate() {
            let f = btn.frame();
            btn.setFrameOrigin(objc2_foundation::NSPoint::new(x + i as f64 * step, (bar_h - f.size.height) / 2.0));
        }
    });
}

#[cfg(not(target_os = "macos"))]
pub fn place_traffic_lights(_: &AppHandle, _: f64, _: f64) {}

/// Где на самом деле стоят кнопки окна: (правый край самой правой, середина по вертикали от верха окна), в точках.
#[cfg(target_os = "macos")]
pub fn traffic_lights(app: &AppHandle) -> Option<(f64, f64)> {
    use objc2_app_kit::{NSWindow, NSWindowButton};
    let (tx, rx) = std::sync::mpsc::channel();
    app.get_webview("ui")?
        .with_webview(move |w| {
            let win: &NSWindow = unsafe { &*(w.ns_window() as *const NSWindow) };
            let win_h = win.frame().size.height;
            let (mut right, mut center) = (0.0_f64, 0.0_f64);
            for kind in [NSWindowButton::CloseButton, NSWindowButton::MiniaturizeButton, NSWindowButton::ZoomButton] {
                if let Some(b) = win.standardWindowButton(kind) {
                    let r = b.convertRect_toView(b.bounds(), None);
                    right = right.max(r.origin.x + r.size.width);
                    center = win_h - (r.origin.y + r.size.height / 2.0);
                }
            }
            tx.send((right, center)).ok();
        })
        .ok()?;
    rx.recv_timeout(std::time::Duration::from_secs(2)).ok()
}

#[cfg(not(target_os = "macos"))]
pub fn traffic_lights(_: &AppHandle) -> Option<(f64, f64)> {
    None
}
