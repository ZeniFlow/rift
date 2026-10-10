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

// ---------------------------------------------------------------- системное размытие под слоем

/// Область размытия в логических пикселях окна (начало слева сверху) и радиус углов.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Region {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    pub r: f64,
}

/// Что видно о размытии на самом деле (для самопроверки): скрыто ли, прозрачность, рамка сверху вниз, материал.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BlurInfo {
    pub hidden: bool,
    pub alpha: f64,
    pub frame: Region,
    pub material: i64,
}

const BLUR_ID: &str = "rift-blur";
/// `NSVisualEffectMaterial`: мягкое размытие — `Popover`, сильное — `HUDWindow`.
pub const MATERIAL_SOFT: i64 = 6;
pub const MATERIAL_STRONG: i64 = 13;

/// Показывает или убирает размытие под слоем `overlay`. `None` — убрать (плавно, за `fade_ms`).
#[cfg(target_os = "macos")]
pub fn set_blur(app: &AppHandle, region: Option<Region>, material: i64, fade_ms: u64) {
    use objc2::{
        msg_send,
        rc::Retained,
        runtime::{AnyClass, AnyObject},
    };
    use objc2_app_kit::NSView;
    use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};

    let Some(overlay) = app.get_webview("overlay") else { return };
    let _ = overlay.with_webview(move |w| unsafe {
        let view: &NSView = &*(w.inner() as *const NSView);
        let Some(parent) = view.superview() else { return };
        // Найти наш вид среди соседей или создать.
        let existing = parent.subviews().iter().find(|v| {
            let id: Option<Retained<NSString>> = msg_send![&***v, identifier];
            id.is_some_and(|s| s.to_string() == BLUR_ID)
        });
        let effect: Retained<AnyObject> = match existing {
            Some(v) => Retained::cast_unchecked(v),
            None => {
                let Some(cls) = AnyClass::get(c"NSVisualEffectView") else { return };
                let e: Retained<AnyObject> = msg_send![cls, new];
                let _: () = msg_send![&*e, setIdentifier: &*NSString::from_str(BLUR_ID)];
                let _: () = msg_send![&*e, setBlendingMode: 1_isize];   // withinWindow: размывает то, что лежит под ним в окне
                let _: () = msg_send![&*e, setState: 1_isize];          // active: не тускнеет вместе с окном
                if let Some(ap) = AnyClass::get(c"NSAppearance") {
                    let dark: Option<Retained<AnyObject>> = msg_send![ap, appearanceNamed: &*NSString::from_str("NSAppearanceNameDarkAqua")];
                    let _: () = msg_send![&*e, setAppearance: dark.as_deref()];
                }
                let _: () = msg_send![&*e, setWantsLayer: true];
                let _: () = msg_send![&*e, setAlphaValue: 0.0_f64];
                let below: isize = -1; // NSWindowBelow: прямо под слоем
                let _: () = msg_send![&*parent, addSubview: &*e, positioned: below, relativeTo: view];
                e
            }
        };

        // Слой могли поднять над видом размытия (новая вкладка): возвращаем размытие прямо под слой.
        let below: isize = -1;
        let _: () = msg_send![&*parent, addSubview: &*effect, positioned: below, relativeTo: view];

        let animate = |alpha: f64| {
            if fade_ms == 0 {
                let _: () = msg_send![&*effect, setAlphaValue: alpha];
                return;
            }
            let Some(ctx_cls) = AnyClass::get(c"NSAnimationContext") else { return };
            let _: () = msg_send![ctx_cls, beginGrouping];
            let ctx: Retained<AnyObject> = msg_send![ctx_cls, currentContext];
            let _: () = msg_send![&*ctx, setDuration: fade_ms as f64 / 1000.0];
            let proxy: Retained<AnyObject> = msg_send![&*effect, animator];
            let _: () = msg_send![&*proxy, setAlphaValue: alpha];
            let _: () = msg_send![ctx_cls, endGrouping];
        };

        match region {
            Some(r) => {
                let ph = parent.frame().size.height;
                let frame = NSRect::new(NSPoint::new(r.x, ph - r.y - r.h), NSSize::new(r.w, r.h));
                let _: () = msg_send![&*effect, setFrame: frame];
                let _: () = msg_send![&*effect, setMaterial: material];
                let layer: Option<Retained<AnyObject>> = msg_send![&*effect, layer];
                if let Some(layer) = layer {
                    let _: () = msg_send![&*layer, setCornerRadius: r.r];
                    let _: () = msg_send![&*layer, setMasksToBounds: true];
                }
                let _: () = msg_send![&*effect, setHidden: false];
                animate(1.0);
            }
            None => animate(0.0),
        }
    });
}

#[cfg(not(target_os = "macos"))]
pub fn set_blur(_: &AppHandle, _: Option<Region>, _: i64, _: u64) {}

/// Окончательно скрывает размытие (после затухания), чтобы невидимый вид не перехватывал клики.
#[cfg(target_os = "macos")]
pub fn hide_blur(app: &AppHandle) {
    use objc2::{msg_send, rc::Retained, runtime::AnyObject};
    use objc2_app_kit::NSView;
    use objc2_foundation::NSString;
    let Some(overlay) = app.get_webview("overlay") else { return };
    let _ = overlay.with_webview(|w| unsafe {
        let view: &NSView = &*(w.inner() as *const NSView);
        let Some(parent) = view.superview() else { return };
        for v in parent.subviews().iter() {
            let id: Option<Retained<NSString>> = msg_send![&*v, identifier];
            if id.is_some_and(|s| s.to_string() == BLUR_ID) {
                let alpha: f64 = msg_send![&*v, alphaValue];
                if alpha < 0.05 {
                    let o: &AnyObject = &*(Retained::as_ptr(&v) as *const AnyObject);
                    let _: () = msg_send![o, setHidden: true];
                }
            }
        }
    });
}

#[cfg(not(target_os = "macos"))]
pub fn hide_blur(_: &AppHandle) {}

/// Для самопроверки: настоящее состояние размытия.
#[cfg(target_os = "macos")]
pub fn blur_info(app: &AppHandle) -> Option<BlurInfo> {
    use objc2::{msg_send, rc::Retained};
    use objc2_app_kit::NSView;
    use objc2_foundation::NSString;
    let (tx, rx) = std::sync::mpsc::channel();
    app.get_webview("overlay")?
        .with_webview(move |w| unsafe {
            let view: &NSView = &*(w.inner() as *const NSView);
            let Some(parent) = view.superview() else { return tx.send(None).unwrap_or(()) };
            let ph = parent.frame().size.height;
            let found = parent.subviews().iter().find_map(|v| {
                let id: Option<Retained<NSString>> = msg_send![&*v, identifier];
                id.is_some_and(|s| s.to_string() == BLUR_ID).then(|| {
                    let f = v.frame();
                    let hidden: bool = msg_send![&*v, isHidden];
                    let alpha: f64 = msg_send![&*v, alphaValue];
                    let material: i64 = msg_send![&*v, material];
                    BlurInfo { hidden, alpha, frame: Region { x: f.origin.x, y: ph - f.origin.y - f.size.height, w: f.size.width, h: f.size.height, r: 0.0 }, material }
                })
            });
            tx.send(found).ok();
        })
        .ok()?;
    rx.recv_timeout(std::time::Duration::from_secs(2)).ok().flatten()
}

#[cfg(not(target_os = "macos"))]
pub fn blur_info(_: &AppHandle) -> Option<BlurInfo> {
    None
}

/// Слой `overlay` — самый верхний вид окна (иначе новая вкладка закрывает меню и окна). `None` — не удалось проверить.
#[cfg(target_os = "macos")]
pub fn overlay_on_top(app: &AppHandle) -> Option<bool> {
    use objc2_app_kit::NSView;
    let (tx, rx) = std::sync::mpsc::channel();
    app.get_webview("overlay")?
        .with_webview(move |w| unsafe {
            let view: &NSView = &*(w.inner() as *const NSView);
            let top = view.superview().and_then(|p| p.subviews().iter().last().map(|v| std::ptr::eq(&*v as *const NSView, view as *const NSView)));
            tx.send(top).ok();
        })
        .ok()?;
    rx.recv_timeout(std::time::Duration::from_secs(2)).ok().flatten()
}

#[cfg(not(target_os = "macos"))]
pub fn overlay_on_top(_: &AppHandle) -> Option<bool> {
    None
}

/// Скрыт ли вид WebView на самом деле (вкладка, которую не видно, не должна перекрывать активную).
#[cfg(target_os = "macos")]
pub fn hidden(app: &AppHandle, label: &str) -> Option<bool> {
    use objc2::msg_send;
    use objc2_app_kit::NSView;
    let (tx, rx) = std::sync::mpsc::channel();
    app.get_webview(label)?
        .with_webview(move |w| unsafe {
            let view: &NSView = &*(w.inner() as *const NSView);
            let h: bool = msg_send![view, isHidden];
            tx.send(h).ok();
        })
        .ok()?;
    rx.recv_timeout(std::time::Duration::from_secs(2)).ok()
}

#[cfg(not(target_os = "macos"))]
pub fn hidden(_: &AppHandle, _: &str) -> Option<bool> {
    None
}
