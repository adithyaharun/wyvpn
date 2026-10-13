use serde::Serialize;

#[derive(Serialize, Clone, Copy, PartialEq, Debug)]
pub struct WindowChrome {
    pub button_center_y: f64,
    pub buttons_right: f64,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Clone, Copy)]
struct Rect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn from_top_left(window_height: f64, close: Rect, zoom: Rect) -> WindowChrome {
    WindowChrome {
        button_center_y: window_height - (close.y + close.height / 2.0),
        buttons_right: zoom.x + zoom.width,
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use objc2_app_kit::{NSButton, NSWindow, NSWindowButton};
    use objc2_foundation::NSRect;
    use tauri::WebviewWindow;

    use super::{Rect, WindowChrome, from_top_left};

    fn window_rect(button: &NSButton) -> Rect {
        let rect: NSRect = button.convertRect_toView(button.bounds(), None);
        Rect {
            x: rect.origin.x,
            y: rect.origin.y,
            width: rect.size.width,
            height: rect.size.height,
        }
    }

    pub fn measure(window: &WebviewWindow) -> Option<WindowChrome> {
        let ptr = window.ns_window().ok()?.cast::<NSWindow>();
        // SAFETY: ns_window() returns the live NSWindow owned by this window, and callers run on the main thread.
        let ns_window = unsafe { ptr.as_ref() }?;
        ns_window.displayIfNeeded();
        let close = ns_window.standardWindowButton(NSWindowButton::CloseButton)?;
        let zoom = ns_window.standardWindowButton(NSWindowButton::ZoomButton)?;
        Some(from_top_left(
            ns_window.frame().size.height,
            window_rect(&close),
            window_rect(&zoom),
        ))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use tauri::WebviewWindow;

    use super::WindowChrome;

    pub fn measure(_window: &WebviewWindow) -> Option<WindowChrome> {
        None
    }
}

pub use imp::measure;

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: f64, y: f64) -> Rect {
        Rect {
            x,
            y,
            width: 14.0,
            height: 16.0,
        }
    }

    #[test]
    fn old_style_buttons_centre_near_seventeen_points() {
        let chrome = from_top_left(600.0, rect(16.0, 575.0), rect(56.0, 575.0));
        assert_eq!(chrome.button_center_y, 17.0);
        assert_eq!(chrome.buttons_right, 70.0);
    }

    #[test]
    fn new_style_buttons_sit_lower_and_wider() {
        let chrome = from_top_left(600.0, rect(20.0, 568.5), rect(76.0, 568.5));
        assert_eq!(chrome.button_center_y, 23.5);
        assert_eq!(chrome.buttons_right, 90.0);
    }
}
