use std::sync::Mutex;

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Wry};

use crate::model::{Entry, IconState, Model};

pub const TRAY_ID: &str = "main";

#[derive(Default)]
pub struct Rendered(Mutex<Option<(Vec<Entry>, IconState)>>);

#[cfg(target_os = "macos")]
fn icon_bytes(state: IconState) -> &'static [u8] {
    match state {
        IconState::Disconnected => include_bytes!("../icons/tray/disconnected.png"),
        IconState::Connecting => include_bytes!("../icons/tray/connecting.png"),
        IconState::Connected => include_bytes!("../icons/tray/connected.png"),
    }
}

#[cfg(not(target_os = "macos"))]
fn icon_bytes(state: IconState) -> &'static [u8] {
    match state {
        IconState::Disconnected => include_bytes!("../icons/tray/disconnected-light.png"),
        IconState::Connecting => include_bytes!("../icons/tray/connecting-light.png"),
        IconState::Connected => include_bytes!("../icons/tray/connected-light.png"),
    }
}

fn icon(state: IconState) -> tauri::Result<Image<'static>> {
    Image::from_bytes(icon_bytes(state))
}

const TEMPLATE: bool = cfg!(target_os = "macos");

fn menu(app: &AppHandle, entries: &[Entry]) -> tauri::Result<Menu<Wry>> {
    let menu = Menu::new(app)?;
    for entry in entries {
        match entry {
            Entry::Info(text) => menu.append(&MenuItem::new(app, text, false, None::<&str>)?)?,
            Entry::Action { id, label, enabled } => {
                menu.append(&MenuItem::with_id(app, id, label, *enabled, None::<&str>)?)?;
            }
            Entry::Separator => menu.append(&PredefinedMenuItem::separator(app)?)?,
        }
    }
    Ok(menu)
}

pub fn build(
    app: &AppHandle,
    model: &Model,
    rendered: &Rendered,
    on_menu: impl Fn(&AppHandle, &str) + Send + Sync + 'static,
) -> tauri::Result<TrayIcon> {
    let entries = model.menu_entries();
    let state = model.icon_state();
    let tray = TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon(state)?)
        .icon_as_template(TEMPLATE)
        .show_menu_on_left_click(true)
        .menu(&menu(app, &entries)?)
        .on_menu_event(move |app, event| on_menu(app, event.id().as_ref()))
        .build(app)?;
    *rendered
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((entries, state));
    Ok(tray)
}

pub fn update(app: &AppHandle, model: &Model, rendered: &Rendered) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let entries = model.menu_entries();
    let state = model.icon_state();
    let mut last = rendered
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (menu_changed, icon_changed) = match last.as_ref() {
        Some((old_entries, old_state)) => (*old_entries != entries, *old_state != state),
        None => (true, true),
    };
    if menu_changed {
        match menu(app, &entries) {
            Ok(menu) => {
                let _ = tray.set_menu(Some(menu));
            }
            Err(error) => tracing::warn!("tray menu rebuild failed: {error}"),
        }
    }
    if icon_changed && let Ok(image) = icon(state) {
        let _ = tray.set_icon(Some(image));
        let _ = tray.set_icon_as_template(TEMPLATE);
    }
    *last = Some((entries, state));
}
