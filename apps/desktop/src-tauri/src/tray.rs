use std::sync::Mutex;

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Wry};

use crate::model::{Entry, IconState, Model};

pub const TRAY_ID: &str = "main";

#[derive(Default)]
struct Latest {
    seq: u64,
    shown: Option<(Vec<Entry>, IconState)>,
}

#[derive(Default)]
pub struct Rendered(Mutex<Latest>);

impl Rendered {
    fn lock(&self) -> std::sync::MutexGuard<'_, Latest> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn begin(&self, entries: &[Entry], state: IconState) -> (u64, bool, bool) {
        let mut latest = self.lock();
        latest.seq += 1;
        let (menu_changed, icon_changed) = match latest.shown.as_ref() {
            Some((old_entries, old_state)) => (old_entries != entries, *old_state != state),
            None => (true, true),
        };
        latest.shown = Some((entries.to_vec(), state));
        (latest.seq, menu_changed, icon_changed)
    }

    fn newer_than(&self, ticket: u64) -> Option<(u64, Vec<Entry>, IconState)> {
        let latest = self.lock();
        if latest.seq == ticket {
            return None;
        }
        latest
            .shown
            .clone()
            .map(|(entries, state)| (latest.seq, entries, state))
    }
}

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
    rendered.begin(&entries, state);
    Ok(tray)
}

fn apply(
    app: &AppHandle,
    tray: &TrayIcon,
    entries: &[Entry],
    state: IconState,
    menu_changed: bool,
    icon_changed: bool,
) {
    if menu_changed {
        match menu(app, entries) {
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
}

pub fn update(app: &AppHandle, model: &Model, rendered: &Rendered) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let entries = model.menu_entries();
    let state = model.icon_state();
    let (mut ticket, menu_changed, icon_changed) = rendered.begin(&entries, state);
    apply(app, &tray, &entries, state, menu_changed, icon_changed);
    while let Some((newer, entries, state)) = rendered.newer_than(ticket) {
        apply(app, &tray, &entries, state, true, true);
        ticket = newer;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(label: &str) -> Vec<Entry> {
        vec![Entry::Info(label.to_owned())]
    }

    #[test]
    fn first_render_changes_everything_then_only_differences() {
        let rendered = Rendered::default();
        let (first, menu, icon) = rendered.begin(&entry("a"), IconState::Disconnected);
        assert!(menu && icon);
        let (second, menu, icon) = rendered.begin(&entry("a"), IconState::Connected);
        assert!(!menu && icon);
        assert!(second > first);
    }

    #[test]
    fn a_stale_applier_is_told_about_the_newer_state() {
        let rendered = Rendered::default();
        let (older, ..) = rendered.begin(&entry("a"), IconState::Disconnected);
        assert!(rendered.newer_than(older).is_none());
        let (newer, ..) = rendered.begin(&entry("b"), IconState::Connected);
        let (seq, entries, state) = rendered.newer_than(older).unwrap();
        assert_eq!(
            (seq, entries, state),
            (newer, entry("b"), IconState::Connected)
        );
        assert!(rendered.newer_than(newer).is_none());
    }

    #[test]
    fn the_lock_is_free_between_begin_and_apply() {
        let rendered = Rendered::default();
        rendered.begin(&entry("a"), IconState::Disconnected);
        assert!(rendered.0.try_lock().is_ok());
    }
}
