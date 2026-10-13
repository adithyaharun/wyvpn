use tauri::AppHandle;
use tauri_plugin_dialog::{
    DialogExt, MessageDialogButtons, MessageDialogKind, MessageDialogResult,
};
use wyvpn_ipc::Request;

use crate::error::CmdError;
use crate::{service, shell};

const TITLE: &str = "WyVPN";
const CLI_PATH: &str = "/usr/local/bin/wyvpn-cli";
const KEEP: &str = "Keep Profiles";
const DELETE: &str = "Delete Profiles and Secrets";
const CANCEL: &str = "Cancel";
const CONFIRM_DELETE: &str = "Delete Everything";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Choice {
    Keep,
    Delete,
    Cancel,
}

fn choice(result: &MessageDialogResult) -> Choice {
    match result {
        MessageDialogResult::Yes => Choice::Keep,
        MessageDialogResult::No => Choice::Delete,
        MessageDialogResult::Custom(label) if label == KEEP => Choice::Keep,
        MessageDialogResult::Custom(label) if label == DELETE => Choice::Delete,
        _ => Choice::Cancel,
    }
}

fn confirmed(result: &MessageDialogResult) -> bool {
    match result {
        MessageDialogResult::Ok => true,
        MessageDialogResult::Custom(label) => label == CONFIRM_DELETE,
        _ => false,
    }
}

fn install_cli_outcome(result: &Result<(), CmdError>) -> (MessageDialogKind, String) {
    match result {
        Ok(()) => (
            MessageDialogKind::Info,
            format!(
                "The command line tool is installed at {CLI_PATH}. Open a new terminal and run wyvpn-cli --version."
            ),
        ),
        Err(error) => (
            MessageDialogKind::Error,
            match error.code.as_str() {
                "permission_denied" => {
                    "Only administrators can install the command line tool.".to_owned()
                }
                "already_exists" => {
                    format!("Something else already exists at {CLI_PATH}. Remove it and try again.")
                }
                _ => format!(
                    "The command line tool could not be installed. {}",
                    error.message
                ),
            },
        ),
    }
}

fn say(app: &AppHandle, kind: MessageDialogKind, message: impl Into<String>) {
    app.dialog()
        .message(message)
        .title(TITLE)
        .kind(kind)
        .show(|_| {});
}

async fn ask(app: &AppHandle, message: &str, buttons: MessageDialogButtons) -> MessageDialogResult {
    let dialog = app
        .dialog()
        .message(message)
        .title(TITLE)
        .kind(MessageDialogKind::Warning)
        .buttons(buttons);
    tauri::async_runtime::spawn_blocking(move || dialog.blocking_show_with_result())
        .await
        .unwrap_or_default()
}

pub fn install_cli(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let bridge = tauri::Manager::state::<shell::Ctx>(&app).bridge.clone();
        let result = bridge.ok(Request::InstallCli).await;
        let (kind, message) = install_cli_outcome(&result);
        say(&app, kind, message);
    });
}

pub fn uninstall(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move { run_uninstall(app).await });
}

async fn run_uninstall(app: AppHandle) {
    let first = ask(
        &app,
        "Uninstall WyVPN? This stops the background service and removes the command line tool. Choose whether to keep your stored profiles and secrets.",
        MessageDialogButtons::YesNoCancelCustom(KEEP.into(), DELETE.into(), CANCEL.into()),
    )
    .await;
    let remove_data = match choice(&first) {
        Choice::Cancel => return,
        Choice::Keep => false,
        Choice::Delete => {
            let second = ask(
                &app,
                "This permanently deletes all profiles and secrets stored by WyVPN. It cannot be undone.",
                MessageDialogButtons::OkCancelCustom(CONFIRM_DELETE.into(), CANCEL.into()),
            )
            .await;
            if !confirmed(&second) {
                return;
            }
            true
        }
    };
    let bridge = tauri::Manager::state::<shell::Ctx>(&app).bridge.clone();
    if let Err(error) = bridge.ok(Request::Uninstall { remove_data }).await {
        say(
            &app,
            MessageDialogKind::Error,
            format!("WyVPN could not be uninstalled. {}", error.message),
        );
        return;
    }
    if service::applicable()
        && let Err(message) = service::unregister()
    {
        say(
            &app,
            MessageDialogKind::Error,
            format!("The background service could not be removed. {message}"),
        );
        return;
    }
    let done = app
        .dialog()
        .message("WyVPN has been uninstalled. Move WyVPN.app to the Trash to finish.")
        .title(TITLE)
        .kind(MessageDialogKind::Info);
    let _ = tauri::async_runtime::spawn_blocking(move || done.blocking_show()).await;
    app.exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialog_results_map_to_choices() {
        assert_eq!(choice(&MessageDialogResult::Yes), Choice::Keep);
        assert_eq!(choice(&MessageDialogResult::No), Choice::Delete);
        assert_eq!(
            choice(&MessageDialogResult::Custom(KEEP.into())),
            Choice::Keep
        );
        assert_eq!(
            choice(&MessageDialogResult::Custom(DELETE.into())),
            Choice::Delete
        );
        assert_eq!(
            choice(&MessageDialogResult::Custom(CANCEL.into())),
            Choice::Cancel
        );
        assert_eq!(choice(&MessageDialogResult::Cancel), Choice::Cancel);
        assert!(confirmed(&MessageDialogResult::Custom(
            CONFIRM_DELETE.into()
        )));
        assert!(!confirmed(&MessageDialogResult::Custom(CANCEL.into())));
        assert!(!confirmed(&MessageDialogResult::Cancel));
    }

    #[test]
    fn install_errors_get_specific_messages() {
        let (_, ok) = install_cli_outcome(&Ok(()));
        assert!(ok.contains(CLI_PATH));
        let (kind, denied) = install_cli_outcome(&Err(CmdError::new("permission_denied", "x")));
        assert_eq!(kind, MessageDialogKind::Error);
        assert_eq!(
            denied,
            "Only administrators can install the command line tool."
        );
        let (_, exists) = install_cli_outcome(&Err(CmdError::new("already_exists", "x")));
        assert!(exists.contains(CLI_PATH));
        let (_, other) = install_cli_outcome(&Err(CmdError::unavailable("down")));
        assert!(other.contains("down"));
    }
}
