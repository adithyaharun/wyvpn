use std::io::BufRead;
use std::time::Duration;

use anyhow::{Context, anyhow, bail, ensure};
use wyvpn_ipc::{
    AuthMode, ConnectionState, ErrorBody, ErrorCode, Event, Request, Sensitive, Transport,
};
use zeroize::Zeroizing;

use crate::client::Client;
use crate::output::sanitize;
use crate::view::{self, StatusView};

async fn read_pin(from_stdin: bool) -> anyhow::Result<Zeroizing<String>> {
    let mut pin = tokio::task::spawn_blocking(move || -> anyhow::Result<Zeroizing<String>> {
        if from_stdin {
            let mut line = Zeroizing::new(String::with_capacity(128));
            std::io::stdin().lock().read_line(&mut line)?;
            Ok(line)
        } else {
            rpassword::prompt_password("PIN: ")
                .map(Zeroizing::new)
                .context("cannot prompt for the PIN on a terminal; use --pin-stdin")
        }
    })
    .await??;
    let trimmed = pin.trim_end_matches(['\r', '\n']).len();
    pin.truncate(trimmed);
    ensure!(!pin.is_empty(), "PIN is empty");
    Ok(pin)
}

pub enum Pin {
    Prompt { from_stdin: bool },
    Unavailable,
}

const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const INTERRUPTED_EXIT: i32 = 130;

fn failure(error: Option<ErrorBody>) -> Ended {
    Ended(match error {
        Some(error) if error.code == ErrorCode::AuthFailed => "the PIN was rejected".to_owned(),
        Some(error) => sanitize(&error.message),
        None => "connection failed".to_owned(),
    })
}

async fn status_of(client: &mut Client, profile_id: &str) -> anyhow::Result<StatusView> {
    view::fetch_status(client)
        .await?
        .into_iter()
        .find(|view| view.status.profile_id == profile_id)
        .context("the daemon reported no status for the profile")
}

pub async fn run(
    client: &mut Client,
    profile_id: String,
    transport: Option<Transport>,
    pin: Pin,
) -> anyhow::Result<StatusView> {
    client.call(Request::Subscribe).await?;
    client
        .call(Request::Connect {
            profile_id: profile_id.clone(),
            transport,
            auto_reconnect: None,
        })
        .await?;
    let (result, interrupted) = tokio::select! {
        result = drive(client, &profile_id, pin) => (result, false),
        _ = tokio::signal::ctrl_c() => (Err(anyhow!("interrupted")), true),
    };
    if result.as_ref().is_err_and(|err| !err.is::<Ended>()) {
        let _ = tokio::time::timeout(
            CLEANUP_TIMEOUT,
            client.call(Request::Disconnect {
                profile_id: profile_id.clone(),
            }),
        )
        .await;
    }
    if interrupted {
        eprintln!("interrupted");
        std::process::exit(INTERRUPTED_EXIT);
    }
    result
}

#[derive(Debug)]
struct Ended(String);

impl std::fmt::Display for Ended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Ended {}

async fn drive(client: &mut Client, profile_id: &str, pin: Pin) -> anyhow::Result<StatusView> {
    let mut announced = false;
    loop {
        match client.next_event().await? {
            Event::CredentialsRequired {
                profile_id: id,
                mode,
            } if id == profile_id => {
                ensure!(
                    mode == AuthMode::Pin,
                    "unsupported credentials mode {mode:?}"
                );
                let Pin::Prompt { from_stdin } = pin else {
                    bail!(
                        "the profile needs a PIN; connect it with `wyvpn-cli connect` or the app"
                    );
                };
                let mut pin = read_pin(from_stdin).await?;
                client
                    .call(Request::SubmitCredentials {
                        profile_id: profile_id.to_owned(),
                        pin: Some(Sensitive::new(std::mem::take(&mut *pin))),
                        otp: None,
                    })
                    .await?;
            }
            Event::StateChanged {
                profile_id: id,
                state,
                error,
            } if id == profile_id => match state {
                ConnectionState::Connected => return status_of(client, profile_id).await,
                ConnectionState::Error => return Err(failure(error).into()),
                ConnectionState::Disconnected => {
                    return Err(Ended("connection ended".into()).into());
                }
                ConnectionState::Connecting => {
                    if !announced {
                        eprintln!("connecting...");
                        announced = true;
                    }
                }
                ConnectionState::Disconnecting => {}
            },
            _ => {}
        }
    }
}

pub async fn disconnect(client: &mut Client, profile_id: &str) -> anyhow::Result<()> {
    client.call(Request::Subscribe).await?;
    let current = view::fetch_status(client)
        .await?
        .into_iter()
        .find(|view| view.status.profile_id == profile_id);
    if current.is_some_and(|view| view.status.state == ConnectionState::Disconnected) {
        return Ok(());
    }
    client
        .call(Request::Disconnect {
            profile_id: profile_id.to_owned(),
        })
        .await?;
    tokio::time::timeout(DISCONNECT_TIMEOUT, async {
        loop {
            if let Event::StateChanged {
                profile_id: id,
                state,
                error,
            } = client.next_event().await?
                && id == profile_id
            {
                match state {
                    ConnectionState::Disconnected => return Ok(()),
                    ConnectionState::Error => return Err(failure(error).into()),
                    _ => {}
                }
            }
        }
    })
    .await
    .map_err(|_| anyhow!("timed out waiting for the disconnect"))?
}
