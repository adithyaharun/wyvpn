use std::collections::HashSet;
use std::fmt::Write;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use wyvpn_core::auth::password_for;
use wyvpn_core::tls::Pins;
use wyvpn_core::{Error, NamedProfile, Profile, import, read_profiles};
use wyvpn_ipc::{
    AuthMode, ErrorBody, ErrorCode, Event, ImportSource, LogSource, MAX_IMPORT_BYTES, Outcome,
    Request, Response, Sensitive, Transport,
};
use zeroize::Zeroizing;

use crate::admin::{self, Peer};
use crate::session::launch_request;
use crate::state::{State, StoredProfile};
use crate::storage::valid_id;

const MAX_NAME_CHARS: usize = 64;
const STOP_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn dispatch(state: &Arc<State>, peer: &Peer, request: Request) -> Outcome {
    let result = match request {
        Request::ListProfiles => Ok(Response::Profiles {
            profiles: state.source.summaries(),
        }),
        Request::Status => Ok(Response::Status {
            statuses: state.statuses(),
        }),
        Request::Subscribe => Ok(Response::Subscribed),
        Request::Connect {
            profile_id,
            transport,
            auto_reconnect,
        } => connect(state, &profile_id, transport, auto_reconnect),
        Request::Disconnect { profile_id } => disconnect(state, &profile_id),
        Request::SubmitCredentials {
            profile_id,
            pin,
            otp,
        } => submit_credentials(state, &profile_id, pin, otp),
        Request::ImportProfile { source, replace } => import_profile(state, source, replace).await,
        Request::RemoveProfile { profile_id } => remove_profile(state, &profile_id),
        Request::RenameProfile { profile_id, name } => rename_profile(state, &profile_id, &name),
        Request::SessionLog => {
            let (profile_id, lines) = state.session_log();
            Ok(Response::Log { profile_id, lines })
        }
        Request::Hello {
            client_version,
            protocol,
        } => Ok(hello(&client_version, protocol)),
        Request::InstallCli => install_cli(state, peer),
        Request::Uninstall { remove_data } => uninstall(state, peer, remove_data).await,
    };
    match result {
        Ok(response) => Outcome::Result(response),
        Err(error) => Outcome::Error(error),
    }
}

fn hello(client_version: &str, protocol: u32) -> Response {
    if protocol != wyvpn_ipc::PROTOCOL_VERSION {
        tracing::warn!(
            client_version,
            client_protocol = protocol,
            protocol = wyvpn_ipc::PROTOCOL_VERSION,
            "client speaks a different protocol"
        );
    }
    Response::Hello {
        daemon_version: wyvpn_ipc::VERSION.to_owned(),
        protocol: wyvpn_ipc::PROTOCOL_VERSION,
    }
}

fn require_admin(state: &State, peer: &Peer) -> Result<(), ErrorBody> {
    if !state.admin.enabled {
        return Err(ErrorBody::new(
            ErrorCode::NotImplemented,
            "not supported on this platform",
        ));
    }
    if peer.is_admin(&state.admin.group) {
        Ok(())
    } else {
        Err(ErrorBody::new(
            ErrorCode::PermissionDenied,
            "administrator rights are required",
        ))
    }
}

fn install_cli(state: &State, peer: &Peer) -> Reply {
    require_admin(state, peer)?;
    admin::install_cli(&state.admin)?;
    Ok(Response::Ok)
}

async fn uninstall(state: &State, peer: &Peer, remove_data: bool) -> Reply {
    require_admin(state, peer)?;
    admin::remove_cli_link(&state.admin)?;
    if remove_data {
        let ids: Vec<String> = state
            .source
            .summaries()
            .into_iter()
            .map(|summary| summary.id)
            .collect();
        for id in &ids {
            state.sessions.stop_and_wait(id, STOP_TIMEOUT).await;
        }
        let _writes = state.lock_profiles();
        #[cfg(unix)]
        if let Err(err) = crate::dns::Dns::new(&state.admin.data_dir).restore() {
            tracing::warn!(%err, "cannot restore dns before wiping data");
        }
        admin::wipe_data(&state.admin.data_dir)?;
        for id in &ids {
            state.forget(id);
        }
        state.publish(Event::ProfilesChanged);
    }
    Ok(Response::Ok)
}

type Reply = Result<Response, ErrorBody>;

fn invalid(message: impl Into<String>) -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidRequest, message)
}

fn storage_error(err: &io::Error) -> ErrorBody {
    tracing::error!(%err, "profile storage failure");
    ErrorBody::new(ErrorCode::Internal, "profile storage failure")
}

fn not_found(profile_id: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::NotFound, format!("no profile {profile_id}"))
}

pub fn core_error(err: &Error) -> ErrorBody {
    let code = match err {
        Error::Unsupported(_) => ErrorCode::UnsupportedAuth,
        Error::MissingHeader
        | Error::MalformedHeader(_)
        | Error::MissingField(_)
        | Error::Archive(_)
        | Error::TooLarge(_)
        | Error::NoProfiles
        | Error::InvalidUri(_)
        | Error::InsecureScheme
        | Error::MissingCredential(_)
        | Error::PasswordTooLong
        | Error::InvalidConfig(_) => ErrorCode::InvalidRequest,
        Error::Http(_)
        | Error::Tls(_)
        | Error::CertificateChanged { .. }
        | Error::Status(_)
        | Error::NotFound
        | Error::Forbidden
        | Error::ResponseSignature
        | Error::InvalidResponse(_)
        | Error::NoSyncHosts
        | Error::Decrypt
        | Error::Rejected { .. } => ErrorCode::Server,
        Error::NonceTooLong | Error::RequestTooLong | Error::InvalidKey(_) | Error::Encrypt => {
            ErrorCode::Internal
        }
    };
    let message = match err {
        Error::Http(inner) if inner.is_timeout() => "request to the server timed out".to_owned(),
        Error::Http(inner) if inner.is_connect() => "cannot connect to the server".to_owned(),
        Error::Http(_) => "request to the server failed".to_owned(),
        other => other.to_string(),
    };
    ErrorBody::new(code, message)
}

fn load(state: &State, profile_id: &str) -> Result<StoredProfile, ErrorBody> {
    if !valid_id(profile_id) {
        return Err(not_found(profile_id));
    }
    state
        .source
        .load(profile_id)
        .map_err(|err| storage_error(&err))?
        .ok_or_else(|| not_found(profile_id))
}

fn pick_transport(profile: &Profile, requested: Option<Transport>) -> Result<Transport, ErrorBody> {
    match requested {
        Some(Transport::WireGuard) if !profile.wireguard_available() => {
            Err(invalid("profile does not support wireguard"))
        }
        Some(transport) => Ok(transport),
        None => Ok(Transport::OpenVpn),
    }
}

fn connect(
    state: &Arc<State>,
    profile_id: &str,
    requested: Option<Transport>,
    auto_reconnect: Option<bool>,
) -> Reply {
    let stored = load(state, profile_id)?;
    let transport = pick_transport(&stored.profile, requested)?;

    let needs_pin = match password_for(&stored.profile.header, None, transport) {
        Ok(_) => false,
        Err(Error::MissingCredential(_)) => true,
        Err(err) => return Err(core_error(&err)),
    };

    let token = state
        .sessions
        .claim(profile_id, transport, auto_reconnect)?;
    state.begin_connecting(profile_id, transport);
    state.clear_log(profile_id);
    state.log(
        LogSource::Daemon,
        &format!("connecting to {} over {transport:?}", stored.summary().name),
    );
    if needs_pin {
        state.log(LogSource::Daemon, "waiting for credentials");
        state.publish(Event::CredentialsRequired {
            profile_id: profile_id.to_owned(),
            mode: stored.profile.auth_mode(),
        });
        state.sessions.expire_credentials(state, token);
        return Ok(Response::Ok);
    }
    start_tunnel(state, stored, transport, None)
}

fn submit_credentials(
    state: &Arc<State>,
    profile_id: &str,
    pin: Option<Sensitive>,
    _otp: Option<Sensitive>,
) -> Reply {
    let transport = state.sessions.awaiting(profile_id).ok_or_else(|| {
        ErrorBody::new(
            ErrorCode::InvalidState,
            "profile is not waiting for credentials",
        )
    })?;
    let stored = match load(state, profile_id) {
        Ok(stored) => stored,
        Err(err) => {
            abandon(state, profile_id);
            return Err(err);
        }
    };
    if stored.profile.auth_mode() == AuthMode::Pin && pin.as_ref().is_none_or(Sensitive::is_empty) {
        return Err(invalid("a PIN is required"));
    }
    start_tunnel(
        state,
        stored,
        transport,
        pin.as_ref()
            .map(|pin| Zeroizing::new(pin.expose().to_owned())),
    )
}

fn abandon(state: &State, profile_id: &str) {
    state.sessions.release(profile_id);
    state.reset(profile_id);
}

fn start_tunnel(
    state: &Arc<State>,
    stored: StoredProfile,
    transport: Transport,
    pin: Option<Zeroizing<String>>,
) -> Reply {
    let profile_id = stored.id.clone();
    let started = launch_request(&stored, transport, pin.as_ref().map(|pin| pin.as_str()))
        .map(drop)
        .and_then(|()| state.sessions.start(state, stored, pin));
    match started {
        Ok(()) => Ok(Response::Ok),
        Err(err) => {
            abandon(state, &profile_id);
            Err(err)
        }
    }
}

fn disconnect(state: &State, profile_id: &str) -> Reply {
    load(state, profile_id)?;
    if !state.sessions.stop(profile_id) {
        state.reset(profile_id);
    }
    Ok(Response::Ok)
}

fn remove_profile(state: &State, profile_id: &str) -> Reply {
    let _writes = state.lock_profiles();
    let removed = valid_id(profile_id)
        && state
            .source
            .remove(profile_id)
            .map_err(|err| storage_error(&err))?;
    if !removed {
        return Err(not_found(profile_id));
    }
    state.sessions.stop(profile_id);
    state.forget(profile_id);
    state.publish(Event::ProfilesChanged);
    Ok(Response::Ok)
}

fn validate_display_name(name: &str) -> Result<Option<String>, ErrorBody> {
    let name = name.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(invalid(format!(
            "name is longer than {MAX_NAME_CHARS} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid("name contains control characters"));
    }
    Ok(Some(name.to_owned()))
}

fn rename_profile(state: &State, profile_id: &str, name: &str) -> Reply {
    let display_name = validate_display_name(name)?;
    let _writes = state.lock_profiles();
    let mut stored = load(state, profile_id)?;
    stored.display_name = display_name.filter(|display| *display != stored.name);
    state
        .source
        .save(&stored)
        .map_err(|err| storage_error(&err))?;
    state.publish(Event::ProfilesChanged);
    Ok(Response::Profile {
        profile: stored.summary(),
    })
}

fn read_source(file: &str, data: &Sensitive) -> Result<Vec<NamedProfile>, ErrorBody> {
    if data.expose().len() > MAX_IMPORT_BYTES.div_ceil(3) * 4 {
        return Err(invalid("file is too large"));
    }
    let bytes = data
        .decode_base64()
        .ok_or_else(|| invalid("file data is not valid base64"))?;
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(invalid("file is too large"));
    }
    let name = Path::new(file).file_name().map_or_else(
        || "profile".to_owned(),
        |n| n.to_string_lossy().into_owned(),
    );
    read_profiles(&name, &bytes).map_err(|e| core_error(&e))
}

async fn import_profile(state: &State, source: ImportSource, replace: bool) -> Reply {
    let (named, tls_pins) = match source {
        ImportSource::File { name, data } => (read_source(&name, &data)?, Pins::new()),
        ImportSource::Uri { uri } => {
            let imported = import::import_uri(uri.expose())
                .await
                .map_err(|e| core_error(&e))?;
            (imported.profiles, imported.pins)
        }
    };

    let _writes = state.lock_profiles();
    let mut pending = Vec::with_capacity(named.len());
    let mut seen = HashSet::new();
    for NamedProfile { name, profile } in named {
        let mut stored = StoredProfile {
            id: profile_id(&name, &profile),
            name: display_name(&name),
            display_name: None,
            profile,
            tls_pins: tls_pins.clone(),
        };
        if !seen.insert(stored.id.clone()) {
            return Err(invalid("the import contains the same profile twice"));
        }
        let existing = state
            .source
            .load(&stored.id)
            .map_err(|err| storage_error(&err))?;
        if !replace && existing.is_some() {
            return Err(ErrorBody::new(
                ErrorCode::AlreadyExists,
                format!(
                    "profile {} already exists; use replace to overwrite",
                    stored.name
                ),
            ));
        }
        stored.display_name = existing.and_then(|existing| existing.display_name);
        pending.push(stored);
    }

    let mut summaries = Vec::with_capacity(pending.len());
    for stored in &pending {
        state
            .source
            .save(stored)
            .map_err(|err| storage_error(&err))?;
        summaries.push(stored.summary());
    }
    if !summaries.is_empty() {
        state.publish(Event::ProfilesChanged);
    }
    Ok(Response::Imported {
        profiles: summaries,
    })
}

fn display_name(name: &str) -> String {
    Path::new(name).file_stem().map_or_else(
        || name.to_owned(),
        |stem| stem.to_string_lossy().into_owned(),
    )
}

fn profile_id(name: &str, profile: &Profile) -> String {
    let header = &profile.header;
    let seed = if header.user_id.is_empty() || header.server_id.is_empty() {
        format!(
            "{name}:{}:{}:{}",
            header.organization, header.server, header.user
        )
    } else {
        format!("{}:{}", header.user_id, header.server_id)
    };
    Sha256::digest(seed)
        .iter()
        .take(16)
        .fold(String::new(), |mut id, byte| {
            let _ = write!(id, "{byte:02x}");
            id
        })
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use super::*;
    use crate::admin::AdminConfig;
    use crate::state::MemoryProfiles;
    use crate::testdata;

    #[test]
    fn unrequested_transport_defaults_to_openvpn() {
        let profile = Profile::parse(testdata::PIN_PROFILE).unwrap();
        assert!(profile.wireguard_available());
        assert_eq!(pick_transport(&profile, None).unwrap(), Transport::OpenVpn);
        assert_eq!(
            pick_transport(&profile, Some(Transport::WireGuard)).unwrap(),
            Transport::WireGuard
        );
    }

    #[test]
    fn wireguard_is_refused_for_profiles_without_it() {
        let text = testdata::ovpn(&[("\"wg\": true", "\"wg\": false")]);
        let profile = Profile::parse(&text).unwrap();
        assert!(!profile.wireguard_available());
        assert_eq!(pick_transport(&profile, None).unwrap(), Transport::OpenVpn);
        assert_eq!(
            pick_transport(&profile, Some(Transport::OpenVpn)).unwrap(),
            Transport::OpenVpn
        );
        let err = pick_transport(&profile, Some(Transport::WireGuard)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        state: Arc<State>,
        config: AdminConfig,
    }

    fn fixture(enabled: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let cli = dir.path().join("wyvpn-cli");
        fs::write(&cli, b"#!/bin/sh\n").unwrap();
        let data = dir.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::write(data.join("p.json"), b"{}").unwrap();
        let config = AdminConfig {
            enabled,
            group: "admin".to_owned(),
            bin_dir: dir.path().join("bin"),
            bundled_cli: cli,
            data_dir: data,
        };
        let state = Arc::new(State::new(MemoryProfiles::default()).with_admin(config.clone()));
        Fixture {
            _dir: dir,
            state,
            config,
        }
    }

    fn error_code(outcome: Outcome) -> ErrorCode {
        match outcome {
            Outcome::Error(err) => err.code,
            Outcome::Result(other) => panic!("expected an error, got {other:?}"),
        }
    }

    const ADMIN: Peer = Peer::Fixed { admin: true };
    const USER: Peer = Peer::Fixed { admin: false };

    #[tokio::test]
    async fn hello_reports_daemon_versions() {
        let fx = fixture(true);
        let reply = dispatch(&fx.state, &USER, Request::hello()).await;
        let Outcome::Result(Response::Hello {
            daemon_version,
            protocol,
        }) = reply
        else {
            panic!("unexpected reply");
        };
        assert_eq!(daemon_version, wyvpn_ipc::VERSION);
        assert_eq!(protocol, wyvpn_ipc::PROTOCOL_VERSION);

        let mismatch = Request::Hello {
            client_version: "0.0.1".into(),
            protocol: wyvpn_ipc::PROTOCOL_VERSION + 1,
        };
        assert!(matches!(
            dispatch(&fx.state, &USER, mismatch).await,
            Outcome::Result(Response::Hello { .. })
        ));
    }

    #[tokio::test]
    async fn non_admin_is_denied() {
        let fx = fixture(true);
        let code = error_code(dispatch(&fx.state, &USER, Request::InstallCli).await);
        assert_eq!(code, ErrorCode::PermissionDenied);
        assert!(fs::symlink_metadata(fx.config.link_path()).is_err());

        let request = Request::Uninstall { remove_data: true };
        let code = error_code(dispatch(&fx.state, &Peer::Unknown, request).await);
        assert_eq!(code, ErrorCode::PermissionDenied);
        assert!(fx.config.data_dir.join("p.json").exists());
    }

    #[tokio::test]
    async fn admin_installs_and_uninstalls() {
        let fx = fixture(true);
        let reply = dispatch(&fx.state, &ADMIN, Request::InstallCli).await;
        assert!(matches!(reply, Outcome::Result(Response::Ok)));
        assert_eq!(
            fs::read_link(fx.config.link_path()).unwrap(),
            fx.config.bundled_cli
        );

        let keep = Request::Uninstall { remove_data: false };
        assert!(matches!(
            dispatch(&fx.state, &ADMIN, keep).await,
            Outcome::Result(Response::Ok)
        ));
        assert!(fs::symlink_metadata(fx.config.link_path()).is_err());
        assert!(fx.config.data_dir.join("p.json").exists());

        let wipe = Request::Uninstall { remove_data: true };
        assert!(matches!(
            dispatch(&fx.state, &ADMIN, wipe).await,
            Outcome::Result(Response::Ok)
        ));
        assert_eq!(fs::read_dir(&fx.config.data_dir).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn unsupported_platform_is_not_implemented() {
        let fx = fixture(false);
        let code = error_code(dispatch(&fx.state, &ADMIN, Request::InstallCli).await);
        assert_eq!(code, ErrorCode::NotImplemented);
    }
}
