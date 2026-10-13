use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use wyvpn_ipc::{ConnectionStatus, ProfileSummary, Request, Response};

use crate::client::Client;
use crate::output::{sanitize_profile, sanitize_status};

#[derive(Debug, Clone, Serialize)]
pub struct StatusView {
    #[serde(flatten)]
    pub status: ConnectionStatus,
    pub uptime_secs: Option<u64>,
}

pub fn join_status(
    profiles: &[ProfileSummary],
    statuses: Vec<ConnectionStatus>,
    now: u64,
) -> Vec<StatusView> {
    statuses
        .into_iter()
        .map(|mut status| {
            if status.profile_name.is_empty() {
                status.profile_name = profiles
                    .iter()
                    .find(|profile| profile.id == status.profile_id)
                    .map_or_else(|| status.profile_id.clone(), |profile| profile.name.clone());
            }
            StatusView {
                uptime_secs: status
                    .connected_since
                    .map(|since| now.saturating_sub(since)),
                status,
            }
        })
        .collect()
}

pub async fn fetch_profiles(client: &mut Client) -> anyhow::Result<Vec<ProfileSummary>> {
    match client.call(Request::ListProfiles).await? {
        Response::Profiles { profiles } => Ok(profiles.into_iter().map(sanitize_profile).collect()),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}

pub async fn fetch_status(client: &mut Client) -> anyhow::Result<Vec<StatusView>> {
    let profiles = fetch_profiles(client).await?;
    match client.call(Request::Status).await? {
        Response::Status { statuses } => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let statuses = statuses.into_iter().map(sanitize_status).collect();
            Ok(join_status(&profiles, statuses, now))
        }
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}

pub fn resolve_profile(profiles: &[ProfileSummary], wanted: &str) -> anyhow::Result<String> {
    if profiles.iter().any(|profile| profile.id == wanted) {
        return Ok(wanted.to_owned());
    }
    let by_name = |field: fn(&ProfileSummary) -> Option<&str>| -> Vec<&str> {
        profiles
            .iter()
            .filter(|profile| field(profile) == Some(wanted))
            .map(|profile| profile.id.as_str())
            .collect()
    };
    for ids in [
        by_name(|profile| Some(profile.name.as_str())),
        by_name(|profile| profile.imported_name.as_deref()),
    ] {
        match ids.as_slice() {
            [] => {}
            [id] => return Ok((*id).to_owned()),
            _ => anyhow::bail!(
                "ambiguous profile name {wanted:?}, matches ids: {}",
                ids.join(", ")
            ),
        }
    }
    Ok(wanted.to_owned())
}
