use crate::error::{Error, Result};
use crate::secret::Secret;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use wyvpn_ipc::{AuthMode, ProfileSummary, Transport};
use zeroize::Zeroizing;

fn nullable<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn lines_or_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Form {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<Form>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(Form::One(line)) => vec![line],
        Some(Form::Many(lines)) => lines,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteData {
    #[serde(default, deserialize_with = "nullable")]
    pub priority: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileHeader {
    #[serde(deserialize_with = "nullable")]
    pub version: u32,
    #[serde(deserialize_with = "nullable")]
    pub user: String,
    #[serde(deserialize_with = "nullable")]
    pub organization: String,
    #[serde(deserialize_with = "nullable")]
    pub server: String,
    #[serde(deserialize_with = "nullable")]
    pub wg: bool,
    #[serde(deserialize_with = "nullable")]
    pub user_id: String,
    #[serde(deserialize_with = "nullable")]
    pub organization_id: String,
    #[serde(deserialize_with = "nullable")]
    pub server_id: String,
    #[serde(deserialize_with = "lines_or_string")]
    pub server_public_key: Vec<String>,
    pub server_box_public_key: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub sync_hosts: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub sync_hash: String,
    #[serde(deserialize_with = "nullable")]
    pub hide_ovpn: bool,
    #[serde(deserialize_with = "nullable")]
    pub ovpn_dco: bool,
    #[serde(deserialize_with = "nullable")]
    pub dynamic_firewall: bool,
    pub geo_sort: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub force_connect: bool,
    #[serde(deserialize_with = "nullable")]
    pub device_auth: bool,
    #[serde(deserialize_with = "nullable")]
    pub sso_auth: bool,
    pub password_mode: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub push_auth: bool,
    #[serde(deserialize_with = "nullable")]
    pub push_auth_ttl: u64,
    #[serde(deserialize_with = "nullable")]
    pub disable_reconnect: bool,
    #[serde(deserialize_with = "nullable")]
    pub restrict_client: bool,
    #[serde(deserialize_with = "nullable")]
    pub token: bool,
    #[serde(deserialize_with = "nullable")]
    pub token_ttl: u64,
    #[serde(deserialize_with = "nullable")]
    pub remotes_data: BTreeMap<String, RemoteData>,
    pub pre_connect_msg: Option<String>,
    pub sync_token: Option<Secret>,
    pub sync_secret: Option<Secret>,
}

const OBJECT_ID_LEN: usize = 24;
const MAX_SYNC_HASH_LEN: usize = 64;

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl ProfileHeader {
    pub(crate) fn validate_ids(&self) -> Result<()> {
        for (value, name) in [
            (&self.organization_id, "organization_id"),
            (&self.user_id, "user_id"),
            (&self.server_id, "server_id"),
        ] {
            if !value.is_empty() && (value.len() != OBJECT_ID_LEN || !is_lower_hex(value)) {
                return Err(Error::MalformedHeader(format!(
                    "{name} must be 24 lowercase hex characters"
                )));
            }
        }
        if self.sync_hash.len() > MAX_SYNC_HASH_LEN || !is_lower_hex(&self.sync_hash) {
            return Err(Error::MalformedHeader(
                "sync_hash must be lowercase hex".into(),
            ));
        }
        Ok(())
    }

    pub fn password_mode(&self) -> PasswordMode {
        PasswordMode::parse(self.password_mode.as_deref())
    }

    pub fn auth_mode(&self) -> AuthMode {
        if self.sso_auth {
            return AuthMode::Sso;
        }
        let mode = self.password_mode();
        match (&mode.factor, mode.unrecognized, mode.pin || mode.password) {
            (Some(_), _, true) => AuthMode::PinOtp,
            (Some(_), _, false) | (None, true, _) => AuthMode::Otp,
            (None, false, true) => AuthMode::Pin,
            (None, false, false) => AuthMode::None,
        }
    }

    pub fn server_public_key_pem(&self) -> Option<String> {
        if self.server_public_key.is_empty() {
            return None;
        }
        Some(self.server_public_key.join("\n"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Factor {
    Otp,
    Duo,
    Onelogin,
    Okta,
    Yubikey,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswordMode {
    pub factor: Option<Factor>,
    pub pin: bool,
    pub password: bool,
    pub unrecognized: bool,
}

impl PasswordMode {
    pub fn parse(mode: Option<&str>) -> Self {
        let mut parsed = Self::default();
        for token in mode
            .unwrap_or_default()
            .split('_')
            .filter(|t| !t.is_empty())
        {
            match token {
                "pin" => parsed.pin = true,
                "password" => parsed.password = true,
                "otp" => parsed.set_factor(Factor::Otp),
                "duo" => parsed.set_factor(Factor::Duo),
                "onelogin" => parsed.set_factor(Factor::Onelogin),
                "okta" => parsed.set_factor(Factor::Okta),
                "yubikey" => parsed.set_factor(Factor::Yubikey),
                _ => parsed.unrecognized = true,
            }
        }
        parsed
    }

    // "duo_otp" and friends are one passcode field, so the provider token wins over "otp"
    fn set_factor(&mut self, factor: Factor) {
        if self.factor.is_none() || self.factor == Some(Factor::Otp) {
            self.factor = Some(factor);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub host: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    pub header: ProfileHeader,
    pub ovpn: Secret,
}

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile")
            .field("header", &self.header)
            .field(
                "ovpn",
                &format_args!("<{} bytes>", self.ovpn.expose().len()),
            )
            .finish()
    }
}

pub(crate) fn split_header(text: &str) -> Result<(Option<ProfileHeader>, String)> {
    let mut json = Zeroizing::new(String::new());
    let mut body = String::new();
    let mut state = HeaderState::Before;
    let text = Zeroizing::new(text.replace('\r', ""));
    for line in text.lines() {
        match state {
            HeaderState::Before if line == "#{" => {
                json.push('{');
                state = HeaderState::Inside;
            }
            HeaderState::Inside => {
                if line == "#}" {
                    json.push('}');
                    state = HeaderState::After;
                } else if let Some(rest) = line.strip_prefix('#') {
                    json.push_str(rest);
                }
            }
            _ => {
                body.push_str(line);
                body.push('\n');
            }
        }
    }
    match state {
        HeaderState::Before => Ok((None, body)),
        HeaderState::Inside => Err(Error::MalformedHeader("unterminated header block".into())),
        HeaderState::After => {
            let header: ProfileHeader = serde_json::from_str(&json)
                .map_err(|err| Error::MalformedHeader(err.to_string()))?;
            header.validate_ids()?;
            Ok((Some(header), body))
        }
    }
}

#[derive(Clone, Copy)]
enum HeaderState {
    Before,
    Inside,
    After,
}

pub(crate) fn extract_block(text: &str, tag: &str) -> Option<Zeroizing<String>> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)?;
    let end = text[start..].find(&close)? + start + close.len();
    Some(Zeroizing::new(text[start..end].to_owned()))
}

pub(crate) fn remove_block(text: &str, tag: &str) -> String {
    let Some(block) = extract_block(text, tag) else {
        return text.to_owned();
    };
    let start = text.find(block.as_str()).unwrap_or_default();
    let mut end = start + block.len();
    if text[end..].starts_with('\n') {
        end += 1;
    }
    format!("{}{}", &text[..start], &text[end..])
}

impl Profile {
    pub fn parse(text: &str) -> Result<Self> {
        let (header, ovpn) = split_header(text)?;
        let header = header.ok_or(Error::MissingHeader)?;
        Ok(Self {
            header,
            ovpn: Secret::from(ovpn),
        })
    }

    pub fn auth_mode(&self) -> AuthMode {
        self.header.auth_mode()
    }

    pub fn wireguard_available(&self) -> bool {
        self.header.wg
    }

    pub fn transports(&self) -> Vec<Transport> {
        let mut transports = vec![Transport::OpenVpn];
        if self.wireguard_available() {
            transports.push(Transport::WireGuard);
        }
        transports
    }

    pub fn device_id(&self) -> Option<&str> {
        self.setenv_value("UV_ID")
    }

    pub fn device_name(&self) -> Option<&str> {
        self.setenv_value("UV_NAME")
    }

    fn setenv_value(&self, name: &str) -> Option<&str> {
        self.ovpn.expose().lines().find_map(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some("setenv"), Some(key), Some(value)) if key == name => Some(value),
                _ => None,
            }
        })
    }

    pub fn private_key_pem(&self) -> Option<Secret> {
        let block = extract_block(self.ovpn.expose(), "key")?;
        let inner = block.strip_prefix("<key>")?.strip_suffix("</key>")?;
        Some(Secret::new(inner.trim()))
    }

    pub fn remotes(&self) -> Vec<Remote> {
        self.ovpn
            .expose()
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                if parts.next() != Some("remote") {
                    return None;
                }
                let host = parts.next()?.to_owned();
                let port = parts.next().and_then(|p| p.parse().ok());
                let protocol = parts.next().map(str::to_owned);
                Some(Remote {
                    host,
                    port,
                    protocol,
                })
            })
            .collect()
    }

    pub fn server_host(&self) -> String {
        self.header
            .sync_hosts
            .iter()
            .find_map(|url| url::Url::parse(url).ok()?.host_str().map(str::to_owned))
            .or_else(|| self.remotes().into_iter().next().map(|r| r.host))
            .unwrap_or_default()
    }

    pub fn summary(&self, id: impl Into<String>, name: impl Into<String>) -> ProfileSummary {
        ProfileSummary {
            id: id.into(),
            name: name.into(),
            server_name: self.header.server.clone(),
            server_host: self.server_host(),
            user: self.header.user.clone(),
            auth_mode: self.auth_mode(),
            transports: self.transports(),
            imported_name: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata::{self, ORG_ID, SYNC_SECRET};

    #[test]
    fn parses_valid_profile() {
        let text = testdata::ovpn(
            &[
                "\"wg\": true",
                "\"password_mode\": \"pin\"",
                "\"sync_hosts\": [\"https://vpn.example.com:9443\"]",
                "\"server_box_public_key\": \"AAAA\"",
            ],
            "",
        );
        let profile = Profile::parse(&text).unwrap();
        assert_eq!(profile.header.organization_id, ORG_ID);
        assert_eq!(profile.header.user, "alice");
        assert_eq!(profile.auth_mode(), AuthMode::Pin);
        assert!(profile.wireguard_available());
        assert_eq!(
            profile.transports(),
            vec![Transport::OpenVpn, Transport::WireGuard]
        );
        assert_eq!(
            profile.header.sync_secret.as_ref().unwrap().expose(),
            SYNC_SECRET
        );
        assert_eq!(
            profile.device_id(),
            Some("abcdef0123456789abcdef0123456789")
        );
        assert_eq!(profile.device_name(), Some("laptop"));
        assert_eq!(profile.server_host(), "vpn.example.com");
        assert!(!profile.ovpn.expose().contains("#{"));
        assert!(profile.ovpn.expose().starts_with("ignore-unknown-option"));
        assert!(
            profile
                .private_key_pem()
                .unwrap()
                .expose()
                .starts_with("-----BEGIN")
        );
        let remotes = profile.remotes();
        assert_eq!(remotes.len(), 2);
        assert_eq!(remotes[0].port, Some(1194));
    }

    #[test]
    fn ids_must_be_lowercase_hex_of_the_documented_length() {
        let bad = [
            ("user_id", "../../etc"),
            ("server_id", "5F3C1A2B4D6E8F0A1B2C3D50"),
            ("organization_id", "5f3c1a2b4d6e8f0a1b2c3d4"),
            ("user_id", "5f3c1a2b4d6e8f0a1b2c3d4%2"),
            ("sync_hash", "abc/def"),
        ];
        for (field, value) in bad {
            let from = match field {
                "user_id" => testdata::USER_ID,
                "server_id" => testdata::SERVER_ID,
                "organization_id" => ORG_ID,
                _ => testdata::SYNC_HASH,
            };
            let text = testdata::ovpn(&[], "").replace(from, value);
            assert!(
                matches!(Profile::parse(&text), Err(Error::MalformedHeader(_))),
                "{field}={value}"
            );
        }
    }

    #[test]
    fn crlf_input_is_accepted() {
        let text = testdata::ovpn(&[], "").replace('\n', "\r\n");
        assert!(Profile::parse(&text).is_ok());
    }

    #[test]
    fn missing_header_is_an_error() {
        assert!(matches!(
            Profile::parse("client\ndev tun\n"),
            Err(Error::MissingHeader)
        ));
    }

    #[test]
    fn malformed_header_is_an_error() {
        let err = Profile::parse("#{\n# \"user\": \n#}\nclient\n").unwrap_err();
        assert!(matches!(err, Error::MalformedHeader(_)));
        let err = Profile::parse("#{\n# \"user\": \"a\"\nclient\n").unwrap_err();
        assert!(matches!(err, Error::MalformedHeader(_)));
    }

    #[test]
    fn null_and_missing_fields_use_defaults() {
        let text = "#{\n# \"wg\": null,\n# \"password_mode\": null,\n# \"server_public_key\": [\"a\", \"b\"]\n#}\nclient\n";
        let profile = Profile::parse(text).unwrap();
        assert!(!profile.header.wg);
        assert_eq!(profile.auth_mode(), AuthMode::None);
        assert_eq!(profile.header.server_public_key_pem().unwrap(), "a\nb");
        assert_eq!(profile.transports(), vec![Transport::OpenVpn]);
    }

    #[test]
    fn auth_mode_derivation() {
        let cases = [
            (None, false, AuthMode::None),
            (Some("pin"), false, AuthMode::Pin),
            (Some("otp"), false, AuthMode::Otp),
            (Some("otp_pin"), false, AuthMode::PinOtp),
            (Some("duo_otp_pin"), false, AuthMode::PinOtp),
            (Some("yubikey"), false, AuthMode::Otp),
            (Some("okta_otp_password"), false, AuthMode::PinOtp),
            (None, true, AuthMode::Sso),
            (Some("pin"), true, AuthMode::Sso),
        ];
        for (mode, sso, expected) in cases {
            let header = ProfileHeader {
                password_mode: mode.map(str::to_owned),
                sso_auth: sso,
                ..ProfileHeader::default()
            };
            assert_eq!(header.auth_mode(), expected, "{mode:?} sso={sso}");
        }
    }

    #[test]
    fn debug_hides_secrets() {
        let profile = Profile::parse(&testdata::ovpn(&[], "")).unwrap();
        let rendered = format!("{profile:?}");
        assert!(!rendered.contains(SYNC_SECRET));
        assert!(!rendered.contains("BEGIN"));
    }

    #[test]
    fn summary_has_no_secrets() {
        let profile = Profile::parse(&testdata::ovpn(&["\"password_mode\": \"pin\""], "")).unwrap();
        let summary = profile.summary("p1", "Office");
        assert_eq!(summary.server_name, "Gateway");
        assert_eq!(summary.auth_mode, AuthMode::Pin);
        assert_eq!(summary.server_host, "vpn.example.com");
    }
}
