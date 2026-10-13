use crate::error::{Error, Result, Unsupported};
use crate::profile::{Profile, ProfileHeader};
use crate::rng;
use crate::secret::Secret;
use crate::sign::{generate_nonce, unix_now};
use crate::vendor::{VENDOR_DEFAULT_USERNAME, VENDOR_VERSION_ENV};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};
use wyvpn_ipc::Transport;
use zeroize::Zeroizing;

const MAX_BOX_PLAINTEXT: usize = 368;
const AUTH_TOKEN_LEN: usize = 16;
const RSA_MARKER: &str = "<%=RSA_ENCRYPTED=%>";

#[derive(Debug, Clone)]
pub struct OpenVpnCredentials {
    pub username: String,
    pub password: Secret,
}

pub(crate) fn decode_box_public_key(encoded: &str) -> Result<PublicKey> {
    let bytes = STANDARD
        .decode(encoded.trim())
        .map_err(|_| Error::InvalidKey("server box public key is not base64"))?;
    PublicKey::from_slice(&bytes).map_err(|_| Error::InvalidKey("server box public key length"))
}

pub fn password_for(
    header: &ProfileHeader,
    pin: Option<&str>,
    transport: Transport,
) -> Result<Secret> {
    if header.sso_auth {
        return Err(Unsupported::Sso.into());
    }
    if header.device_auth {
        return Err(Unsupported::DeviceAuth.into());
    }
    let mode = header.password_mode();
    if mode.unrecognized {
        return Err(
            Unsupported::UnknownMode(header.password_mode.clone().unwrap_or_default()).into(),
        );
    }
    if mode.factor.is_some() {
        return Err(if mode.pin || mode.password {
            Unsupported::PinOtp
        } else {
            Unsupported::Otp
        }
        .into());
    }
    if mode.password {
        return Err(Unsupported::Password.into());
    }
    if transport == Transport::OpenVpn && header.dynamic_firewall {
        return Err(Unsupported::DynamicFirewall.into());
    }
    if mode.pin {
        return match pin {
            Some(pin) if !pin.is_empty() => Ok(Secret::new(pin)),
            _ => Err(Error::MissingCredential("pin")),
        };
    }
    Ok(Secret::default())
}

pub(crate) fn resolve_auth_token(token: Option<&str>) -> Result<Zeroizing<String>> {
    match token {
        Some(token) if token.len() == AUTH_TOKEN_LEN && token.is_ascii() => {
            Ok(Zeroizing::new(token.to_owned()))
        }
        Some(_) => Err(Error::InvalidKey("auth token must be 16 ASCII characters")),
        None => Ok(Zeroizing::new(rng::alphanumeric(AUTH_TOKEN_LEN))),
    }
}

pub fn openvpn_credentials(
    profile: &Profile,
    pin: Option<&str>,
    auth_token: Option<&str>,
) -> Result<Option<OpenVpnCredentials>> {
    let header = &profile.header;
    let password = password_for(header, pin, Transport::OpenVpn)?;
    if !header.password_mode().pin {
        return Ok(None);
    }
    let token = resolve_auth_token(auth_token)?;
    let timestamp = unix_now();

    if let Some(box_key) = header.server_box_public_key.as_deref() {
        let plaintext = Zeroizing::new(format!("{}{timestamp:010}{}", *token, password.expose()));
        if plaintext.len() > MAX_BOX_PLAINTEXT {
            return Err(Error::PasswordTooLong);
        }
        let (username, cipher) =
            seal_with_derived_nonce(&decode_box_public_key(box_key)?, plaintext.as_bytes())?;
        return Ok(Some(OpenVpnCredentials {
            username,
            password: Secret::new(format!("$x${cipher}")),
        }));
    }

    if let Some(pem) = header.server_public_key_pem() {
        let envelope = RsaEnvelope {
            token: &token,
            password: password.expose(),
            nonce: generate_nonce(),
            timestamp,
        };
        let body = Zeroizing::new(serde_json::to_vec(&envelope).map_err(|_| Error::Encrypt)?);
        let key = parse_rsa_public_key(&pem)?;
        let cipher = key
            .encrypt(
                &mut OsRng,
                Oaep::new_with_mgf_hash::<Sha512, Sha512>(),
                &body,
            )
            .map_err(|_| Error::PasswordTooLong)?;
        return Ok(Some(OpenVpnCredentials {
            username: VENDOR_DEFAULT_USERNAME.to_owned(),
            password: Secret::new(format!("{RSA_MARKER}{}", STANDARD.encode(cipher))),
        }));
    }

    Ok(Some(OpenVpnCredentials {
        username: VENDOR_DEFAULT_USERNAME.to_owned(),
        password,
    }))
}

pub fn connection_token_credentials(
    profile: &Profile,
    connection_token: &Secret,
) -> Result<OpenVpnCredentials> {
    let box_key = profile
        .header
        .server_box_public_key
        .as_deref()
        .ok_or(Error::MissingField("server_box_public_key"))?;
    let (username, cipher) = seal_with_derived_nonce(
        &decode_box_public_key(box_key)?,
        connection_token.expose().as_bytes(),
    )?;
    Ok(OpenVpnCredentials {
        username,
        password: Secret::new(format!("$f${cipher}")),
    })
}

pub fn version_setenv_line(client_version: &str) -> String {
    format!("setenv {VENDOR_VERSION_ENV} {client_version}")
}

#[derive(Serialize)]
struct RsaEnvelope<'a> {
    token: &'a str,
    password: &'a str,
    nonce: String,
    timestamp: u64,
}

fn parse_rsa_public_key(pem: &str) -> Result<RsaPublicKey> {
    RsaPublicKey::from_pkcs1_pem(pem)
        .or_else(|_| RsaPublicKey::from_public_key_pem(pem))
        .map_err(|_| Error::InvalidKey("server RSA public key"))
}

fn seal_with_derived_nonce(server: &PublicKey, plaintext: &[u8]) -> Result<(String, String)> {
    let sender = SecretKey::generate(&mut OsRng);
    let sender_public = sender.public_key();
    let digest = Sha256::digest(sender_public.as_bytes());
    let nonce = Nonce::from_slice(&digest[..24]);
    let cipher = SalsaBox::new(server, &sender)
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::Encrypt)?;
    Ok((
        STANDARD_NO_PAD.encode(sender_public.as_bytes()),
        STANDARD_NO_PAD.encode(cipher),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    fn profile(extra: &[&str]) -> Profile {
        Profile::parse(&testdata::ovpn(extra, "")).unwrap()
    }

    fn with_box_key(extra: &[&str]) -> (Profile, SecretKey) {
        let server = SecretKey::generate(&mut OsRng);
        let key = format!(
            "\"server_box_public_key\": \"{}\"",
            STANDARD.encode(server.public_key().as_bytes())
        );
        let mut fields = vec![key.as_str()];
        fields.extend_from_slice(extra);
        (profile(&fields), server)
    }

    #[test]
    fn pin_is_boxed_for_the_server() {
        let (profile, server) = with_box_key(&["\"password_mode\": \"pin\""]);
        let creds = openvpn_credentials(&profile, Some("1234"), Some("tokentokentoken1"))
            .unwrap()
            .unwrap();
        assert_eq!(creds.username.len(), 43);
        let cipher = creds.password.expose().strip_prefix("$x$").unwrap();
        assert!(!cipher.contains('='));

        let sender =
            PublicKey::from_slice(&STANDARD_NO_PAD.decode(&creds.username).unwrap()).unwrap();
        let digest = Sha256::digest(sender.as_bytes());
        let plain = SalsaBox::new(&sender, &server)
            .decrypt(
                Nonce::from_slice(&digest[..24]),
                STANDARD_NO_PAD.decode(cipher).unwrap().as_slice(),
            )
            .unwrap();
        let plain = String::from_utf8(plain).unwrap();
        assert_eq!(&plain[..16], "tokentokentoken1");
        assert!(plain[16..26].bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(&plain[26..], "1234");
    }

    #[test]
    fn each_credential_uses_a_fresh_sender_key() {
        let (profile, _) = with_box_key(&["\"password_mode\": \"pin\""]);
        let a = openvpn_credentials(&profile, Some("1"), None)
            .unwrap()
            .unwrap();
        let b = openvpn_credentials(&profile, Some("1"), None)
            .unwrap()
            .unwrap();
        assert_ne!(a.username, b.username);
    }

    #[test]
    fn rsa_envelope_is_used_without_box_key() {
        let pem = testdata::PUB_PKCS1
            .trim()
            .lines()
            .map(|l| format!("{l:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let profile = profile(&[
            "\"password_mode\": \"pin\"",
            &format!("\"server_public_key\": [{pem}]"),
        ]);
        let creds = openvpn_credentials(&profile, Some("4321"), None)
            .unwrap()
            .unwrap();
        assert_eq!(creds.username, VENDOR_DEFAULT_USERNAME);
        let encoded = creds.password.expose().strip_prefix(RSA_MARKER).unwrap();
        let private = RsaPrivateKey::from_pkcs8_pem(testdata::KEY_PKCS8).unwrap();
        let plain = private
            .decrypt(
                Oaep::new_with_mgf_hash::<Sha512, Sha512>(),
                &STANDARD.decode(encoded).unwrap(),
            )
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(json["password"], "4321");
        assert_eq!(json["token"].as_str().unwrap().len(), 16);
        assert_eq!(json["nonce"].as_str().unwrap().len(), 32);
        assert!(json["timestamp"].is_u64());
    }

    #[test]
    fn plain_password_without_server_keys() {
        let profile = profile(&["\"password_mode\": \"pin\""]);
        let creds = openvpn_credentials(&profile, Some("9999"), None)
            .unwrap()
            .unwrap();
        assert_eq!(creds.username, VENDOR_DEFAULT_USERNAME);
        assert_eq!(creds.password.expose(), "9999");
    }

    #[test]
    fn no_prompt_profiles_need_no_credentials() {
        assert!(
            openvpn_credentials(&profile(&[]), None, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn pin_is_required_and_not_in_debug() {
        let profile = profile(&["\"password_mode\": \"pin\""]);
        assert!(matches!(
            openvpn_credentials(&profile, None, None),
            Err(Error::MissingCredential("pin"))
        ));
        let creds = openvpn_credentials(&profile, Some("5555"), None)
            .unwrap()
            .unwrap();
        assert!(!format!("{creds:?}").contains("5555"));
    }

    #[test]
    fn unsupported_modes_fail_without_partial_login() {
        let cases: [(&[&str], Unsupported); 6] = [
            (&["\"password_mode\": \"otp\""], Unsupported::Otp),
            (&["\"password_mode\": \"otp_pin\""], Unsupported::PinOtp),
            (
                &["\"sso_auth\": true", "\"password_mode\": null"],
                Unsupported::Sso,
            ),
            (
                &["\"device_auth\": true", "\"password_mode\": \"pin\""],
                Unsupported::DeviceAuth,
            ),
            (&["\"password_mode\": \"password\""], Unsupported::Password),
            (
                &["\"dynamic_firewall\": true", "\"password_mode\": \"pin\""],
                Unsupported::DynamicFirewall,
            ),
        ];
        for (extra, expected) in cases {
            let err = openvpn_credentials(&profile(extra), Some("1234"), None).unwrap_err();
            match err {
                Error::Unsupported(found) => assert_eq!(found, expected),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn dynamic_firewall_is_fine_for_wireguard_password() {
        let profile = profile(&["\"dynamic_firewall\": true", "\"password_mode\": \"pin\""]);
        let password = password_for(&profile.header, Some("1"), Transport::WireGuard).unwrap();
        assert_eq!(password.expose(), "1");
    }

    #[test]
    fn overlong_password_is_rejected() {
        let (profile, _) = with_box_key(&["\"password_mode\": \"pin\""]);
        let pin = "9".repeat(400);
        assert!(matches!(
            openvpn_credentials(&profile, Some(&pin), None),
            Err(Error::PasswordTooLong)
        ));
    }

    #[test]
    fn connection_token_uses_f_envelope() {
        let (profile, server) = with_box_key(&[]);
        let creds =
            connection_token_credentials(&profile, &Secret::new("fwtoken:ssotoken")).unwrap();
        let cipher = creds.password.expose().strip_prefix("$f$").unwrap();
        let sender =
            PublicKey::from_slice(&STANDARD_NO_PAD.decode(&creds.username).unwrap()).unwrap();
        let digest = Sha256::digest(sender.as_bytes());
        let plain = SalsaBox::new(&sender, &server)
            .decrypt(
                Nonce::from_slice(&digest[..24]),
                STANDARD_NO_PAD.decode(cipher).unwrap().as_slice(),
            )
            .unwrap();
        assert_eq!(plain, b"fwtoken:ssotoken");
    }

    #[test]
    fn version_line_uses_vendor_env_name() {
        assert_eq!(
            version_setenv_line("1.0"),
            format!("setenv {VENDOR_VERSION_ENV} 1.0")
        );
    }
}
