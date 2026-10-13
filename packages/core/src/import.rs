use crate::bundle::NamedProfile;
use crate::error::{Error, Result};
use crate::http::{ApiClient, HttpRequest, Method, url_pin_key};
use crate::profile::Profile;
use crate::tls::{Pins, TlsObservation, TlsPolicy};
use crate::vendor::{VENDOR_URI_SCHEME, VENDOR_URI_SCHEME_SECURE, VENDOR_USER_AGENT_SYNC};
use std::collections::BTreeMap;
use std::time::Duration;
use url::Url;

const IMPORT_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Debug, Clone)]
pub struct Imported {
    pub profiles: Vec<NamedProfile>,
    pub tls: Option<TlsObservation>,
    pub pins: Pins,
}

pub fn normalize_import_uri(input: &str) -> Result<Url> {
    let input = input.trim();
    let lower = input.to_ascii_lowercase();
    let rewritten = [VENDOR_URI_SCHEME_SECURE, VENDOR_URI_SCHEME, "pts", "http"]
        .into_iter()
        .find(|scheme| lower.starts_with(&format!("{scheme}:")))
        .map(|scheme| format!("https:{}", &input[scheme.len() + 1..]))
        .or_else(|| lower.starts_with("https:").then(|| input.to_owned()))
        .unwrap_or_else(|| format!("https://{input}"));
    let rewritten = rewritten.replacen("/k/", "/ku/", 1);

    let url = Url::parse(&rewritten).map_err(|err| Error::InvalidUri(err.to_string()))?;
    if url.host_str().is_none_or(str::is_empty) {
        return Err(Error::InvalidUri("missing host".into()));
    }
    if !url.path().starts_with("/ku/") || url.path().len() <= 4 {
        return Err(Error::InvalidUri("not a profile link".into()));
    }
    Ok(url)
}

pub fn build_import_request(url: Url) -> HttpRequest {
    HttpRequest {
        method: Method::GET,
        url,
        headers: vec![
            ("User-Agent".into(), VENDOR_USER_AGENT_SYNC.into()),
            ("Accept".into(), "application/json".into()),
        ],
        body: None,
        timeout: IMPORT_TIMEOUT,
    }
}

pub async fn fetch_profiles(client: &ApiClient, url: Url) -> Result<Imported> {
    let observed_url = url.clone();
    let response = client.execute(build_import_request(url)).await?;
    match response.status {
        200 => {}
        403 => return Err(Error::Forbidden),
        404 => return Err(Error::NotFound),
        other => return Err(Error::Status(other)),
    }
    let files: BTreeMap<String, String> = serde_json::from_slice(&response.body)
        .map_err(|err| Error::InvalidResponse(err.to_string()))?;
    if files.is_empty() {
        return Err(Error::NoProfiles);
    }
    let mut profiles = Vec::with_capacity(files.len());
    for (name, text) in files {
        let profile = Profile::parse(&text)
            .map_err(|err| Error::InvalidResponse(format!("{name}: {err}")))?;
        profiles.push(NamedProfile { name, profile });
    }
    let tls = client.tls_observation(&observed_url);
    let mut pins = Pins::new();
    if let (Some(observation), Some(key)) = (tls, url_pin_key(&observed_url))
        && !observation.verified_by_roots
    {
        pins.insert(key, observation.fingerprint);
    }
    Ok(Imported {
        profiles,
        tls,
        pins,
    })
}

pub fn import_policy(url: &Url) -> TlsPolicy {
    match url.host() {
        Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)) => TlsPolicy::first_use(),
        _ => TlsPolicy::Verify,
    }
}

pub async fn import_uri(input: &str) -> Result<Imported> {
    let url = normalize_import_uri(input)?;
    let client = ApiClient::new(import_policy(&url))?;
    fetch_profiles(&client, url).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn every_documented_form_normalises_to_https() {
        let expected = "https://vpn.example.com/ku/abc123";
        let inputs = [
            format!("{VENDOR_URI_SCHEME}://vpn.example.com/ku/abc123"),
            format!("{VENDOR_URI_SCHEME_SECURE}://vpn.example.com/ku/abc123"),
            "pts://vpn.example.com/ku/abc123".to_owned(),
            "http://vpn.example.com/ku/abc123".to_owned(),
            "https://vpn.example.com/ku/abc123".to_owned(),
            "vpn.example.com/ku/abc123".to_owned(),
            "https://vpn.example.com/k/abc123".to_owned(),
            "  vpn.example.com/k/abc123\n".to_owned(),
        ];
        for input in inputs {
            assert_eq!(
                normalize_import_uri(&input).unwrap().as_str(),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn only_ip_literals_may_use_first_use_trust() {
        let policy = |text: &str| import_policy(&Url::parse(text).unwrap());
        assert_eq!(policy("https://vpn.example.com/ku/x"), TlsPolicy::Verify);
        assert_eq!(policy("https://localhost:9443/ku/x"), TlsPolicy::Verify);
        for ip in ["https://192.0.2.7/ku/x", "https://[2001:db8::1]:9443/ku/x"] {
            assert_eq!(policy(ip), TlsPolicy::first_use(), "{ip}");
        }
    }

    #[test]
    fn port_is_preserved_and_garbage_rejected() {
        assert_eq!(
            normalize_import_uri("https://h.example:9443/k/x")
                .unwrap()
                .as_str(),
            "https://h.example:9443/ku/x"
        );
        assert!(normalize_import_uri("https://h.example/other/x").is_err());
        assert!(normalize_import_uri("https://h.example/ku/").is_err());
        assert!(normalize_import_uri("").is_err());
    }

    fn client() -> ApiClient {
        ApiClient::new(TlsPolicy::Verify)
            .unwrap()
            .allow_plain_http()
    }

    #[tokio::test]
    async fn imports_every_profile_in_the_response() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "Org_alice_One.ovpn": testdata::ovpn(&[], ""),
            "Org_alice_Two.ovpn": testdata::ovpn(&["\"password_mode\": \"pin\""], ""),
        });
        Mock::given(method("GET"))
            .and(path("/ku/abc"))
            .and(header("accept", "application/json"))
            .and(header("user-agent", VENDOR_USER_AGENT_SYNC))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let url = Url::parse(&format!("{}/ku/abc", server.uri())).unwrap();
        let imported = fetch_profiles(&client(), url).await.unwrap();
        assert_eq!(imported.profiles.len(), 2);
        assert_eq!(imported.profiles[0].name, "Org_alice_One.ovpn");
        assert_eq!(
            imported.profiles[1].profile.header.password_mode.as_deref(),
            Some("pin")
        );
    }

    #[tokio::test]
    async fn error_statuses_map_to_errors() {
        for (status, check) in [
            (404u16, "not found"),
            (403, "disabled"),
            (500, "status 500"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let url = Url::parse(&format!("{}/ku/abc", server.uri())).unwrap();
            let err = fetch_profiles(&client(), url)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains(check), "{err}");
        }
    }

    #[tokio::test]
    async fn empty_and_malformed_responses_fail() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ku/empty"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/ku/bad"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"a.ovpn": "client\n"})),
            )
            .mount(&server)
            .await;
        let empty = Url::parse(&format!("{}/ku/empty", server.uri())).unwrap();
        assert!(matches!(
            fetch_profiles(&client(), empty).await,
            Err(Error::NoProfiles)
        ));
        let bad = Url::parse(&format!("{}/ku/bad", server.uri())).unwrap();
        assert!(matches!(
            fetch_profiles(&client(), bad).await,
            Err(Error::InvalidResponse(_))
        ));
    }
}
