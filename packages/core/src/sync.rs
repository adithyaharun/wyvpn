use crate::error::{Error, Result};
use crate::http::{ApiClient, HttpRequest, HttpResponse, Method};
use crate::profile::{Profile, extract_block, remove_block, split_header};
use crate::secret::Secret;
use crate::sign::{generate_nonce, sign_request, unix_now, verify_hmac_base64};
use crate::vendor::VENDOR_USER_AGENT_SYNC;
use serde::Deserialize;
use std::time::Duration;
use url::Url;
use zeroize::Zeroizing;

const SYNC_TIMEOUT: Duration = Duration::from_secs(5);
const NO_SUBSCRIPTION: u16 = 480;

#[derive(Debug, Clone)]
pub enum SyncOutcome {
    Unchanged,
    Updated(Box<Profile>),
}

#[derive(Deserialize)]
struct SyncBody {
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    conf: Option<String>,
}

pub fn sync_path(profile: &Profile) -> Result<String> {
    let header = &profile.header;
    for (value, name) in [
        (&header.organization_id, "organization_id"),
        (&header.user_id, "user_id"),
        (&header.server_id, "server_id"),
        (&header.sync_hash, "sync_hash"),
    ] {
        if value.is_empty() {
            return Err(Error::MissingField(name));
        }
    }
    Ok(format!(
        "/key/sync/{}/{}/{}/{}",
        header.organization_id, header.user_id, header.server_id, header.sync_hash
    ))
}

fn credentials(profile: &Profile) -> Result<(&str, &Secret)> {
    let token = profile
        .header
        .sync_token
        .as_ref()
        .filter(|t| !t.is_empty())
        .ok_or(Error::MissingField("sync_token"))?;
    let secret = profile
        .header
        .sync_secret
        .as_ref()
        .filter(|s| !s.is_empty())
        .ok_or(Error::MissingField("sync_secret"))?;
    Ok((token.expose(), secret))
}

pub fn build_sync_request(
    profile: &Profile,
    base_url: &str,
    timestamp: u64,
    nonce: &str,
) -> Result<HttpRequest> {
    let path = sync_path(profile)?;
    let (token, secret) = credentials(profile)?;
    let auth = sign_request(secret, token, timestamp, nonce, "GET", &path, &[])?;
    let mut url = Url::parse(base_url).map_err(|err| Error::InvalidUri(err.to_string()))?;
    url.set_path(&path);
    url.set_query(Some("ver=2"));
    let mut headers: Vec<(String, String)> = auth
        .headers()
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
    headers.push(("User-Agent".into(), VENDOR_USER_AGENT_SYNC.into()));
    Ok(HttpRequest {
        method: Method::GET,
        url,
        headers,
        body: None,
        timeout: SYNC_TIMEOUT,
    })
}

pub fn parse_sync_response(profile: &Profile, response: &HttpResponse) -> Result<SyncOutcome> {
    match response.status {
        NO_SUBSCRIPTION => return Ok(SyncOutcome::Unchanged),
        200 => {}
        other => return Err(Error::Status(other)),
    }
    let body: SyncBody = serde_json::from_slice(&response.body)
        .map_err(|err| Error::InvalidResponse(err.to_string()))?;
    let Some(conf) = body.conf.filter(|c| !c.is_empty()) else {
        return Ok(SyncOutcome::Unchanged);
    };
    let (_, secret) = credentials(profile)?;
    let signature = body
        .signature
        .ok_or_else(|| Error::InvalidResponse("missing signature".into()))?;
    if !verify_hmac_base64(secret, conf.as_bytes(), &signature) {
        return Err(Error::ResponseSignature);
    }
    Ok(SyncOutcome::Updated(Box::new(apply_sync(profile, &conf)?)))
}

pub async fn sync_from(
    client: &ApiClient,
    base_url: &str,
    profile: &Profile,
) -> Result<SyncOutcome> {
    let request = build_sync_request(profile, base_url, unix_now(), &generate_nonce())?;
    let response = client.execute(request).await?;
    parse_sync_response(profile, &response)
}

pub async fn sync_profile(client: &ApiClient, profile: &Profile) -> Result<SyncOutcome> {
    let mut last = Error::NoSyncHosts;
    for host in &profile.header.sync_hosts {
        match sync_from(client, host, profile).await {
            Ok(outcome) => return Ok(outcome),
            Err(err @ Error::CertificateChanged { .. }) => return Err(err),
            Err(err) => last = err,
        }
    }
    Err(last)
}

fn setenv_line<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find(|line| {
        let mut parts = line.split_whitespace();
        parts.next() == Some("setenv") && parts.next() == Some(name)
    })
}

pub fn apply_sync(old: &Profile, conf: &str) -> Result<Profile> {
    let (new_header, new_body) = split_header(conf)?;
    let old_ovpn = old.ovpn.expose();
    let mut body = Zeroizing::new(String::new());
    for line in new_body.lines() {
        let replacement = ["UV_ID", "UV_NAME"]
            .into_iter()
            .find(|name| setenv_line(line, name).is_some())
            .and_then(|name| setenv_line(old_ovpn, name));
        body.push_str(replacement.unwrap_or(line));
        body.push('\n');
    }

    let new_cert = extract_block(&body, "cert");
    let mut body = Zeroizing::new(remove_block(&body, "cert"));
    if !body.ends_with('\n') {
        body.push('\n');
    }

    if old_ovpn.contains("key-direction") && !body.contains("key-direction") {
        body.push_str("key-direction 1\n");
    }
    for block in [
        extract_block(old_ovpn, "tls-auth"),
        extract_block(old_ovpn, "tls-crypt"),
        new_cert.or_else(|| extract_block(old_ovpn, "cert")),
        extract_block(old_ovpn, "key"),
    ]
    .into_iter()
    .flatten()
    {
        body.push_str(&block);
        body.push('\n');
    }

    let mut header = new_header.unwrap_or_else(|| old.header.clone());
    header.sync_token.clone_from(&old.header.sync_token);
    header.sync_secret.clone_from(&old.header.sync_secret);
    Ok(Profile {
        header,
        ovpn: Secret::from(std::mem::take(&mut *body)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::hmac_base64;
    use crate::testdata::{self, SYNC_SECRET, SYNC_TOKEN};
    use crate::tls::TlsPolicy;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

    fn profile() -> Profile {
        Profile::parse(&testdata::ovpn(&["\"password_mode\": \"pin\""], "")).unwrap()
    }

    fn client() -> ApiClient {
        ApiClient::new(TlsPolicy::Verify)
            .unwrap()
            .allow_plain_http()
    }

    fn server_conf() -> String {
        "#{\n# \"version\": 1,\n# \"user\": \"alice\",\n# \"server\": \"Renamed\",\n# \"wg\": true,\n# \"password_mode\": \"pin\",\n# \"sync_hash\": \"0badc0de\"\n#}\nsetenv UV_ID 11111111111111111111111111111111\nsetenv UV_NAME other\nclient\nremote new.example.com 1194 udp\n<ca>\nNEWCA\n</ca>\n<cert>\nNEWCERT\n</cert>\n".to_owned()
    }

    fn signed_body(conf: &str) -> serde_json::Value {
        serde_json::json!({
            "signature": hmac_base64(&Secret::new(SYNC_SECRET), conf.as_bytes()),
            "conf": conf,
        })
    }

    struct ValidSignature;

    impl Match for ValidSignature {
        fn matches(&self, request: &Request) -> bool {
            let header = |name: &str| {
                request
                    .headers
                    .get(name)
                    .map(|v| v.to_str().unwrap().to_owned())
                    .unwrap_or_default()
            };
            let nonce = header("auth-nonce");
            let message = format!(
                "{}&{}&{}&GET&{}",
                header("auth-token"),
                header("auth-timestamp"),
                nonce,
                request.url.path()
            );
            nonce.len() <= 32
                && header("auth-token") == SYNC_TOKEN
                && request.url.query() == Some("ver=2")
                && header("user-agent") == crate::vendor::VENDOR_USER_AGENT_SYNC
                && header("auth-signature")
                    == hmac_base64(&Secret::new(SYNC_SECRET), message.as_bytes())
        }
    }

    #[test]
    fn request_has_documented_shape() {
        let request = build_sync_request(
            &profile(),
            "https://vpn.example.com:9443",
            1_760_000_000,
            "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6",
        )
        .unwrap();
        assert_eq!(
            request.url.as_str(),
            "https://vpn.example.com:9443/key/sync/5f3c1a2b4d6e8f0a1b2c3d4e/5f3c1a2b4d6e8f0a1b2c3d4f/5f3c1a2b4d6e8f0a1b2c3d50/0cc175b9c0f1b6a831c399e269772661?ver=2"
        );
        assert_eq!(request.header("Auth-Timestamp"), Some("1760000000"));
        assert!(request.header("auth-signature").is_some());
        assert!(!format!("{request:?}").contains(SYNC_TOKEN));
    }

    #[tokio::test]
    async fn sync_applies_signed_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("^/key/sync/"))
            .and(ValidSignature)
            .respond_with(ResponseTemplate::new(200).set_body_json(signed_body(&server_conf())))
            .expect(1)
            .mount(&server)
            .await;

        let old = profile();
        let SyncOutcome::Updated(new) = sync_from(&client(), &server.uri(), &old).await.unwrap()
        else {
            panic!("expected update");
        };
        assert_eq!(new.header.server, "Renamed");
        assert!(new.header.wg);
        assert_eq!(new.header.sync_hash, "0badc0de");
        assert_eq!(new.header.sync_token.as_ref().unwrap().expose(), SYNC_TOKEN);
        assert_eq!(
            new.header.sync_secret.as_ref().unwrap().expose(),
            SYNC_SECRET
        );
        assert_eq!(new.device_id(), old.device_id());
        assert_eq!(new.device_name(), Some("laptop"));
        assert!(new.ovpn.expose().contains("remote new.example.com"));
        assert_eq!(new.ovpn.expose().matches("<cert>").count(), 1);
        assert!(new.ovpn.expose().contains("NEWCERT"));
        assert!(new.ovpn.expose().contains("<tls-auth>\nTA\n</tls-auth>"));
        assert!(new.ovpn.expose().contains("key-direction 1"));
        assert!(new.private_key_pem().is_some());
        let tail = new.ovpn.expose().find("<tls-auth>").unwrap();
        assert!(tail > new.ovpn.expose().find("NEWCA").unwrap());
        assert!(new.ovpn.expose().find("<cert>").unwrap() > tail);
        assert!(
            new.ovpn.expose().find("<key>").unwrap() > new.ovpn.expose().find("<cert>").unwrap()
        );
    }

    #[tokio::test]
    async fn tampered_response_is_rejected() {
        let server = MockServer::start().await;
        let mut body = signed_body(&server_conf());
        body["conf"] = format!("{}\nroute 0.0.0.0 0.0.0.0\n", server_conf()).into();
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        let err = sync_from(&client(), &server.uri(), &profile())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ResponseSignature));
    }

    #[tokio::test]
    async fn empty_and_no_subscription_responses_mean_unchanged() {
        for response in [
            ResponseTemplate::new(200).set_body_string("{}"),
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"conf": "", "signature": ""})),
            ResponseTemplate::new(480).set_body_string("{}"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(response)
                .mount(&server)
                .await;
            let outcome = sync_from(&client(), &server.uri(), &profile())
                .await
                .unwrap();
            assert!(matches!(outcome, SyncOutcome::Unchanged));
        }
    }

    #[tokio::test]
    async fn rejected_signature_reports_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let err = sync_from(&client(), &server.uri(), &profile())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Status(401)));
    }

    #[tokio::test]
    async fn sync_profile_tries_hosts_in_order() {
        let bad = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&bad)
            .await;
        let good = MockServer::start().await;
        Mock::given(method("GET"))
            .and(ValidSignature)
            .respond_with(ResponseTemplate::new(200).set_body_json(signed_body(&server_conf())))
            .mount(&good)
            .await;
        let mut profile = profile();
        profile.header.sync_hosts = vec![bad.uri(), good.uri()];
        let outcome = sync_profile(&client(), &profile).await.unwrap();
        assert!(matches!(outcome, SyncOutcome::Updated(_)));

        profile.header.sync_hosts.clear();
        assert!(matches!(
            sync_profile(&client(), &profile).await,
            Err(Error::NoSyncHosts)
        ));
    }

    #[tokio::test]
    async fn plain_http_is_refused_by_default() {
        let strict = ApiClient::new(TlsPolicy::Verify).unwrap();
        let err = sync_from(&strict, "http://127.0.0.1:1", &profile())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InsecureScheme));
    }

    #[test]
    fn missing_credentials_are_reported() {
        let mut profile = profile();
        profile.header.sync_secret = None;
        assert!(matches!(
            build_sync_request(&profile, "https://h", 1, "n"),
            Err(Error::MissingField("sync_secret"))
        ));
    }
}
