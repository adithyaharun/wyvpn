use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::state::{Found, newer_than};

pub const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_REDIRECTS: usize = 5;
const REDIRECT_HOSTS: [&str; 3] = [
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

pub fn redirect_allowed(target: &Url, hops: usize) -> bool {
    hops < MAX_REDIRECTS
        && target.scheme() == "https"
        && target
            .host_str()
            .is_some_and(|host| REDIRECT_HOSTS.contains(&host))
}

#[derive(Deserialize)]
struct Manifest {
    version: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    pub_date: Option<String>,
}

pub fn endpoint(config: Option<&Value>) -> Result<Url, String> {
    let config = config.ok_or("the update feed is not configured")?;
    let raw = config
        .get("endpoints")
        .and_then(Value::as_array)
        .and_then(|list| list.first())
        .and_then(Value::as_str)
        .ok_or("the update feed is not configured")?;
    let url = Url::parse(raw).map_err(|_| "the update feed address is invalid")?;
    let insecure = config
        .get("dangerousInsecureTransportProtocol")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if url.scheme() != "https" && !insecure {
        return Err("the update feed must use https".to_owned());
    }
    Ok(url)
}

pub fn evaluate(body: &[u8], current: &str) -> Result<Option<Found>, String> {
    if body.len() > MAX_BODY_BYTES {
        return Err("the update feed is too large".to_owned());
    }
    let manifest: Manifest =
        serde_json::from_slice(body).map_err(|_| "the update feed could not be read")?;
    Ok(
        newer_than(&manifest.version, current)?.map(|version| Found {
            version,
            notes: manifest.notes,
            date: manifest.pub_date,
        }),
    )
}

#[cfg(target_os = "linux")]
pub async fn fetch(url: &Url) -> Result<Vec<u8>, String> {
    use std::sync::Arc;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(15);

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
        .map_err(|_| "the system certificate store is unavailable")?;
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "TLS is unavailable")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if redirect_allowed(attempt.url(), attempt.previous().len()) {
                attempt.follow()
            } else {
                attempt.error("the update server redirected somewhere unexpected")
            }
        }))
        .user_agent(concat!("WyVPN/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| "could not start the update check")?;
    let mut response = client
        .get(url.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|error| {
            tracing::warn!("update feed request failed: {error}");
            "could not reach the update server".to_owned()
        })?;
    let too_large = || "the update feed is too large".to_owned();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "could not read the update feed")?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn manifest(version: &str) -> Vec<u8> {
        json!({
            "version": version,
            "notes": "Fixes",
            "pub_date": "2026-10-21T00:00:00Z",
            "platforms": {"darwin-aarch64": {"signature": "s", "url": "https://x/y"}}
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn a_newer_version_is_offered() {
        let found = evaluate(&manifest("0.2.0"), "0.1.2").unwrap().unwrap();
        assert_eq!(found.version, "0.2.0");
        assert_eq!(found.notes.as_deref(), Some("Fixes"));
        assert_eq!(found.date.as_deref(), Some("2026-10-21T00:00:00Z"));
    }

    #[test]
    fn a_v_prefix_is_accepted() {
        let found = evaluate(&manifest("v0.2.0"), "0.1.2").unwrap().unwrap();
        assert_eq!(found.version, "0.2.0");
    }

    #[test]
    fn the_same_version_is_up_to_date() {
        assert_eq!(evaluate(&manifest("0.1.2"), "0.1.2"), Ok(None));
    }

    #[test]
    fn an_older_version_is_not_offered() {
        assert_eq!(evaluate(&manifest("0.1.1"), "0.1.2"), Ok(None));
    }

    #[test]
    fn an_invalid_version_fails() {
        assert!(evaluate(&manifest("latest"), "0.1.2").is_err());
        assert!(evaluate(&manifest(""), "0.1.2").is_err());
    }

    #[test]
    fn a_prerelease_older_than_the_running_release_is_not_offered() {
        assert_eq!(evaluate(&manifest("0.1.2-test.1"), "0.1.2"), Ok(None));
        assert!(
            evaluate(&manifest("0.1.3-rc.1"), "0.1.2")
                .unwrap()
                .is_some()
        );
        assert_eq!(
            evaluate(&manifest("0.1.2"), "0.1.2-test.1")
                .unwrap()
                .map(|f| f.version),
            Some("0.1.2".to_owned())
        );
    }

    #[test]
    fn a_manifest_without_platforms_parses() {
        let body = json!({"version": "0.2.0"}).to_string();
        let found = evaluate(body.as_bytes(), "0.1.2").unwrap().unwrap();
        assert_eq!((found.notes, found.date), (None, None));
    }

    #[test]
    fn a_body_that_is_not_json_fails() {
        assert!(evaluate(b"<html>nope</html>", "0.1.2").is_err());
        assert!(evaluate(b"", "0.1.2").is_err());
        assert!(evaluate(b"{\"notes\": \"no version\"}", "0.1.2").is_err());
    }

    #[test]
    fn a_body_over_the_cap_fails() {
        let mut body = manifest("0.2.0");
        body.resize(MAX_BODY_BYTES + 1, b' ');
        assert!(evaluate(&body, "0.1.2").is_err());
    }

    #[test]
    fn http_endpoints_need_the_insecure_flag() {
        let plain = json!({"endpoints": ["http://127.0.0.1:8787/latest.json"]});
        assert!(endpoint(Some(&plain)).is_err());
        let allowed = json!({
            "endpoints": ["http://127.0.0.1:8787/latest.json"],
            "dangerousInsecureTransportProtocol": true
        });
        assert!(endpoint(Some(&allowed)).is_ok());
        let secure = json!({"endpoints": ["https://example.com/latest.json"]});
        assert_eq!(
            endpoint(Some(&secure)).unwrap().as_str(),
            "https://example.com/latest.json"
        );
    }

    #[test]
    fn redirects_stay_on_https_github_hosts_and_are_bounded() {
        let ok = |url: &str, hops| redirect_allowed(&Url::parse(url).unwrap(), hops);
        assert!(ok("https://github.com/a/b", 0));
        assert!(ok("https://objects.githubusercontent.com/x", 4));
        assert!(ok("https://release-assets.githubusercontent.com/x", 1));
        assert!(!ok("https://github.com/a/b", 5));
        assert!(!ok("http://github.com/a/b", 0));
        assert!(!ok("https://evil.example/x", 0));
        assert!(!ok("https://github.com.evil.example/x", 0));
        assert!(!ok("https://githubusercontent.com/x", 0));
        assert!(!ok("https://user@127.0.0.1/x", 0));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_redirect_to_another_host_is_refused() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 1024];
            let _ = socket.read(&mut buf).await;
            let reply = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/latest.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            socket.write_all(reply.as_bytes()).await.unwrap();
        });
        let url = Url::parse(&format!("http://127.0.0.1:{port}/latest.json")).unwrap();
        assert!(fetch(&url).await.is_err());
    }

    #[test]
    fn a_missing_or_malformed_endpoint_fails() {
        assert!(endpoint(None).is_err());
        assert!(endpoint(Some(&json!({}))).is_err());
        assert!(endpoint(Some(&json!({"endpoints": []}))).is_err());
        assert!(endpoint(Some(&json!({"endpoints": ["not a url"]}))).is_err());
    }
}
