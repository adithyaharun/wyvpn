pub const KEY_PKCS8: &str = include_str!("key_pkcs8.pem");
pub const KEY_PKCS1: &str = include_str!("key_pkcs1.pem");
pub const PUB_PKCS1: &str = include_str!("pub_pkcs1.pem");

pub const SYNC_TOKEN: &str = "Ns7d8KJmQw2xY4pZ0aB1cD3eF5gH6iJk";
pub const SYNC_SECRET: &str = "Xy9Pq2Lm7Nr4St6Uv8Wz0Ab3Cd5Ef1Gh";
pub const ORG_ID: &str = "5f3c1a2b4d6e8f0a1b2c3d4e";
pub const USER_ID: &str = "5f3c1a2b4d6e8f0a1b2c3d4f";
pub const SERVER_ID: &str = "5f3c1a2b4d6e8f0a1b2c3d50";
pub const SYNC_HASH: &str = "0cc175b9c0f1b6a831c399e269772661";

pub fn ovpn(extra: &[&str], body_extra: &str) -> String {
    let mut fields = vec![
        "\"version\": 1".to_owned(),
        "\"user\": \"alice\"".to_owned(),
        "\"organization\": \"Org\"".to_owned(),
        "\"server\": \"Gateway\"".to_owned(),
        format!("\"organization_id\": \"{ORG_ID}\""),
        format!("\"user_id\": \"{USER_ID}\""),
        format!("\"server_id\": \"{SERVER_ID}\""),
        format!("\"sync_hash\": \"{SYNC_HASH}\""),
        format!("\"sync_token\": \"{SYNC_TOKEN}\""),
        format!("\"sync_secret\": \"{SYNC_SECRET}\""),
    ];
    fields.extend(extra.iter().map(|f| (*f).to_owned()));
    let mut text = String::from("#{\n");
    text.push_str(
        &fields
            .iter()
            .map(|f| format!("# {f}"))
            .collect::<Vec<_>>()
            .join(",\n"),
    );
    text.push_str("\n#}\n");
    text.push_str("ignore-unknown-option data-ciphers\nsetenv UV_ID abcdef0123456789abcdef0123456789\nsetenv UV_NAME laptop\nclient\ndev tun\nremote vpn.example.com 1194 udp\nremote 192.0.2.7 443 tcp-client\n");
    text.push_str(body_extra);
    text.push_str("<ca>\nCA\n</ca>\n<tls-auth>\nTA\n</tls-auth>\nkey-direction 1\n<cert>\nCERT\n</cert>\n<key>\n");
    text.push_str(KEY_PKCS8.trim());
    text.push_str("\n</key>\n");
    text
}
