use serde::Serialize;
use wyvpn_ipc::ErrorBody;

const MAX_MESSAGE_CHARS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CmdError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<String>,
}

impl CmdError {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_owned(),
            message: sanitize(message),
            retry: None,
        }
    }

    pub fn with_retry(mut self, token: String) -> Self {
        self.retry = Some(token);
        self
    }

    pub fn invalid_request(message: &str) -> Self {
        Self::new("invalid_request", message)
    }

    pub fn unavailable(message: &str) -> Self {
        Self::new("daemon_unavailable", message)
    }

    pub fn too_large(limit: usize) -> Self {
        Self::new(
            "too_large",
            &format!("file exceeds the {} KiB import limit", limit / 1024),
        )
    }

    pub fn io(message: &str) -> Self {
        Self::new("io", message)
    }

    pub fn internal(message: &str) -> Self {
        Self::new("internal", message)
    }
}

impl From<ErrorBody> for CmdError {
    fn from(body: ErrorBody) -> Self {
        let code = serde_json::to_value(body.code)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "internal".to_owned());
        Self {
            code,
            message: sanitize(&body.message),
            retry: None,
        }
    }
}

pub fn sanitize(text: &str) -> String {
    wyvpn_ipc::sanitize_text(text, MAX_MESSAGE_CHARS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyvpn_ipc::ErrorCode;

    #[test]
    fn daemon_codes_map_to_snake_case() {
        let cases = [
            (ErrorCode::InvalidState, "invalid_state"),
            (ErrorCode::UnsupportedAuth, "unsupported_auth"),
            (ErrorCode::AlreadyExists, "already_exists"),
            (ErrorCode::NotFound, "not_found"),
            (ErrorCode::AuthFailed, "auth_failed"),
            (ErrorCode::PermissionDenied, "permission_denied"),
        ];
        for (code, expected) in cases {
            assert_eq!(CmdError::from(ErrorBody::new(code, "x")).code, expected);
        }
    }

    #[test]
    fn messages_are_sanitized() {
        let error = CmdError::from(ErrorBody::new(
            ErrorCode::Server,
            "a\u{1b}[31mb\u{202e}c\nd",
        ));
        assert_eq!(error.message, "a[31mbcd");
        assert!(sanitize(&"x".repeat(400)).ends_with('…'));
    }

    #[test]
    fn serializes_as_code_and_message() {
        let json = serde_json::to_value(CmdError::unavailable("down")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"code": "daemon_unavailable", "message": "down"})
        );
    }

    #[test]
    fn retry_token_is_serialized_only_when_present() {
        let error = CmdError::new("already_exists", "x").with_retry("tok".into());
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            serde_json::json!({"code": "already_exists", "message": "x", "retry": "tok"})
        );
    }
}
