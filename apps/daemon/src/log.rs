use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use wyvpn_ipc::{LogLine, LogSource};

pub const CAPACITY: usize = 1000;
pub const MAX_LINE_CHARS: usize = 512;

const REDACTED_KEYS: [&str; 3] = ["auth-token-user", "auth-token", "password"];
const REDACTED: &str = "[redacted]";

#[derive(Default)]
pub struct SessionLog {
    profile_id: Option<String>,
    lines: VecDeque<LogLine>,
    next_seq: u64,
    published: u64,
    flush_scheduled: bool,
}

impl SessionLog {
    pub fn clear(&mut self, profile_id: &str) {
        self.profile_id = Some(profile_id.to_owned());
        self.lines.clear();
        self.next_seq = 0;
        self.published = 0;
    }

    pub fn push(&mut self, source: LogSource, text: &str) -> bool {
        let text: String = redact(without_control(text).trim_end())
            .chars()
            .take(MAX_LINE_CHARS)
            .collect();
        if text.trim().is_empty() {
            return false;
        }
        if self.lines.len() == CAPACITY {
            self.lines.pop_front();
        }
        self.lines.push_back(LogLine {
            seq: self.next_seq,
            at_ms: now_ms(),
            source,
            text,
        });
        self.next_seq += 1;
        !std::mem::replace(&mut self.flush_scheduled, true)
    }

    pub fn snapshot(&self) -> (Option<String>, Vec<LogLine>) {
        (
            self.profile_id.clone(),
            self.lines.iter().cloned().collect(),
        )
    }

    pub fn take_unpublished(&mut self) -> Option<(String, Vec<LogLine>)> {
        self.flush_scheduled = false;
        let profile_id = self.profile_id.clone()?;
        let lines: Vec<LogLine> = self
            .lines
            .iter()
            .filter(|line| line.seq >= self.published)
            .cloned()
            .collect();
        self.published = self.next_seq;
        (!lines.is_empty()).then_some((profile_id, lines))
    }
}

pub fn without_control(message: &str) -> String {
    message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

pub fn redact(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        let key = (i == 0 || !is_word(bytes[i - 1]))
            .then(|| {
                REDACTED_KEYS.iter().find(|key| {
                    bytes[i..].starts_with(key.as_bytes())
                        && !bytes
                            .get(i + key.len())
                            .is_some_and(|b| is_word(*b) || *b == b'-')
                })
            })
            .flatten();
        let Some(key) = key else {
            i += 1;
            continue;
        };
        let mut start = i + key.len();
        while bytes
            .get(start)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'=' | b':'))
        {
            start += 1;
        }
        let end = value_end(bytes, start);
        if start == i + key.len() || end == start {
            i += key.len();
            continue;
        }
        out.push_str(&text[copied..start]);
        out.push_str(REDACTED);
        copied = end;
        i = end;
    }
    out.push_str(&text[copied..]);
    out
}

fn value_end(bytes: &[u8], start: usize) -> usize {
    match bytes.get(start) {
        Some(&quote @ (b'"' | b'\'')) => bytes[start + 1..]
            .iter()
            .position(|b| *b == quote)
            .map_or(bytes.len(), |at| start + 2 + at),
        _ => bytes[start..]
            .iter()
            .position(|b| b.is_ascii_whitespace() || *b == b',')
            .map_or(bytes.len(), |at| start + at),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(log: &SessionLog) -> Vec<String> {
        log.snapshot().1.into_iter().map(|line| line.text).collect()
    }

    #[test]
    fn ring_buffer_drops_the_oldest_lines() {
        let mut log = SessionLog::default();
        log.clear("p1");
        for n in 0..CAPACITY + 5 {
            log.push(LogSource::Tunnel, &format!("line {n}"));
        }
        let (_, lines) = log.snapshot();
        assert_eq!(lines.len(), CAPACITY);
        assert_eq!(lines[0].text, "line 5");
        assert_eq!(lines[0].seq, 5);
        assert_eq!(lines[CAPACITY - 1].seq, (CAPACITY + 4) as u64);
    }

    #[test]
    fn long_lines_are_truncated() {
        let mut log = SessionLog::default();
        log.push(LogSource::Tunnel, &"é".repeat(MAX_LINE_CHARS * 2));
        assert_eq!(text(&log)[0].chars().count(), MAX_LINE_CHARS);
    }

    #[test]
    fn control_characters_become_spaces() {
        let mut log = SessionLog::default();
        log.push(LogSource::Tunnel, "a\x1b[31mb\r\tc");
        assert_eq!(text(&log), ["a [31mb  c"]);
    }

    #[test]
    fn control_characters_do_not_hide_secrets() {
        let mut log = SessionLog::default();
        log.push(LogSource::Tunnel, "password\thunter2");
        log.push(LogSource::Tunnel, "auth-token\tX");
        log.push(LogSource::Tunnel, "password\0hunter2");
        assert_eq!(
            text(&log),
            [
                "password [redacted]",
                "auth-token [redacted]",
                "password [redacted]"
            ]
        );
    }

    #[test]
    fn redacts_each_key() {
        let cases = [
            ("auth-token abc", "auth-token [redacted]"),
            ("auth-token-user YWRtaW4=", "auth-token-user [redacted]"),
            ("password hunter2", "password [redacted]"),
            ("Password=hunter2 next", "Password=[redacted] next"),
            ("password: \"a b\" tail", "password: [redacted] tail"),
            (
                "PUSH_REPLY,route 10.0.0.0,auth-token SESS_1,auth-token-user dXNy,ifconfig 10.8.0.2",
                "PUSH_REPLY,route 10.0.0.0,auth-token [redacted],auth-token-user [redacted],ifconfig 10.8.0.2",
            ),
            ("--password secret", "--password [redacted]"),
            ("no secrets here", "no secrets here"),
            ("password", "password"),
            ("passwords are fine", "passwords are fine"),
        ];
        for (input, expected) in cases {
            assert_eq!(redact(input), expected, "{input}");
        }
    }

    #[test]
    fn stored_lines_are_redacted() {
        let mut log = SessionLog::default();
        log.push(LogSource::Tunnel, "auth-token abc");
        assert_eq!(text(&log), ["auth-token [redacted]"]);
    }

    #[test]
    fn clear_resets_lines_and_sequence() {
        let mut log = SessionLog::default();
        log.clear("p1");
        log.push(LogSource::Daemon, "one");
        log.clear("p2");
        assert_eq!(log.snapshot(), (Some("p2".to_owned()), Vec::new()));
        log.push(LogSource::Daemon, "two");
        assert_eq!(log.snapshot().1[0].seq, 0);
    }

    #[test]
    fn unpublished_lines_are_taken_once() {
        let mut log = SessionLog::default();
        log.clear("p1");
        assert!(log.push(LogSource::Daemon, "one"));
        assert!(!log.push(LogSource::Daemon, "two"));
        let (id, lines) = log.take_unpublished().unwrap();
        assert_eq!((id.as_str(), lines.len()), ("p1", 2));
        assert!(log.take_unpublished().is_none());
        assert!(log.push(LogSource::Daemon, "three"));
        assert_eq!(log.take_unpublished().unwrap().1[0].seq, 2);
    }
}
