use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

pub trait Exec: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<String>;
}

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy)]
pub struct SystemExec {
    timeout: Duration,
}

impl SystemExec {
    #[cfg(test)]
    pub const fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for SystemExec {
    fn default() -> Self {
        Self {
            timeout: COMMAND_TIMEOUT,
        }
    }
}

fn drain(pipe: Option<impl Read + Send + 'static>) -> Option<mpsc::Receiver<Vec<u8>>> {
    pipe.map(|mut pipe| {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            let _ = sender.send(bytes);
        });
        receiver
    })
}

fn collected(receiver: Option<mpsc::Receiver<Vec<u8>>>, deadline: Instant) -> Vec<u8> {
    receiver
        .and_then(|receiver| {
            receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .ok()
        })
        .unwrap_or_default()
}

impl Exec for SystemExec {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<String> {
        let mut command = Command::new(program);
        command
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
        let mut child = command.spawn()?;
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{program} did not finish within {} s",
                        self.timeout.as_secs()
                    ),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = String::from_utf8_lossy(&collected(stdout, deadline)).into_owned();
        if !status.success() {
            let stderr = String::from_utf8_lossy(&collected(stderr, deadline)).into_owned();
            let detail = [stderr.trim(), stdout.trim()]
                .into_iter()
                .find(|text| !text.is_empty())
                .and_then(|text| text.lines().next())
                .unwrap_or_default();
            return Err(io::Error::other(format!(
                "{program} exited with {status}: {detail}"
            )));
        }
        Ok(stdout)
    }
}

#[cfg(all(test, unix))]
mod system_tests {
    use super::*;

    #[test]
    fn a_hung_child_is_killed_at_the_timeout() {
        let exec = SystemExec::with_timeout(Duration::from_millis(200));
        let started = Instant::now();
        let err = exec.run("/bin/sleep", &["30"]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn output_and_failures_are_reported() {
        let exec = SystemExec::default();
        assert_eq!(exec.run("/bin/echo", &["hello"]).unwrap().trim(), "hello");
        let err = exec
            .run("/bin/ls", &["/nonexistent-wyvpn-path"])
            .unwrap_err();
        assert!(err.to_string().contains("exited with"), "{err}");
    }
}

#[cfg(test)]
pub mod fake {
    use std::io;
    use std::sync::{Arc, Mutex, PoisonError};

    use super::Exec;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Call {
        pub program: String,
        pub args: Vec<String>,
    }

    impl Call {
        pub fn line(&self) -> String {
            let program = self.program.rsplit(['/', '\\']).next().unwrap_or_default();
            std::iter::once(program)
                .chain(self.args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ")
        }
    }

    #[derive(Default)]
    struct Inner {
        calls: Vec<Call>,
        responses: Vec<(String, String)>,
    }

    #[derive(Clone, Default)]
    pub struct FakeExec(Arc<Mutex<Inner>>);

    impl FakeExec {
        fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        pub fn respond(&self, line_part: &str, output: &str) {
            self.lock()
                .responses
                .push((line_part.to_owned(), output.to_owned()));
        }

        pub fn calls(&self) -> Vec<Call> {
            self.lock().calls.clone()
        }

        pub fn lines(&self) -> Vec<String> {
            self.calls().iter().map(Call::line).collect()
        }
    }

    impl Exec for FakeExec {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<String> {
            let call = Call {
                program: program.to_owned(),
                args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            };
            let line = call.line();
            let mut inner = self.lock();
            inner.calls.push(call);
            Ok(inner
                .responses
                .iter()
                .find(|(part, _)| line.contains(part))
                .map(|(_, output)| output.clone())
                .unwrap_or_default())
        }
    }
}
