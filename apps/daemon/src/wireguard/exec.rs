use std::io;
use std::process::{Command, Stdio};

pub trait Exec: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<String>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemExec;

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
        let output = command.output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = [stderr.trim(), stdout.trim()]
                .into_iter()
                .find(|text| !text.is_empty())
                .and_then(|text| text.lines().next())
                .unwrap_or_default();
            return Err(io::Error::other(format!(
                "{program} exited with {}: {detail}",
                output.status
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
        failures: Vec<(String, String)>,
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

        pub fn fail(&self, line_part: &str, message: &str) {
            self.lock()
                .failures
                .push((line_part.to_owned(), message.to_owned()));
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
            if let Some((_, message)) = inner.failures.iter().find(|(part, _)| line.contains(part))
            {
                return Err(io::Error::other(message.clone()));
            }
            Ok(inner
                .responses
                .iter()
                .find(|(part, _)| line.contains(part))
                .map(|(_, output)| output.clone())
                .unwrap_or_default())
        }
    }
}
