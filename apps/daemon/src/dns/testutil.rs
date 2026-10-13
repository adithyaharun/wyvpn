use std::cell::RefCell;
use std::collections::HashMap;
use std::io;

use super::Runner;

#[derive(Debug, Clone)]
pub struct Call {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<String>,
}

#[derive(Default)]
pub struct FakeRunner {
    calls: RefCell<Vec<Call>>,
    responses: RefCell<HashMap<String, String>>,
    failing: RefCell<Option<String>>,
}

impl FakeRunner {
    pub fn respond(&self, stdin: &str, output: &str) {
        self.responses
            .borrow_mut()
            .insert(stdin.to_owned(), output.to_owned());
    }

    pub fn fail_on(&self, arg: &str) {
        *self.failing.borrow_mut() = Some(arg.to_owned());
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.borrow().clone()
    }
}

impl Runner for FakeRunner {
    fn run(&self, program: &str, args: &[&str], stdin: Option<&str>) -> io::Result<String> {
        self.calls.borrow_mut().push(Call {
            program: program.to_owned(),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            stdin: stdin.map(str::to_owned),
        });
        if let Some(bad) = self.failing.borrow().as_deref() {
            if args.contains(&bad) {
                return Err(io::Error::other("injected failure"));
            }
        }
        let key = stdin.map(str::trim).unwrap_or_default();
        Ok(self
            .responses
            .borrow()
            .get(key)
            .cloned()
            .unwrap_or_default())
    }
}

pub fn mkdirs(root: &std::path::Path, rel: &str) {
    std::fs::create_dir_all(root.join(rel)).unwrap();
}
