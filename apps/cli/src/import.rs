use std::io::{BufRead, Read};
use std::path::Path;

use anyhow::{Context, bail};
use wyvpn_ipc::{ImportSource, MAX_IMPORT_BYTES};

const MAX_LINK_BYTES: u64 = 8192;

pub fn read_file(path: &Path) -> anyhow::Result<ImportSource> {
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let mut bytes = Vec::new();
    file.take(MAX_IMPORT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_IMPORT_BYTES {
        bail!(
            "{} is larger than {} KiB",
            path.display(),
            MAX_IMPORT_BYTES / 1024
        );
    }
    let name = path
        .file_name()
        .map_or_else(|| "profile".into(), |n| n.to_string_lossy().into_owned());
    Ok(ImportSource::file(name, &bytes))
}

pub fn resolve(arg: &str, mut stdin: impl BufRead) -> anyhow::Result<ImportSource> {
    let from_stdin = arg == "-";
    let value = if from_stdin {
        let mut line = String::new();
        (&mut stdin).take(MAX_LINK_BYTES).read_line(&mut line)?;
        line.trim().to_owned()
    } else {
        arg.to_owned()
    };
    if value.is_empty() {
        bail!("nothing to import");
    }
    if Path::new(&value).is_file() {
        return read_file(Path::new(&value));
    }
    if !from_stdin {
        eprintln!(
            "warning: a link on the command line is visible to other users; use `wyvpn-cli import -` to read it from stdin"
        );
    }
    Ok(ImportSource::uri(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_read_and_oversize_files_refused() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("a.ovpn");
        std::fs::write(&small, "hello").unwrap();
        let ImportSource::File { name, data } = resolve(small.to_str().unwrap(), &b""[..]).unwrap()
        else {
            panic!();
        };
        assert_eq!(name, "a.ovpn");
        assert_eq!(data.decode_base64().unwrap().as_slice(), b"hello");

        let big = dir.path().join("big.ovpn");
        std::fs::write(&big, vec![b'x'; MAX_IMPORT_BYTES + 1]).unwrap();
        assert!(read_file(&big).is_err());
    }

    #[test]
    fn stdin_accepts_links_and_paths() {
        let ImportSource::Uri { uri } = resolve("-", &b"vpn.example.com/ku/abc\n"[..]).unwrap()
        else {
            panic!();
        };
        assert_eq!(uri.expose(), "vpn.example.com/ku/abc");
        assert!(resolve("-", &b"\n"[..]).is_err());
    }
}
