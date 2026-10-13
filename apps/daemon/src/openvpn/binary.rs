use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

pub const MIN_VERSION: Version = Version {
    major: 2,
    minor: 5,
    patch: 0,
};

#[cfg(unix)]
const ROOT_UID: u32 = 0;
#[cfg(not(unix))]
const ROOT_UID: u32 = 0;
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone)]
pub struct OpenVpnBinary {
    pub path: PathBuf,
    pub version: Version,
}

#[derive(Debug, thiserror::Error)]
pub enum BinaryError {
    #[error("no trusted openvpn binary found; searched: {}", join_paths(.searched))]
    NotFound { searched: Vec<PathBuf> },
    #[error("{} is not a regular file", .0.display())]
    NotRegularFile(PathBuf),
    #[error("{} is owned by uid {uid}, expected uid {expected}", path.display())]
    #[cfg_attr(not(unix), allow(dead_code))]
    WrongOwner {
        path: PathBuf,
        uid: u32,
        expected: u32,
    },
    #[error("{} is writable by group or others", .0.display())]
    #[cfg_attr(not(unix), allow(dead_code))]
    Writable(PathBuf),
    #[error("cannot determine the version of {}: {reason}", path.display())]
    VersionUnreadable { path: PathBuf, reason: String },
    #[error("{} is OpenVPN {found}; {MIN_VERSION} or later is required", path.display())]
    VersionTooOld { path: PathBuf, found: Version },
    #[error("signature verification failed for {}: {reason}", path.display())]
    SignatureInvalid { path: PathBuf, reason: String },
    #[error("cannot inspect {}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
}

fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn candidate_paths() -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        [
            "/opt/homebrew/sbin/openvpn",
            "/usr/local/sbin/openvpn",
            "/usr/sbin/openvpn",
            "/usr/bin/openvpn",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect()
    }
    #[cfg(windows)]
    {
        std::env::var_os("ProgramFiles")
            .map(|base| {
                PathBuf::from(base)
                    .join("OpenVPN")
                    .join("bin")
                    .join("openvpn.exe")
            })
            .into_iter()
            .collect()
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
pub struct Trust<'a> {
    pub uid: u32,
    pub exempt: Option<&'a Path>,
}

impl Trust<'static> {
    pub const fn root() -> Self {
        Self {
            uid: ROOT_UID,
            exempt: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    Pass,
    #[cfg_attr(windows, allow(dead_code))]
    Skip(String),
    Fail(String),
}

pub fn bundled_in(exe_dir: &Path) -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        Some(exe_dir.parent()?.join("Resources/openvpn/openvpn"))
    } else if cfg!(windows) {
        Some(exe_dir.join("openvpn").join("openvpn.exe"))
    } else {
        None
    }
}

pub fn bundled_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    bundled_in(exe.parent()?)
}

pub fn locate(override_path: Option<&Path>, data_dir: &Path) -> Result<OpenVpnBinary, BinaryError> {
    match override_path {
        Some(path) => locate_in(&[path.to_path_buf()], &Trust::root(), query_version),
        None => locate_with(
            bundled_path().as_deref(),
            cfg!(target_os = "macos")
                .then(|| super::stage::bin_dir(data_dir))
                .as_deref(),
            &candidate_paths(),
            &Trust::root(),
            &super::signature::verify,
            query_version,
        ),
    }
}

pub fn locate_with(
    bundled: Option<&Path>,
    stage_dir: Option<&Path>,
    candidates: &[PathBuf],
    trust: &Trust<'_>,
    verify: &dyn Fn(&Path) -> Check,
    version_of: impl Fn(&Path) -> io::Result<String>,
) -> Result<OpenVpnBinary, BinaryError> {
    if let Some(bundled) = bundled {
        if let Some(binary) = inspect_bundled(bundled, stage_dir, verify, &version_of)? {
            return Ok(binary);
        }
    }
    locate_in(candidates, trust, version_of)
}

fn inspect_bundled(
    path: &Path,
    stage_dir: Option<&Path>,
    verify: &dyn Fn(&Path) -> Check,
    version_of: &impl Fn(&Path) -> io::Result<String>,
) -> Result<Option<OpenVpnBinary>, BinaryError> {
    let io_error = |source| BinaryError::Io {
        path: path.to_path_buf(),
        source,
    };
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(io_error(err)),
    };
    if !meta.is_file() {
        return Err(BinaryError::NotRegularFile(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o022 != 0 {
            return Err(BinaryError::Writable(path.to_path_buf()));
        }
    }
    if let Some(reason) = match verify(path) {
        Check::Pass => None,
        Check::Skip(reason) => {
            tracing::info!(path = %path.display(), reason, "bundled openvpn not trusted, trying system paths");
            return Ok(None);
        }
        Check::Fail(reason) => Some(reason),
    } {
        return Err(BinaryError::SignatureInvalid {
            path: path.to_path_buf(),
            reason,
        });
    }
    let Some(dir) = stage_dir else {
        return check_version(path.to_path_buf(), version_of).map(Some);
    };
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let staged = super::stage::stage(path, dir, &name).map_err(io_error)?;
    if let Check::Fail(reason) | Check::Skip(reason) = verify(&staged) {
        return Err(BinaryError::SignatureInvalid {
            path: staged,
            reason,
        });
    }
    check_version(staged, version_of).map(Some)
}

pub fn locate_in(
    candidates: &[PathBuf],
    trust: &Trust<'_>,
    version_of: impl Fn(&Path) -> io::Result<String>,
) -> Result<OpenVpnBinary, BinaryError> {
    let mut first_error = None;
    for candidate in candidates {
        match inspect(candidate, trust, &version_of) {
            Ok(binary) => return Ok(binary),
            Err(BinaryError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                first_error.get_or_insert(err);
            }
        }
    }
    Err(first_error.unwrap_or_else(|| BinaryError::NotFound {
        searched: candidates.to_vec(),
    }))
}

fn inspect(
    candidate: &Path,
    trust: &Trust<'_>,
    version_of: &impl Fn(&Path) -> io::Result<String>,
) -> Result<OpenVpnBinary, BinaryError> {
    let path = resolve_trusted(candidate, trust)?;
    check_version(path, version_of)
}

fn check_version(
    path: PathBuf,
    version_of: &impl Fn(&Path) -> io::Result<String>,
) -> Result<OpenVpnBinary, BinaryError> {
    let output = version_of(&path).map_err(|err| BinaryError::VersionUnreadable {
        path: path.clone(),
        reason: err.to_string(),
    })?;
    let version = parse_version(&output).ok_or_else(|| BinaryError::VersionUnreadable {
        path: path.clone(),
        reason: "unrecognised --version output".to_owned(),
    })?;
    if version < MIN_VERSION {
        return Err(BinaryError::VersionTooOld {
            path,
            found: version,
        });
    }
    Ok(OpenVpnBinary { path, version })
}

#[cfg(not(unix))]
pub fn resolve_trusted(candidate: &Path, _trust: &Trust<'_>) -> Result<PathBuf, BinaryError> {
    let io_error = |source| BinaryError::Io {
        path: candidate.to_path_buf(),
        source,
    };
    let path = fs::canonicalize(candidate).map_err(io_error)?;
    if !fs::metadata(&path).map_err(io_error)?.is_file() {
        return Err(BinaryError::NotRegularFile(path));
    }
    Ok(path)
}

#[cfg(unix)]
enum Step {
    Parent,
    Name(std::ffi::OsString),
}

#[cfg(unix)]
fn steps(path: &Path) -> Vec<Step> {
    use std::path::Component;

    path.components()
        .filter_map(|component| match component {
            Component::ParentDir => Some(Step::Parent),
            Component::Normal(name) => Some(Step::Name(name.to_owned())),
            _ => None,
        })
        .collect()
}

#[cfg(unix)]
pub fn resolve_trusted(candidate: &Path, trust: &Trust<'_>) -> Result<PathBuf, BinaryError> {
    use std::collections::VecDeque;
    use std::os::unix::fs::MetadataExt;

    const MAX_LINKS: u32 = 40;

    let io_error = |path: &Path, source| BinaryError::Io {
        path: path.to_path_buf(),
        source,
    };
    let exempt = |path: &Path| trust.exempt.is_some_and(|root| root.starts_with(path));
    let check_owner_and_mode = |path: &Path, meta: &fs::Metadata, mode: bool| {
        if exempt(path) {
            return Ok(());
        }
        let mode = if mode { meta.mode() } else { 0 };
        check_unix_owner_and_mode(path, meta.uid(), mode, trust.uid)
    };

    let absolute = std::path::absolute(candidate).map_err(|err| io_error(candidate, err))?;
    let mut pending: VecDeque<Step> = steps(&absolute).into();
    let mut resolved = PathBuf::from("/");
    let root_meta = fs::symlink_metadata(&resolved).map_err(|err| io_error(&resolved, err))?;
    check_owner_and_mode(&resolved, &root_meta, true)?;

    let mut links = 0;
    while let Some(step) = pending.pop_front() {
        let name = match step {
            Step::Parent => {
                resolved.pop();
                continue;
            }
            Step::Name(name) => name,
        };
        let next = resolved.join(name);
        let meta = fs::symlink_metadata(&next).map_err(|err| io_error(&next, err))?;
        if meta.file_type().is_symlink() {
            check_owner_and_mode(&next, &meta, false)?;
            links += 1;
            if links > MAX_LINKS {
                return Err(io_error(
                    &next,
                    io::Error::other("too many levels of symbolic links"),
                ));
            }
            let target = fs::read_link(&next).map_err(|err| io_error(&next, err))?;
            if target.is_absolute() {
                resolved = PathBuf::from("/");
            }
            for step in steps(&target).into_iter().rev() {
                pending.push_front(step);
            }
            continue;
        }
        if !pending.is_empty() {
            if !meta.is_dir() {
                return Err(io_error(&next, io::ErrorKind::NotADirectory.into()));
            }
            check_owner_and_mode(&next, &meta, true)?;
        }
        resolved = next;
    }

    let meta = fs::symlink_metadata(&resolved).map_err(|err| io_error(&resolved, err))?;
    if !meta.is_file() {
        return Err(BinaryError::NotRegularFile(resolved));
    }
    check_owner_and_mode(&resolved, &meta, true)?;
    Ok(resolved)
}

#[cfg(unix)]
pub fn check_unix_owner_and_mode(
    path: &Path,
    uid: u32,
    mode: u32,
    expected_uid: u32,
) -> Result<(), BinaryError> {
    if uid != expected_uid {
        return Err(BinaryError::WrongOwner {
            path: path.to_path_buf(),
            uid,
            expected: expected_uid,
        });
    }
    if mode & 0o022 != 0 {
        return Err(BinaryError::Writable(path.to_path_buf()));
    }
    Ok(())
}

fn query_version(path: &Path) -> io::Result<String> {
    use std::io::Read;
    use std::time::Instant;

    let mut child = Command::new(path)
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        out
    });
    let deadline = Instant::now() + VERSION_TIMEOUT;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "--version timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = reader.join().unwrap_or_default();
    Ok(String::from_utf8_lossy(&out).into_owned())
}

pub fn parse_version(output: &str) -> Option<Version> {
    let first = output.lines().next()?;
    let token = first.strip_prefix("OpenVPN ")?.split_whitespace().next()?;
    let mut parts = token.split('.').map(|part| {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<u32>().ok()
    });
    let major = parts.next()??;
    let minor = parts.next()??;
    let patch = parts.next().flatten().unwrap_or(0);
    Some(Version {
        major,
        minor,
        patch,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn version(major: u32, minor: u32, patch: u32) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    #[test]
    fn parses_version_lines() {
        let line = "OpenVPN 2.7.8 aarch64-apple-darwin [SSL (OpenSSL)] built on Jan  1 2026\nlibrary versions: x\n";
        assert_eq!(parse_version(line), Some(version(2, 7, 8)));
        assert_eq!(
            parse_version("OpenVPN 2.6.12 x86_64"),
            Some(version(2, 6, 12))
        );
        assert_eq!(parse_version("OpenVPN 2.7_git x"), Some(version(2, 7, 0)));
        assert_eq!(parse_version("OpenVPN 2.7_rc1 x"), Some(version(2, 7, 0)));
        assert_eq!(parse_version("OpenVPN 3 x"), None);
        assert_eq!(parse_version("Something else 2.6.0"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn compares_against_minimum() {
        assert!(version(2, 4, 12) < MIN_VERSION);
        assert!(version(2, 5, 0) >= MIN_VERSION);
        assert!(version(2, 6, 0) >= MIN_VERSION);
        assert!(version(3, 0, 0) >= MIN_VERSION);
    }

    #[test]
    fn not_found_names_every_searched_path() {
        let searched = vec![
            PathBuf::from("/nonexistent/a/openvpn"),
            PathBuf::from("/nonexistent/b/openvpn"),
        ];
        let err = locate_in(&searched, &Trust::root(), |_| Ok(String::new())).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("/nonexistent/a/openvpn"));
        assert!(message.contains("/nonexistent/b/openvpn"));
        assert!(matches!(err, BinaryError::NotFound { .. }));
    }

    mod bundled {
        use super::*;

        fn current_uid() -> u32 {
            #[cfg(unix)]
            return nix::unistd::getuid().as_raw();
            #[cfg(not(unix))]
            0
        }

        const GOOD: &str = "OpenVPN 2.6.12 x86_64\n";

        struct Layout {
            _dir: tempfile::TempDir,
            base: PathBuf,
            bundled: PathBuf,
            system: PathBuf,
        }

        fn layout(bundled_exists: bool) -> Layout {
            let dir = tempfile::tempdir().unwrap();
            let base = fs::canonicalize(dir.path()).unwrap();
            let bundled = base.join("bundled-openvpn");
            let system = base.join("system-openvpn");
            if bundled_exists {
                fs::write(&bundled, b"b").unwrap();
            }
            fs::write(&system, b"s").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for path in [&bundled, &system] {
                    if path.exists() {
                        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
                    }
                }
            }
            Layout {
                _dir: dir,
                base,
                bundled,
                system,
            }
        }

        fn run(layout: &Layout, check: Check) -> Result<OpenVpnBinary, BinaryError> {
            let trust = Trust {
                uid: current_uid(),
                exempt: Some(&layout.base),
            };
            locate_with(
                Some(&layout.bundled),
                None,
                std::slice::from_ref(&layout.system),
                &trust,
                &|_| check.clone(),
                |_| Ok(GOOD.to_owned()),
            )
        }

        #[test]
        fn prefers_the_verified_bundle() {
            let layout = layout(true);
            let found = run(&layout, Check::Pass).unwrap();
            assert_eq!(found.path, layout.bundled);
        }

        #[test]
        fn failed_verification_is_reported_not_bypassed() {
            let layout = layout(true);
            let err = run(&layout, Check::Fail("bad signature".into())).unwrap_err();
            assert!(matches!(err, BinaryError::SignatureInvalid { .. }));
            assert!(err.to_string().contains("signature verification failed"));
        }

        #[test]
        fn missing_bundle_falls_through() {
            let layout = layout(false);
            let found = run(&layout, Check::Fail("unused".into())).unwrap();
            assert_eq!(found.path, layout.system);
        }

        #[test]
        fn unconfigured_verifier_falls_through() {
            let layout = layout(true);
            let found = run(&layout, Check::Skip("no team id".into())).unwrap();
            assert_eq!(found.path, layout.system);
        }

        #[test]
        fn verifier_is_not_consulted_for_a_missing_bundle() {
            let layout = layout(false);
            let trust = Trust {
                uid: current_uid(),
                exempt: Some(&layout.base),
            };
            let found = locate_with(
                Some(&layout.bundled),
                None,
                std::slice::from_ref(&layout.system),
                &trust,
                &|_| panic!("verifier must not run"),
                |_| Ok(GOOD.to_owned()),
            );
            assert!(found.is_ok());
        }

        fn run_staged(
            layout: &Layout,
            check: Check,
            seen: &Mutex<Vec<PathBuf>>,
        ) -> Result<OpenVpnBinary, BinaryError> {
            let trust = Trust {
                uid: current_uid(),
                exempt: Some(&layout.base),
            };
            locate_with(
                Some(&layout.bundled),
                Some(&layout.base.join("stage")),
                std::slice::from_ref(&layout.system),
                &trust,
                &|path| {
                    seen.lock().unwrap().push(path.to_path_buf());
                    check.clone()
                },
                |_| Ok(GOOD.to_owned()),
            )
        }

        #[test]
        fn verified_bundle_runs_from_a_verified_copy() {
            let layout = layout(true);
            let seen = Mutex::new(Vec::new());
            let found = run_staged(&layout, Check::Pass, &seen).unwrap();
            let copy = layout.base.join("stage").join("bundled-openvpn");
            assert_eq!(found.path, copy);
            assert_eq!(fs::read(&copy).unwrap(), b"b");
            assert_eq!(*seen.lock().unwrap(), vec![layout.bundled.clone(), copy]);
        }

        #[test]
        fn copy_is_reused_then_refreshed() {
            let layout = layout(true);
            let seen = Mutex::new(Vec::new());
            let copy = layout.base.join("stage").join("bundled-openvpn");
            run_staged(&layout, Check::Pass, &seen).unwrap();
            fs::write(&copy, b"b").unwrap();
            let before = fs::metadata(&copy).unwrap().modified().unwrap();
            run_staged(&layout, Check::Pass, &seen).unwrap();
            assert_eq!(fs::metadata(&copy).unwrap().modified().unwrap(), before);

            fs::write(&layout.bundled, b"updated").unwrap();
            run_staged(&layout, Check::Pass, &seen).unwrap();
            assert_eq!(fs::read(&copy).unwrap(), b"updated");
        }

        #[test]
        fn failed_source_leaves_the_copy_alone() {
            let layout = layout(true);
            let seen = Mutex::new(Vec::new());
            let copy = layout.base.join("stage").join("bundled-openvpn");
            run_staged(&layout, Check::Pass, &seen).unwrap();
            fs::write(&layout.bundled, b"tampered").unwrap();
            let err = run_staged(&layout, Check::Fail("bad".into()), &seen).unwrap_err();
            assert!(matches!(err, BinaryError::SignatureInvalid { .. }));
            assert_eq!(fs::read(&copy).unwrap(), b"b");
        }

        #[cfg(unix)]
        #[test]
        fn writable_bundle_is_refused() {
            use std::os::unix::fs::PermissionsExt;
            let layout = layout(true);
            fs::set_permissions(&layout.bundled, fs::Permissions::from_mode(0o777)).unwrap();
            let err = run(&layout, Check::Pass).unwrap_err();
            assert!(matches!(err, BinaryError::Writable(_)));
        }

        #[test]
        fn bundled_locations() {
            let found = bundled_in(Path::new("/App/WyVPN.app/Contents/MacOS"));
            if cfg!(target_os = "macos") {
                assert_eq!(
                    found.unwrap(),
                    Path::new("/App/WyVPN.app/Contents/Resources/openvpn/openvpn")
                );
            } else if cfg!(windows) {
                assert!(
                    found
                        .unwrap()
                        .ends_with(Path::new("openvpn").join("openvpn.exe"))
                );
            } else {
                assert!(found.is_none());
            }
        }
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        struct Fixture {
            _dir: tempfile::TempDir,
            base: PathBuf,
            path: PathBuf,
            uid: u32,
        }

        impl Fixture {
            fn trust(&self) -> Trust<'_> {
                Trust {
                    uid: self.uid,
                    exempt: Some(&self.base),
                }
            }

            fn dir(&self, name: &str, mode: u32) -> PathBuf {
                let dir = self.base.join(name);
                fs::create_dir(&dir).unwrap();
                fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
                dir
            }

            fn binary_in(&self, dir: &Path) -> PathBuf {
                let path = dir.join("openvpn");
                fs::write(&path, b"#!/bin/sh\n").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
                path
            }
        }

        fn fixture(mode: u32) -> Fixture {
            let dir = crate::testdata::private_tempdir();
            let base = fs::canonicalize(dir.path()).unwrap();
            let path = base.join("openvpn");
            fs::write(&path, b"#!/bin/sh\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let uid = fs::metadata(&path).unwrap().uid();
            Fixture {
                _dir: dir,
                base,
                path,
                uid,
            }
        }

        fn ok_version(_: &Path) -> io::Result<String> {
            Ok("OpenVPN 2.6.8 x86_64\n".to_owned())
        }

        #[test]
        fn accepts_private_binary_with_matching_owner() {
            let f = fixture(0o755);
            let binary = locate_in(std::slice::from_ref(&f.path), &f.trust(), ok_version).unwrap();
            assert_eq!(binary.version, version(2, 6, 8));
            assert_eq!(binary.path, f.path);
        }

        #[test]
        fn rejects_world_writable_without_running_it() {
            let f = fixture(0o757);
            let err = locate_in(std::slice::from_ref(&f.path), &f.trust(), |_| {
                panic!("must not execute")
            })
            .unwrap_err();
            assert!(matches!(err, BinaryError::Writable(_)));
        }

        #[test]
        fn rejects_group_writable() {
            let f = fixture(0o775);
            let err = locate_in(std::slice::from_ref(&f.path), &f.trust(), ok_version).unwrap_err();
            assert!(matches!(err, BinaryError::Writable(_)));
        }

        #[test]
        fn rejects_wrong_owner() {
            let f = fixture(0o755);
            let trust = Trust {
                uid: f.uid.wrapping_add(1),
                exempt: Some(&f.base),
            };
            let err = locate_in(std::slice::from_ref(&f.path), &trust, ok_version).unwrap_err();
            assert!(matches!(err, BinaryError::WrongOwner { .. }));
        }

        #[test]
        fn rejects_directories() {
            let f = fixture(0o755);
            let err = locate_in(std::slice::from_ref(&f.base), &f.trust(), ok_version).unwrap_err();
            assert!(matches!(err, BinaryError::NotRegularFile(_)));
        }

        #[test]
        fn rejects_old_versions_and_garbage() {
            let f = fixture(0o755);
            let old = locate_in(std::slice::from_ref(&f.path), &f.trust(), |_| {
                Ok("OpenVPN 2.4.12 x\n".into())
            });
            assert!(matches!(old, Err(BinaryError::VersionTooOld { .. })));
            let junk = locate_in(std::slice::from_ref(&f.path), &f.trust(), |_| {
                Ok("hello\n".into())
            });
            assert!(matches!(junk, Err(BinaryError::VersionUnreadable { .. })));
        }

        #[test]
        fn follows_symlinks_and_checks_the_target() {
            let f = fixture(0o757);
            let link = f.base.join("link");
            std::os::unix::fs::symlink(&f.path, &link).unwrap();
            let err = locate_in(&[link], &f.trust(), ok_version).unwrap_err();
            assert!(matches!(err, BinaryError::Writable(p) if p == f.path));
        }

        #[test]
        fn returns_the_resolved_path_for_a_good_symlink() {
            let f = fixture(0o755);
            let link = f.base.join("link");
            std::os::unix::fs::symlink("openvpn", &link).unwrap();
            let binary = locate_in(&[link], &f.trust(), ok_version).unwrap();
            assert_eq!(binary.path, f.path);
        }

        #[test]
        fn falls_through_missing_candidates_to_a_valid_one() {
            let f = fixture(0o755);
            let candidates = [PathBuf::from("/nonexistent/openvpn"), f.path.clone()];
            assert!(locate_in(&candidates, &f.trust(), ok_version).is_ok());
        }

        #[test]
        fn accepts_a_good_nested_chain() {
            let f = fixture(0o755);
            let dir = f.dir("sbin", 0o755);
            let path = f.binary_in(&dir);
            assert_eq!(resolve_trusted(&path, &f.trust()).unwrap(), path);
        }

        #[test]
        fn rejects_ancestor_with_the_wrong_owner() {
            let f = fixture(0o755);
            let dir = f.dir("sbin", 0o755);
            let path = f.binary_in(&dir);
            if f.uid == 0 {
                return;
            }
            let trust = Trust {
                uid: 0,
                exempt: Some(&f.base),
            };
            let err = resolve_trusted(&path, &trust).unwrap_err();
            assert!(matches!(err, BinaryError::WrongOwner { path, .. } if path == dir));
        }

        #[test]
        fn rejects_writable_and_sticky_ancestors() {
            let f = fixture(0o755);
            for (name, mode) in [("group", 0o775), ("world", 0o777), ("sticky", 0o1777)] {
                let dir = f.dir(name, mode);
                let path = f.binary_in(&dir);
                let err = resolve_trusted(&path, &f.trust()).unwrap_err();
                assert!(
                    matches!(&err, BinaryError::Writable(p) if *p == dir),
                    "{name}: {err}"
                );
            }
        }

        #[test]
        fn rejects_symlink_chain_through_a_writable_directory() {
            let f = fixture(0o755);
            let good = f.dir("good", 0o755);
            let target = f.binary_in(&good);
            let loose = f.dir("loose", 0o777);
            let link = loose.join("openvpn");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let err = resolve_trusted(&link, &f.trust()).unwrap_err();
            assert!(matches!(&err, BinaryError::Writable(p) if *p == loose));
        }

        #[test]
        fn rejects_symlink_into_a_writable_directory() {
            let f = fixture(0o755);
            let loose = f.dir("loose", 0o777);
            let target = f.binary_in(&loose);
            let link = f.base.join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let err = resolve_trusted(&link, &f.trust()).unwrap_err();
            assert!(matches!(&err, BinaryError::Writable(p) if *p == loose));
        }

        #[test]
        fn rejects_symlink_loops() {
            let f = fixture(0o755);
            let link = f.base.join("loop");
            std::os::unix::fs::symlink(&link, &link).unwrap();
            assert!(resolve_trusted(&link, &f.trust()).is_err());
        }

        #[test]
        fn version_probe_times_out() {
            let f = fixture(0o755);
            fs::write(&f.path, b"#!/bin/sh\nsleep 30\n").unwrap();
            let started = std::time::Instant::now();
            let err = query_version(&f.path).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert!(started.elapsed() < Duration::from_secs(10));
        }

        #[test]
        fn owner_and_mode_checks() {
            let p = Path::new("/x");
            assert!(check_unix_owner_and_mode(p, 0, 0o100755, 0).is_ok());
            assert!(check_unix_owner_and_mode(p, 501, 0o100755, 0).is_err());
            assert!(check_unix_owner_and_mode(p, 0, 0o100775, 0).is_err());
            assert!(check_unix_owner_and_mode(p, 0, 0o100757, 0).is_err());
        }
    }
}
