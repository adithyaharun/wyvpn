use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use wyvpn_core::tls::Pins;
use wyvpn_core::{Profile, ProfileHeader, Secret};
use zeroize::Zeroizing;

use crate::state::{ProfileSource, StoredProfile, summarize};
use wyvpn_ipc::ProfileSummary;

pub const DATA_DIR_ENV: &str = "WYVPN_DATA_DIR";

const SECRET_BLOCKS: [&str; 3] = ["key", "tls-auth", "tls-crypt"];
const MAX_ID_LEN: usize = 64;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
struct PublicRecord {
    id: String,
    name: String,
    #[serde(default)]
    display_name: Option<String>,
    header: ProfileHeader,
    ovpn: String,
}

#[derive(Serialize, Deserialize, Default)]
struct SecretRecord {
    sync_token: Option<Secret>,
    sync_secret: Option<Secret>,
    #[serde(default)]
    blocks: BTreeMap<String, Secret>,
    #[serde(default)]
    tls_pins: Pins,
}

pub fn default_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(DATA_DIR_ENV).filter(|dir| !dir.is_empty()) {
        return PathBuf::from(dir);
    }
    platform_dir()
}

#[cfg(target_os = "macos")]
fn platform_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/WyVPN")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_dir() -> PathBuf {
    PathBuf::from("/var/lib/wyvpn")
}

#[cfg(windows)]
fn platform_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    PathBuf::from(base).join("WyVPN")
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn strip_secret_blocks(ovpn: &str) -> (String, BTreeMap<String, Secret>) {
    let mut text = Zeroizing::new(ovpn.to_owned());
    let mut blocks = BTreeMap::new();
    for tag in SECRET_BLOCKS {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let Some(start) = text.find(&open) else {
            continue;
        };
        let inner_start = start + open.len();
        let Some(len) = text[inner_start..].find(&close) else {
            continue;
        };
        let inner = text[inner_start..inner_start + len].trim().to_owned();
        text.replace_range(inner_start..inner_start + len, "");
        blocks.insert(tag.to_owned(), Secret::new(inner));
    }
    (text.to_string(), blocks)
}

fn restore_secret_blocks(ovpn: &str, blocks: &BTreeMap<String, Secret>) -> Secret {
    let mut text = Zeroizing::new(ovpn.to_owned());
    for (tag, inner) in blocks {
        let empty = format!("<{tag}></{tag}>");
        if let Some(start) = text.find(&empty) {
            let filled = Zeroizing::new(format!("<{tag}>\n{}\n</{tag}>", inner.expose()));
            text.replace_range(start..start + empty.len(), &filled);
        }
    }
    Secret::from(std::mem::take(&mut *text))
}

pub struct FileProfiles {
    dir: PathBuf,
}

impl FileProfiles {
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        prepare_dir(&dir)?;
        Ok(Self { dir })
    }

    fn public_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    fn secret_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.secrets.json"))
    }

    fn read_public(&self, id: &str) -> io::Result<Option<PublicRecord>> {
        match fs::read(self.public_path(id)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "corrupt profile record")),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn read_secrets(&self, id: &str) -> io::Result<SecretRecord> {
        match fs::read(self.secret_path(id)).map(Zeroizing::new) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "corrupt secrets record")),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(SecretRecord::default()),
            Err(err) => Err(err),
        }
    }
}

impl ProfileSource for FileProfiles {
    fn summaries(&self) -> Vec<ProfileSummary> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut summaries: Vec<ProfileSummary> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let file_name = entry.file_name().into_string().ok()?;
                let id = file_name.strip_suffix(".json")?;
                if !valid_id(id) {
                    return None;
                }
                match self.read_public(id) {
                    Ok(Some(record)) => Some(summarize(
                        &Profile {
                            header: record.header,
                            ovpn: Secret::from(record.ovpn),
                        },
                        &record.id,
                        &record.name,
                        record.display_name.as_deref(),
                    )),
                    Ok(None) => None,
                    Err(err) => {
                        tracing::warn!(profile = id, %err, "skipping unreadable profile");
                        None
                    }
                }
            })
            .collect();
        summaries.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        summaries
    }

    fn load(&self, id: &str) -> io::Result<Option<StoredProfile>> {
        if !valid_id(id) {
            return Ok(None);
        }
        let Some(record) = self.read_public(id)? else {
            return Ok(None);
        };
        let secrets = self.read_secrets(id)?;
        let mut header = record.header;
        header.sync_token = secrets.sync_token;
        header.sync_secret = secrets.sync_secret;
        Ok(Some(StoredProfile {
            id: record.id,
            name: record.name,
            display_name: record.display_name,
            profile: Profile {
                header,
                ovpn: restore_secret_blocks(&record.ovpn, &secrets.blocks),
            },
            tls_pins: secrets.tls_pins,
        }))
    }

    fn save(&self, stored: &StoredProfile) -> io::Result<()> {
        if !valid_id(&stored.id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid profile id",
            ));
        }
        let (ovpn, blocks) = strip_secret_blocks(stored.profile.ovpn.expose());
        let mut header = stored.profile.header.clone();
        let secrets = SecretRecord {
            sync_token: header.sync_token.take(),
            sync_secret: header.sync_secret.take(),
            blocks,
            tls_pins: stored.tls_pins.clone(),
        };
        let public = PublicRecord {
            id: stored.id.clone(),
            name: stored.name.clone(),
            display_name: stored.display_name.clone(),
            header,
            ovpn,
        };

        let secret_bytes = Zeroizing::new(serde_json::to_vec(&secrets).map_err(io::Error::from)?);
        write_atomic(
            &self.dir,
            &format!("{}.secrets.json", stored.id),
            &secret_bytes,
        )?;
        let public_bytes = serde_json::to_vec(&public).map_err(io::Error::from)?;
        write_atomic(&self.dir, &format!("{}.json", stored.id), &public_bytes)
    }

    fn remove(&self, id: &str) -> io::Result<bool> {
        if !valid_id(id) {
            return Ok(false);
        }
        let existed = remove_if_present(&self.public_path(id))?;
        remove_if_present(&self.secret_path(id))?;
        if existed {
            sync_dir(&self.dir)?;
        }
        Ok(existed)
    }
}

pub(crate) fn remove_if_present(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

pub(crate) fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temp = dir.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = create_private(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, dir.join(name))?;
        sync_dir(dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub(crate) fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(windows)]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn prepare_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    if fs::metadata(dir)?.uid() != nix::unistd::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not owned by the daemon user", dir.display()),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn prepare_dir(dir: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::ptr;

    use windows_sys::Win32::Foundation::{FALSE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        IsWellKnownSid, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };

    const REPARSE_POINT: u32 = 0x400;
    const DATA_DIR_SDDL: &str = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    fn win32(code: u32) -> io::Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code as i32))
        }
    }

    fs::create_dir_all(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.file_attributes() & REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a plain directory", dir.display()),
        ));
    }

    let wide = |text: &std::ffi::OsStr| -> Vec<u16> { text.encode_wide().chain(Some(0)).collect() };
    let path = wide(dir.as_os_str());
    let sddl = wide(std::ffi::OsStr::new(DATA_DIR_SDDL));

    let mut raw: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = Descriptor(raw);

    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let (mut present, mut defaulted) = (0, 0);
    let parsed = unsafe {
        GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) != 0
            && GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) != 0
    };
    if !parsed || present == FALSE || dacl.is_null() {
        return Err(io::Error::other(
            "cannot build the data directory descriptor",
        ));
    }

    let protected = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let set = |info, owner: PSID| unsafe {
        win32(SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            info,
            owner,
            ptr::null_mut(),
            dacl,
            ptr::null(),
        ))
    };
    if set(protected | OWNER_SECURITY_INFORMATION, owner).is_err() {
        set(protected, ptr::null_mut())?;
    }

    let mut current: PSID = ptr::null_mut();
    let mut holder: PSECURITY_DESCRIPTOR = ptr::null_mut();
    win32(unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut current,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut holder,
        )
    })?;
    let _holder = Descriptor(holder);
    let trusted = unsafe {
        IsWellKnownSid(current, WinLocalSystemSid) != 0
            || IsWellKnownSid(current, WinBuiltinAdministratorsSid) != 0
    };
    if trusted {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not owned by SYSTEM or Administrators", dir.display()),
        ))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::testdata;

    const SYNC_SECRET: &str = "Xy9Pq2Lm7Nr4St6Uv8Wz0Ab3Cd5Ef1Gh";
    const SYNC_TOKEN: &str = "Ns7d8KJmQw2xY4pZ0aB1cD3eF5gH6iJk";

    pub fn stored() -> StoredProfile {
        let profile = Profile::parse(&testdata::ovpn(&[])).unwrap();
        StoredProfile {
            id: "abc123".into(),
            name: "office".into(),
            display_name: None,
            profile,
            tls_pins: Pins::from([(
                "vpn.example.com:443".to_owned(),
                wyvpn_core::tls::Fingerprint::of_certificate(b"cert"),
            )]),
        }
    }

    #[test]
    fn round_trip_keeps_secrets_out_of_the_public_file() {
        let dir = crate::testdata::private_tempdir();
        let store = FileProfiles::open(dir.path().join("data")).unwrap();
        let original = stored();
        store.save(&original).unwrap();

        let loaded = store.load("abc123").unwrap().unwrap();
        assert_eq!(loaded.name, "office");
        assert_eq!(loaded.tls_pins, original.tls_pins);
        assert_eq!(
            loaded.profile.ovpn.expose().trim(),
            original.profile.ovpn.expose().trim()
        );
        assert_eq!(
            loaded.profile.header.sync_secret.as_ref().unwrap().expose(),
            SYNC_SECRET
        );
        assert_eq!(
            loaded.profile.header.sync_token.as_ref().unwrap().expose(),
            SYNC_TOKEN
        );
        assert_eq!(
            loaded.profile.private_key_pem().unwrap().expose(),
            original.profile.private_key_pem().unwrap().expose()
        );
        assert_eq!(loaded.summary(), original.summary());

        let public = fs::read_to_string(store.public_path("abc123")).unwrap();
        for needle in [SYNC_SECRET, SYNC_TOKEN, "PRIVATE KEY", "TA\n"] {
            assert!(!public.contains(needle), "public file leaks {needle:?}");
        }
        let secrets = fs::read_to_string(store.secret_path("abc123")).unwrap();
        assert!(secrets.contains(SYNC_SECRET));
        assert!(secrets.contains("PRIVATE KEY"));
    }

    #[test]
    fn display_name_round_trips_and_old_records_load_unchanged() {
        let dir = crate::testdata::private_tempdir();
        let store = FileProfiles::open(dir.path().to_path_buf()).unwrap();
        let mut item = stored();
        item.display_name = Some("Home".into());
        store.save(&item).unwrap();
        let loaded = store.load("abc123").unwrap().unwrap();
        assert_eq!(loaded.display_name.as_deref(), Some("Home"));
        let summary = &store.summaries()[0];
        assert_eq!(summary.name, "Home");
        assert_eq!(summary.imported_name.as_deref(), Some("office"));

        let path = store.public_path("abc123");
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        record.as_object_mut().unwrap().remove("display_name");
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        let loaded = store.load("abc123").unwrap().unwrap();
        assert_eq!(loaded.display_name, None);
        assert_eq!(loaded.name, "office");
        let summary = &store.summaries()[0];
        assert_eq!(summary.name, "office");
        assert_eq!(summary.imported_name, None);
    }

    #[test]
    fn list_remove_and_overwrite() {
        let dir = crate::testdata::private_tempdir();
        let store = FileProfiles::open(dir.path().to_path_buf()).unwrap();
        assert!(store.summaries().is_empty());
        assert!(store.load("abc123").unwrap().is_none());

        let mut item = stored();
        store.save(&item).unwrap();
        item.name = "renamed".into();
        store.save(&item).unwrap();
        let summaries = store.summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "renamed");

        assert!(store.remove("abc123").unwrap());
        assert!(!store.remove("abc123").unwrap());
        assert!(store.summaries().is_empty());
        assert!(!store.secret_path("abc123").exists());
    }

    #[test]
    fn ids_cannot_escape_the_directory() {
        let dir = crate::testdata::private_tempdir();
        let store = FileProfiles::open(dir.path().join("data")).unwrap();
        fs::write(dir.path().join("evil.json"), b"{}").unwrap();
        for id in ["../evil", "a/b", "", "a.b", &"x".repeat(65)] {
            assert!(store.load(id).unwrap().is_none());
            assert!(!store.remove(id).unwrap());
        }
        let mut item = stored();
        item.id = "../evil".into();
        assert!(store.save(&item).is_err());
        assert!(dir.path().join("evil.json").exists());
    }

    #[test]
    fn corrupt_records_are_skipped_in_listings() {
        let dir = crate::testdata::private_tempdir();
        let store = FileProfiles::open(dir.path().to_path_buf()).unwrap();
        store.save(&stored()).unwrap();
        fs::write(store.public_path("broken"), b"not json").unwrap();
        assert_eq!(store.summaries().len(), 1);
        assert!(store.load("broken").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = crate::testdata::private_tempdir();
        let data = dir.path().join("data");
        let store = FileProfiles::open(data.clone()).unwrap();
        store.save(&stored()).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&store.secret_path("abc123")), 0o600);
        assert_eq!(mode(&store.public_path("abc123")), 0o600);

        fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
        FileProfiles::open(data.clone()).unwrap();
        assert_eq!(mode(&data), 0o700);

        let leftovers = fs::read_dir(&data)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }
}
