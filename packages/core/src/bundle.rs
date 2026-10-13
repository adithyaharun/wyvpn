use crate::error::{Error, Result};
use crate::profile::Profile;
use std::io::Read;
use zeroize::Zeroizing;

const MAX_INPUT: usize = 3_000_000;

#[derive(Debug, Clone)]
pub struct NamedProfile {
    pub name: String,
    pub profile: Profile,
}

pub fn is_tar(bytes: &[u8]) -> bool {
    bytes.get(257..262) == Some(b"ustar")
}

pub fn read_bundle(bytes: &[u8]) -> Result<Vec<NamedProfile>> {
    if bytes.len() > MAX_INPUT {
        return Err(Error::TooLarge(MAX_INPUT));
    }
    let mut archive = tar::Archive::new(bytes);
    let mut profiles = Vec::new();
    let entries = archive
        .entries()
        .map_err(|err| Error::Archive(err.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|err| Error::Archive(err.to_string()))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry
            .path()
            .map_err(|err| Error::Archive(err.to_string()))?
            .to_string_lossy()
            .into_owned();
        let lower = name.to_ascii_lowercase();
        if !(lower.ends_with(".ovpn") || lower.ends_with(".conf")) {
            continue;
        }
        let mut text = Zeroizing::new(String::new());
        entry
            .read_to_string(&mut text)
            .map_err(|err| Error::Archive(format!("{name}: {err}")))?;
        let profile =
            Profile::parse(&text).map_err(|err| Error::Archive(format!("{name}: {err}")))?;
        profiles.push(NamedProfile { name, profile });
    }
    if profiles.is_empty() {
        return Err(Error::NoProfiles);
    }
    Ok(profiles)
}

pub fn read_profiles(file_name: &str, bytes: &[u8]) -> Result<Vec<NamedProfile>> {
    if file_name.to_ascii_lowercase().ends_with(".tar") || is_tar(bytes) {
        return read_bundle(bytes);
    }
    if bytes.len() > MAX_INPUT {
        return Err(Error::TooLarge(MAX_INPUT));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::MalformedHeader("profile is not valid UTF-8".into()))?;
    Ok(vec![NamedProfile {
        name: file_name.to_owned(),
        profile: Profile::parse(text)?,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata;

    fn build_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn reads_every_profile_member() {
        let one = testdata::ovpn(&[], "");
        let two = testdata::ovpn(&["\"password_mode\": \"pin\""], "");
        let bytes = build_tar(&[
            ("Org_alice_One.ovpn", one.as_bytes()),
            ("notes.txt", b"ignored"),
            ("Org_alice_Two.OVPN", two.as_bytes()),
        ]);
        assert!(is_tar(&bytes));
        let profiles = read_bundle(&bytes).unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[1].name, "Org_alice_Two.OVPN");
        assert_eq!(
            profiles[1].profile.header.password_mode.as_deref(),
            Some("pin")
        );
    }

    #[test]
    fn tar_without_profiles_is_an_error() {
        let bytes = build_tar(&[("a.txt", b"x")]);
        assert!(matches!(read_bundle(&bytes), Err(Error::NoProfiles)));
    }

    #[test]
    fn bad_member_names_the_file() {
        let bytes = build_tar(&[("bad.ovpn", b"client\n")]);
        let err = read_bundle(&bytes).unwrap_err().to_string();
        assert!(err.contains("bad.ovpn"));
    }

    #[test]
    fn garbage_is_not_a_tar() {
        assert!(matches!(
            read_bundle(&[7u8; 2048]),
            Err(Error::Archive(_) | Error::NoProfiles)
        ));
    }

    #[test]
    fn read_profiles_dispatches_on_content() {
        let text = testdata::ovpn(&[], "");
        assert_eq!(read_profiles("x.ovpn", text.as_bytes()).unwrap().len(), 1);
        let bytes = build_tar(&[("a.ovpn", text.as_bytes())]);
        assert_eq!(read_profiles("download", &bytes).unwrap().len(), 1);
    }

    #[test]
    fn oversized_input_is_rejected() {
        let big = vec![b'a'; MAX_INPUT + 1];
        assert!(matches!(
            read_profiles("x.ovpn", &big),
            Err(Error::TooLarge(_))
        ));
    }
}
