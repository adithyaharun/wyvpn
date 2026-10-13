pub const PIN_PROFILE: &str = include_str!("../tests/fixtures/pin.ovpn");

pub fn ovpn(replacements: &[(&str, &str)]) -> String {
    replacements
        .iter()
        .fold(PIN_PROFILE.to_owned(), |text, (from, to)| {
            text.replace(from, to)
        })
}

pub fn private_tempdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}
