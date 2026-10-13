#[cfg(unix)]
pub fn run() {
    let _ = send();
}

#[cfg(unix)]
fn send() -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use crate::dns::{SOCKET_NAME, parse_foreign_options};

    const TIMEOUT: Duration = Duration::from_secs(5);

    let vars: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(key, _)| {
            key == "script_type" || key == "dev" || key.starts_with("foreign_option_")
        })
        .collect();
    if !vars
        .iter()
        .any(|(key, value)| key == "script_type" && crate::dns::phase_of(value).is_some())
    {
        return Ok(());
    }
    let report = parse_foreign_options(vars);

    let mut stream = UnixStream::connect(SOCKET_NAME)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let mut line = serde_json::to_vec(&report).map_err(std::io::Error::other)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()?;
    BufReader::new(stream).read_line(&mut String::new())?;
    Ok(())
}

#[cfg(not(unix))]
pub fn run() {}
