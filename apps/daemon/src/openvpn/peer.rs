use std::net::{Ipv4Addr, SocketAddrV4};

const ROW_WORDS: usize = 6;

fn port_of(word: u32) -> u16 {
    u16::from_be((word & 0xffff) as u16)
}

pub fn owning_pid(table: &[u32], local: SocketAddrV4, remote_port: u16) -> Option<u32> {
    let count = *table.first()? as usize;
    let rows = table.get(1..)?;
    rows.as_chunks::<ROW_WORDS>()
        .0
        .iter()
        .take(count)
        .find_map(|row| {
            let matches = Ipv4Addr::from(row[1].to_ne_bytes()) == *local.ip()
                && port_of(row[2]) == local.port()
                && port_of(row[4]) == remote_port;
            matches.then_some(row[5])
        })
}

#[cfg(windows)]
pub fn connection_owner(local: SocketAddrV4, remote_port: u16) -> std::io::Result<Option<u32>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_CONNECTIONS,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    const NO_ERROR: u32 = 0;
    const INSUFFICIENT_BUFFER: u32 = 122;

    let mut size = 0u32;
    let mut buffer: Vec<u32> = Vec::new();
    for _ in 0..8 {
        let ptr = if buffer.is_empty() {
            std::ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };
        // SAFETY: `ptr` is null with `size == 0` or a writable buffer of `size` bytes.
        let status = unsafe {
            GetExtendedTcpTable(
                ptr,
                &mut size,
                0,
                u32::from(AF_INET),
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        match status {
            NO_ERROR => return Ok(owning_pid(&buffer, local, remote_port)),
            INSUFFICIENT_BUFFER => {
                buffer = vec![0u32; (size as usize).div_ceil(4) + ROW_WORDS * 8];
                size = u32::try_from(buffer.len() * 4).unwrap_or(u32::MAX);
            }
            other => return Err(std::io::Error::from_raw_os_error(other as i32)),
        }
    }
    Err(std::io::Error::other("tcp table kept growing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(port: u16) -> u32 {
        u32::from(port.to_be())
    }

    fn row(local: u16, remote: u16, pid: u32) -> [u32; ROW_WORDS] {
        [
            5,
            u32::from_ne_bytes([127, 0, 0, 1]),
            word(local),
            u32::from_ne_bytes([127, 0, 0, 1]),
            word(remote),
            pid,
        ]
    }

    fn table(rows: &[[u32; ROW_WORDS]]) -> Vec<u32> {
        let mut out = vec![rows.len() as u32];
        out.extend(rows.iter().flatten());
        out
    }

    #[test]
    fn finds_the_client_side_row() {
        let table = table(&[
            row(4000, 50000, 7),
            row(50000, 4000, 99),
            row(50001, 4000, 5),
        ]);
        let local = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 50000);
        assert_eq!(owning_pid(&table, local, 4000), Some(99));
        let other = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 50001);
        assert_eq!(owning_pid(&table, other, 4000), Some(5));
    }

    #[test]
    fn ignores_missing_wrong_port_and_truncated_rows() {
        let local = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 50000);
        assert_eq!(owning_pid(&[], local, 4000), None);
        assert_eq!(
            owning_pid(&table(&[row(50000, 4001, 9)]), local, 4000),
            None
        );
        let mut short = table(&[row(50000, 4000, 9)]);
        short.pop();
        assert_eq!(owning_pid(&short, local, 4000), None);
        let mut lying = table(&[row(1, 2, 3)]);
        lying[0] = 10;
        assert_eq!(owning_pid(&lying, local, 4000), None);
    }
}
