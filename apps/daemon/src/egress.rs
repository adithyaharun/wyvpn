use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

pub trait Egress: Send + Sync + 'static {
    fn local_ip(&self, endpoint: SocketAddr) -> io::Result<IpAddr>;
    fn still_assigned(&self, ip: IpAddr) -> bool;
}

pub struct RoutingTable;

impl Egress for RoutingTable {
    fn local_ip(&self, endpoint: SocketAddr) -> io::Result<IpAddr> {
        let bind: SocketAddr = if endpoint.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(endpoint)?;
        Ok(socket.local_addr()?.ip())
    }

    fn still_assigned(&self, ip: IpAddr) -> bool {
        UdpSocket::bind((ip, 0)).is_ok()
    }
}

#[cfg(test)]
pub mod fake {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    pub struct Scripted {
        steady: Mutex<IpAddr>,
        queued: Mutex<VecDeque<io::Result<IpAddr>>>,
        assigned: Mutex<Vec<IpAddr>>,
    }

    pub fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    impl Scripted {
        pub fn steady(address: &str) -> Self {
            Self {
                steady: Mutex::new(ip(address)),
                queued: Mutex::default(),
                assigned: Mutex::default(),
            }
        }

        pub fn set(&self, address: &str) {
            *self.steady.lock().unwrap() = ip(address);
        }

        pub fn keep_assigned(&self, address: &str) {
            self.assigned.lock().unwrap().push(ip(address));
        }

        pub fn queue(&self, result: io::Result<IpAddr>) {
            self.queued.lock().unwrap().push_back(result);
        }
    }

    impl Egress for Scripted {
        fn local_ip(&self, _endpoint: SocketAddr) -> io::Result<IpAddr> {
            if let Some(result) = self.queued.lock().unwrap().pop_front() {
                return result;
            }
            Ok(*self.steady.lock().unwrap())
        }

        fn still_assigned(&self, ip: IpAddr) -> bool {
            self.assigned.lock().unwrap().contains(&ip)
        }
    }
}
