use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wyvpn_core::wireguard::Cidr;

use super::exec::SystemExec;
use super::netops::{
    LinkOps, Platform, Programs, RouteEntry, RouteOps, SystemNet, Via, is_own_linux_interface,
    valid_name,
};
use crate::storage::{prepare_dir, remove_if_present, write_atomic};

const STATE_DIR: &str = "state";
const RECORD_NAME: &str = "wg.json";

#[derive(Debug, Serialize, Deserialize)]
struct StoredRoute {
    network: String,
    dev: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway: Option<IpAddr>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    interface: String,
    routes: Vec<StoredRoute>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Saved {
    pub interface: String,
    pub routes: Vec<RouteEntry>,
}

impl From<&RouteEntry> for StoredRoute {
    fn from(entry: &RouteEntry) -> Self {
        Self {
            network: entry.network.to_string(),
            dev: entry.via.dev().to_owned(),
            gateway: match &entry.via {
                Via::Interface(_) => None,
                Via::Gateway { gateway, .. } => Some(*gateway),
            },
        }
    }
}

fn restore_route(stored: &StoredRoute) -> Option<RouteEntry> {
    let network: Cidr = stored.network.parse().ok()?;
    if !valid_name(&stored.dev)
        || stored
            .gateway
            .is_some_and(|ip| ip.is_ipv4() != network.addr.is_ipv4())
    {
        return None;
    }
    let via = match stored.gateway {
        Some(gateway) => Via::Gateway {
            gateway,
            dev: stored.dev.clone(),
        },
        None => Via::Interface(stored.dev.clone()),
    };
    Some(RouteEntry { network, via })
}

pub struct StateStore {
    dir: PathBuf,
}

impl StateStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.join(STATE_DIR),
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(RECORD_NAME)
    }

    pub fn save(&self, interface: &str, routes: &[RouteEntry]) -> io::Result<()> {
        let record = Record {
            interface: interface.to_owned(),
            routes: routes.iter().map(StoredRoute::from).collect(),
        };
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        prepare_dir(&self.dir)?;
        write_atomic(&self.dir, RECORD_NAME, &bytes)
    }

    pub fn load(&self) -> io::Result<Option<Saved>> {
        let bytes = match std::fs::read(self.path()) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let corrupt =
            || io::Error::new(io::ErrorKind::InvalidData, "corrupt wireguard state record");
        let record: Record = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
        if !valid_name(&record.interface) {
            return Err(corrupt());
        }
        let routes = record.routes.iter().filter_map(restore_route).collect();
        Ok(Some(Saved {
            interface: record.interface,
            routes,
        }))
    }

    pub fn clear(&self) -> io::Result<()> {
        remove_if_present(&self.path()).map(drop)
    }
}

pub fn recover_routes(
    store: &StateStore,
    routes: &mut dyn RouteOps,
    platform: Platform,
) -> Option<String> {
    let saved = match store.load() {
        Ok(Some(saved)) => saved,
        Ok(None) => return None,
        Err(err) => {
            tracing::warn!(%err, "discarding the wireguard state record");
            if let Err(err) = store.clear() {
                tracing::warn!(%err, "cannot remove the wireguard state record");
            }
            return None;
        }
    };
    for route in saved.routes.iter().rev() {
        let kernel_owned = platform == Platform::MacOs && matches!(route.via, Via::Interface(_));
        if kernel_owned {
            continue;
        }
        if let Err(err) = routes.delete_route(route) {
            tracing::debug!(%err, network = %route.network, "stale route already gone");
        }
    }
    if let Err(err) = store.clear() {
        tracing::warn!(%err, "cannot remove the wireguard state record");
    }
    tracing::info!(
        routes = saved.routes.len(),
        "removed wireguard routes left by a previous run"
    );
    Some(saved.interface)
}

pub fn recover_with(store: &StateStore, net: &mut (impl RouteOps + LinkOps), platform: Platform) {
    let Some(interface) = recover_routes(store, net, platform) else {
        return;
    };
    if platform == Platform::Linux
        && is_own_linux_interface(&interface)
        && let Err(err) = net.remove_link(&interface)
    {
        tracing::debug!(%err, "stale interface already gone");
    }
}

pub fn recover(data_dir: &Path) {
    let store = StateStore::new(data_dir);
    if matches!(store.load(), Ok(None)) {
        return;
    }
    let platform = Platform::current();
    match Programs::locate(platform) {
        Ok(programs) => {
            let mut net = SystemNet::new(SystemExec::default(), platform, programs);
            recover_with(&store, &mut net, platform);
        }
        Err(err) => tracing::warn!(%err, "cannot clean up wireguard routes left by a previous run"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::netops::fake::FakeNet;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    fn entries() -> Vec<RouteEntry> {
        vec![
            RouteEntry {
                network: cidr("203.0.113.9/32"),
                via: Via::Gateway {
                    gateway: "192.168.1.1".parse().unwrap(),
                    dev: "en0".into(),
                },
            },
            RouteEntry {
                network: cidr("0.0.0.0/1"),
                via: Via::Interface("utun4".into()),
            },
        ]
    }

    #[test]
    fn saves_interface_and_routes_without_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path());
        store.save("utun4", &entries()).unwrap();
        let text = std::fs::read_to_string(dir.path().join("state/wg.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["interface"], "utun4");
        assert_eq!(value["routes"].as_array().unwrap().len(), 2);
        assert!(!text.contains("key"));
        assert_eq!(
            store.load().unwrap().unwrap(),
            Saved {
                interface: "utun4".into(),
                routes: entries()
            }
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("state/wg.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn missing_record_loads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(StateStore::new(dir.path()).load().unwrap(), None);
    }

    #[test]
    fn invalid_entries_are_dropped_on_load() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("state")).unwrap();
        std::fs::write(
            dir.path().join("state/wg.json"),
            r#"{"interface":"utun4","routes":[
                {"network":"10.0.0.0/8","dev":"utun4"},
                {"network":"nonsense","dev":"utun4"},
                {"network":"10.1.0.0/16","dev":"-x"},
                {"network":"10.2.0.0/16","dev":"en0","gateway":"fe80::1"}
            ]}"#,
        )
        .unwrap();
        let saved = StateStore::new(dir.path()).load().unwrap().unwrap();
        assert_eq!(saved.routes.len(), 1);
        assert_eq!(saved.routes[0].network, cidr("10.0.0.0/8"));
    }

    #[test]
    fn bad_interface_name_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("state")).unwrap();
        std::fs::write(
            dir.path().join("state/wg.json"),
            r#"{"interface":"--evil","routes":[]}"#,
        )
        .unwrap();
        assert!(StateStore::new(dir.path()).load().is_err());
    }

    #[test]
    fn recovery_deletes_in_reverse_and_clears_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path());
        store.save("utun4", &entries()).unwrap();
        let mut net = FakeNet::default();
        recover_with(&store, &mut net, Platform::Linux);
        assert_eq!(
            net.log(),
            [
                "del 0.0.0.0/1 dev utun4",
                "del 203.0.113.9/32 via 192.168.1.1 dev en0"
            ]
        );
        assert_eq!(store.load().unwrap(), None);
    }

    #[test]
    fn macos_recovery_leaves_kernel_owned_interface_routes_alone() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path());
        store.save("utun4", &entries()).unwrap();
        let mut net = FakeNet::default();
        recover_with(&store, &mut net, Platform::MacOs);
        assert_eq!(net.log(), ["del 203.0.113.9/32 via 192.168.1.1 dev en0"]);
    }

    #[test]
    fn recovery_removes_only_our_linux_interface() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path());
        let mut net = FakeNet::default();
        store.save("wyvpn0", &[]).unwrap();
        recover_with(&store, &mut net, Platform::Linux);
        assert_eq!(net.log(), ["remove_link wyvpn0"]);

        let mut other = FakeNet::default();
        store.save("tun7", &[]).unwrap();
        recover_with(&store, &mut other, Platform::Linux);
        assert!(other.log().is_empty());

        let mut mac = FakeNet::default();
        store.save("wyvpn0", &[]).unwrap();
        recover_with(&store, &mut mac, Platform::MacOs);
        assert!(mac.log().is_empty());
    }

    #[test]
    fn recovery_clears_the_record_even_when_deletes_fail() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path());
        store.save("utun4", &entries()).unwrap();
        let mut net = FakeNet::default();
        net.lock().fail_delete = true;
        recover_with(&store, &mut net, Platform::Linux);
        assert_eq!(net.log().len(), 2);
        assert_eq!(store.load().unwrap(), None);
    }

    #[test]
    fn recovery_discards_a_corrupt_record() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("state")).unwrap();
        std::fs::write(dir.path().join("state/wg.json"), b"{").unwrap();
        let store = StateStore::new(dir.path());
        let mut net = FakeNet::default();
        recover_with(&store, &mut net, Platform::MacOs);
        assert!(net.log().is_empty());
        assert!(!dir.path().join("state/wg.json").exists());
    }

    #[test]
    fn recovery_without_a_record_does_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut net = FakeNet::default();
        recover_with(&StateStore::new(dir.path()), &mut net, Platform::Linux);
        assert!(net.log().is_empty());
    }
}
