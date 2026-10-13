#![deny(unsafe_code)]

pub mod auth;
pub mod error;
pub mod http;
pub mod import;
pub mod ovpn;
pub mod profile;
pub mod rng;
pub mod secret;
pub mod sign;
pub mod sync;
pub mod tls;
pub mod vendor;
pub mod wireguard;

mod bundle;

#[cfg(test)]
mod testdata;

pub use bundle::{NamedProfile, read_bundle, read_profiles};
pub use error::{Error, Result, Unsupported};
pub use profile::{Profile, ProfileHeader};
pub use secret::Secret;
pub use wyvpn_ipc::{AuthMode, Transport};
