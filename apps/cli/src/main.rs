mod client;
mod connect;
mod import;
mod mcp;
mod output;
mod view;

use clap::{Parser, Subcommand, ValueEnum};
use wyvpn_ipc::{Request, Response, Transport};

#[derive(Parser)]
#[command(name = "wyvpn-cli", version, about = "WyVPN command-line client")]
struct Cli {
    /// Print machine-readable JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum TransportArg {
    Openvpn,
    Wireguard,
}

impl From<TransportArg> for Transport {
    fn from(arg: TransportArg) -> Self {
        match arg {
            TransportArg::Openvpn => Transport::OpenVpn,
            TransportArg::Wireguard => Transport::WireGuard,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// List configured profiles
    List,
    /// Show connection status of every profile
    Status,
    /// Connect a profile by id or name
    Connect {
        profile: String,
        /// Read the PIN from the first line of stdin instead of prompting
        #[arg(long)]
        pin_stdin: bool,
        /// Tunnel transport to use; the daemon default (OpenVPN) when omitted
        #[arg(long, value_enum)]
        transport: Option<TransportArg>,
    },
    /// Disconnect a profile by id or name
    Disconnect { profile: String },
    /// Import profiles from a .ovpn or .tar file, or from a profile link ("-" reads it from stdin)
    Import {
        source: String,
        /// Overwrite a profile that already exists
        #[arg(long)]
        replace: bool,
    },
    /// Remove a stored profile by id or name
    Remove { profile: String },
    /// Rename a profile by id or name
    #[command(group(clap::ArgGroup::new("target").required(true).args(["name", "reset"])))]
    Rename {
        profile: String,
        /// New display name
        name: Option<String>,
        /// Restore the imported name
        #[arg(long)]
        reset: bool,
    },
    /// Serve Model Context Protocol over stdio for AI agents
    Mcp {
        /// Also expose the connect and disconnect tools
        #[arg(long)]
        allow_control: bool,
    },
}

fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let socket = wyvpn_ipc::socket_path();
    match cli.command {
        Command::Mcp { allow_control } => mcp::run(socket, allow_control).await,
        Command::List => {
            let profiles =
                view::fetch_profiles(&mut client::Client::connect(&socket).await?).await?;
            if cli.json {
                print_json(&profiles)
            } else {
                print!("{}", output::profiles_table(&profiles));
                Ok(())
            }
        }
        Command::Status => {
            let views = view::fetch_status(&mut client::Client::connect(&socket).await?).await?;
            if cli.json {
                print_json(&views)
            } else {
                print!("{}", output::status_table(&views));
                Ok(())
            }
        }
        Command::Connect {
            profile,
            pin_stdin,
            transport,
        } => {
            let transport = transport.map(Transport::from);
            let mut client = client::Client::connect(&socket).await?;
            let profiles = view::fetch_profiles(&mut client).await?;
            let profile_id = view::resolve_profile(&profiles, &profile)?;
            view::ensure_transport(&profiles, &profile_id, transport)?;
            let pin = connect::Pin::Prompt {
                from_stdin: pin_stdin,
            };
            let view = connect::run(&mut client, profile_id, transport, pin).await?;
            if cli.json {
                print_json(&view)
            } else {
                println!("{}", output::connected_line(&view.status));
                Ok(())
            }
        }
        Command::Disconnect { profile } => {
            let mut client = client::Client::connect(&socket).await?;
            let profile_id = resolve(&mut client, &profile).await?;
            connect::disconnect(&mut client, &profile_id).await?;
            if cli.json {
                print_json(&serde_json::json!({ "ok": true }))
            } else {
                println!("disconnected");
                Ok(())
            }
        }
        Command::Remove { profile } => {
            let profile_id =
                resolve(&mut client::Client::connect(&socket).await?, &profile).await?;
            control(&socket, cli.json, Request::RemoveProfile { profile_id }).await
        }
        Command::Rename {
            profile,
            name,
            reset: _,
        } => {
            let mut client = client::Client::connect(&socket).await?;
            let profile_id = resolve(&mut client, &profile).await?;
            let request = Request::RenameProfile {
                profile_id,
                name: name.unwrap_or_default(),
            };
            let Response::Profile { profile } = client.call(request).await? else {
                anyhow::bail!("unexpected reply: rename");
            };
            let profile = output::sanitize_profile(profile);
            if cli.json {
                print_json(&profile)
            } else {
                let reset = profile.imported_name.is_none();
                println!("{}", output::renamed_line(&profile, reset));
                Ok(())
            }
        }
        Command::Import { source, replace } => {
            let source = import::resolve(&source, std::io::stdin().lock())?;
            let response =
                client::request(&socket, Request::ImportProfile { source, replace }).await?;
            let Response::Imported { profiles } = response else {
                anyhow::bail!("unexpected reply: {response:?}");
            };
            let profiles: Vec<_> = profiles.into_iter().map(output::sanitize_profile).collect();
            if cli.json {
                print_json(&profiles)
            } else {
                print!("{}", output::profiles_table(&profiles));
                Ok(())
            }
        }
    }
}

async fn resolve(client: &mut client::Client, wanted: &str) -> anyhow::Result<String> {
    let profiles = view::fetch_profiles(client).await?;
    view::resolve_profile(&profiles, wanted)
}

async fn control(socket: &str, json: bool, request: Request) -> anyhow::Result<()> {
    let response = client::request(socket, request).await?;
    anyhow::ensure!(
        matches!(response, Response::Ok),
        "unexpected reply: {response:?}"
    );
    if json {
        print_json(&serde_json::json!({ "ok": true }))
    } else {
        println!("ok");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_transport(args: &[&str]) -> Result<Option<Transport>, clap::Error> {
        let cli = Cli::try_parse_from(
            ["wyvpn-cli", "connect", "p"]
                .into_iter()
                .chain(args.iter().copied()),
        )?;
        let Command::Connect { transport, .. } = cli.command else {
            unreachable!()
        };
        Ok(transport.map(Transport::from))
    }

    #[test]
    fn transport_flag_maps_each_value() {
        assert_eq!(
            parse_transport(&["--transport", "openvpn"]).unwrap(),
            Some(Transport::OpenVpn)
        );
        assert_eq!(
            parse_transport(&["--transport", "wireguard"]).unwrap(),
            Some(Transport::WireGuard)
        );
    }

    #[test]
    fn missing_transport_flag_is_none() {
        assert_eq!(parse_transport(&[]).unwrap(), None);
    }

    #[test]
    fn invalid_transport_is_rejected() {
        for value in ["wire_guard", "WireGuard", "open_vpn", "tcp", ""] {
            assert!(parse_transport(&["--transport", value]).is_err(), "{value}");
        }
    }
}
