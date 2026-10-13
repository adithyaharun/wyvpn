use std::collections::VecDeque;

use anyhow::{Context, bail};

use crate::output::sanitize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf};
use wyvpn_ipc::trust::PeerTrust;
use wyvpn_ipc::{
    Event, Outcome, Request, RequestEnvelope, Response, ServerMessage, check_hello, decode_line,
    encode_line,
};

#[cfg(unix)]
type Stream = tokio::net::UnixStream;
#[cfg(windows)]
type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

pub struct Client {
    lines: Lines<BufReader<ReadHalf<Stream>>>,
    writer: WriteHalf<Stream>,
    next_id: u64,
    events: VecDeque<Event>,
}

impl Client {
    pub async fn connect(path: &str) -> anyhow::Result<Self> {
        #[cfg(unix)]
        let stream = Stream::connect(path).await;
        #[cfg(windows)]
        let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(path);
        let stream = stream.with_context(|| format!("cannot reach wyvpnd at {path}"))?;
        if enforce_trust() {
            #[cfg(unix)]
            let trust = wyvpn_ipc::trust::socket_server(&stream);
            #[cfg(windows)]
            let trust = wyvpn_ipc::trust::pipe_server(&stream);
            let trust = trust.context("cannot verify the WyVPN service")?;
            if trust != PeerTrust::Trusted {
                bail!(
                    "the WyVPN service socket is not owned by the system; refusing to send requests"
                );
            }
        }
        let (reader, writer) = tokio::io::split(stream);
        let mut client = Self {
            lines: BufReader::new(reader).lines(),
            writer,
            next_id: 1,
            events: VecDeque::new(),
        };
        client.handshake().await?;
        Ok(client)
    }

    async fn handshake(&mut self) -> anyhow::Result<()> {
        match self.exchange(Request::hello()).await? {
            Outcome::Result(Response::Hello {
                daemon_version,
                protocol,
            }) => Ok(check_hello(&daemon_version, protocol)?),
            Outcome::Result(_) | Outcome::Error(_) => bail!(
                "the WyVPN service is older than this CLI (version {}); update WyVPN or restart the service",
                wyvpn_ipc::VERSION
            ),
        }
    }

    pub async fn call(&mut self, request: Request) -> anyhow::Result<Response> {
        match self.exchange(request).await? {
            Outcome::Result(result) => Ok(result),
            Outcome::Error(error) => bail!("{}", sanitize(&error.message)),
        }
    }

    async fn exchange(&mut self, request: Request) -> anyhow::Result<Outcome> {
        let id = self.next_id;
        self.next_id += 1;
        self.writer
            .write_all(&encode_line(&RequestEnvelope { id, request })?)
            .await?;
        loop {
            let Some(line) = self.lines.next_line().await? else {
                bail!("wyvpnd closed the connection");
            };
            match decode_line::<ServerMessage>(line.as_bytes())? {
                ServerMessage::Response(response) if response.id == id => {
                    return Ok(response.outcome);
                }
                ServerMessage::Event(envelope) => self.events.push_back(envelope.event),
                ServerMessage::Response(_) => {}
            }
        }
    }

    pub async fn next_event(&mut self) -> anyhow::Result<Event> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }
            let Some(line) = self.lines.next_line().await? else {
                bail!("wyvpnd closed the connection");
            };
            if let ServerMessage::Event(envelope) = decode_line::<ServerMessage>(line.as_bytes())? {
                return Ok(envelope.event);
            }
        }
    }
}

fn enforce_trust() -> bool {
    !cfg!(debug_assertions)
}

pub async fn request(path: &str, request: Request) -> anyhow::Result<Response> {
    Client::connect(path).await?.call(request).await
}
