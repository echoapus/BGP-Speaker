use std::{io, net::TcpStream, thread, time::Duration};

use crate::{
    bgp::{self, Message},
    config::{Config, PeerConfig},
    policy::Policy,
    route::{Prefix, Route, RouteStore},
};

pub fn run(config: Config) -> io::Result<()> {
    let mut store = RouteStore::default();
    for route in config.routes {
        store.add(route);
    }
    let routes = store.list().to_vec();
    let mut handles = Vec::new();
    for peer in config.peers {
        let routes = routes.clone();
        handles.push(thread::spawn(move || run_peer(peer, routes)));
    }
    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("peer error: {error}"),
            Err(_) => eprintln!("peer thread panicked"),
        }
    }
    Ok(())
}

fn run_peer(peer: PeerConfig, routes: Vec<Route>) -> io::Result<()> {
    let policy = Policy::for_peer(&peer);
    let mut session = PeerSession::connect(&peer)?;
    for route in routes.iter().filter(|route| policy.allows(route)) {
        session.announce(route)?;
    }
    loop {
        match bgp::receive(&mut session.stream) {
            Ok(Message::Keepalive) => bgp::send(&mut session.stream, &Message::Keepalive)?,
            Ok(Message::Notification { code, subcode }) => {
                return Err(io::Error::other(format!(
                    "peer notification {code}/{subcode}"
                )))
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                bgp::send(&mut session.stream, &Message::Keepalive)?
            }
            Err(error) => return Err(error),
        }
    }
}

pub struct PeerSession {
    stream: TcpStream,
    local_as: u16,
}

impl PeerSession {
    pub fn connect(peer: &PeerConfig) -> io::Result<Self> {
        let mut stream = TcpStream::connect(peer.address)?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        bgp::send(&mut stream, &bgp::open_for(peer))?;
        match bgp::receive(&mut stream)? {
            Message::Open { asn, .. } if asn == peer.remote_as as u16 => {}
            Message::Open { asn, .. } => {
                return Err(io::Error::other(format!(
                    "peer AS mismatch: expected {}, got {asn}",
                    peer.remote_as
                )))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer did not send OPEN",
                ))
            }
        }
        bgp::send(&mut stream, &Message::Keepalive)?;
        Ok(Self {
            stream,
            local_as: peer.local_as as u16,
        })
    }

    pub fn announce(&mut self, route: &Route) -> io::Result<()> {
        bgp::send(
            &mut self.stream,
            &Message::Update {
                route: Some(route.clone()),
                withdraw: None,
                local_as: self.local_as,
            },
        )
    }

    pub fn withdraw(&mut self, prefix: Prefix) -> io::Result<()> {
        bgp::send(
            &mut self.stream,
            &Message::Update {
                route: None,
                withdraw: Some(prefix),
                local_as: self.local_as,
            },
        )
    }
}
