use std::{
    io::{self, BufRead},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};

use crate::{
    bgp::{self, Message},
    config::{Config, PeerConfig},
    policy::Policy,
    route::{Prefix, Route, RouteStore},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Idle,
    Connect,
    OpenSent,
    OpenConfirm,
    Established,
}

enum PeerCommand {
    Announce(Route),
    Withdraw(Prefix),
    Stop,
}

struct PeerHandle {
    policy: Policy,
    commands: Sender<PeerCommand>,
}

pub fn run(config: Config) -> io::Result<()> {
    let mut store = RouteStore::default();
    for route in config.routes {
        store.add(route);
    }
    let routes = store.list().to_vec();
    let peers = config.peers.clone();

    let listener = TcpListener::bind(config.listen)?;
    let inbound_peers = peers.clone();
    let inbound_routes = routes.clone();
    thread::spawn(move || accept_peers(listener, inbound_peers, inbound_routes));

    let mut handles = Vec::new();
    let mut command_peers = Vec::new();
    for peer in peers {
        let routes = routes.clone();
        let (commands, receiver) = mpsc::channel();
        command_peers.push(PeerHandle {
            policy: Policy::for_peer(&peer),
            commands,
        });
        handles.push(thread::spawn(move || run_peer(peer, routes, receiver)));
    }

    for line in io::stdin().lock().lines() {
        let line = line?;
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("announce") => {
                let prefix = fields
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "announce needs PREFIX NEXT_HOP",
                        )
                    })?
                    .parse()
                    .map_err(io::Error::other)?;
                let next_hop = fields
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "announce needs PREFIX NEXT_HOP",
                        )
                    })?
                    .parse()
                    .map_err(io::Error::other)?;
                let route = Route { prefix, next_hop };
                if store.add(route.clone()) {
                    for peer in &command_peers {
                        if peer.policy.allows(&route) {
                            let _ = peer.commands.send(PeerCommand::Announce(route.clone()));
                        }
                    }
                }
            }
            Some("withdraw") => {
                let prefix = fields
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "withdraw needs PREFIX")
                    })?
                    .parse()
                    .map_err(io::Error::other)?;
                if store.remove(prefix).is_some() {
                    for peer in &command_peers {
                        let _ = peer.commands.send(PeerCommand::Withdraw(prefix));
                    }
                }
            }
            Some("quit") => break,
            Some(command) => eprintln!("unknown command: {command}"),
            None => {}
        }
    }

    for peer in &command_peers {
        let _ = peer.commands.send(PeerCommand::Stop);
    }

    for handle in handles {
        if handle.join().is_err() {
            eprintln!("peer thread panicked");
        }
    }
    Ok(())
}

fn run_peer(peer: PeerConfig, routes: Vec<Route>, commands: Receiver<PeerCommand>) {
    let mut retry_delay = Duration::from_secs(1);
    loop {
        match PeerSession::connect(&peer)
            .and_then(|mut session| session.export(&Policy::for_peer(&peer), &routes, &commands))
        {
            Ok(()) => retry_delay = Duration::from_secs(1),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return,
            Err(error) => eprintln!("peer {} error: {error}", peer.name),
        }
        thread::sleep(retry_delay);
        retry_delay = (retry_delay * 2).min(Duration::from_secs(30));
    }
}

fn accept_peers(listener: TcpListener, peers: Vec<PeerConfig>, routes: Vec<Route>) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer = match stream.peer_addr() {
                    Ok(address) => peers
                        .iter()
                        .find(|peer| peer.address.ip() == address.ip())
                        .cloned(),
                    Err(_) => None,
                };
                let Some(peer) = peer else {
                    eprintln!("rejected inbound BGP connection from unknown peer");
                    continue;
                };
                let routes = routes.clone();
                thread::spawn(move || {
                    let policy = Policy::for_peer(&peer);
                    let (_commands, receiver) = mpsc::channel();
                    match PeerSession::accept(stream, &peer)
                        .and_then(|mut session| session.export(&policy, &routes, &receiver))
                    {
                        Ok(()) => {}
                        Err(error) => eprintln!("inbound peer {} error: {error}", peer.name),
                    }
                });
            }
            Err(error) => eprintln!("BGP listener error: {error}"),
        }
    }
}

pub struct PeerSession {
    stream: TcpStream,
    local_as: u16,
    hold_time: Duration,
    keepalive_interval: Duration,
    pub state: SessionState,
}

impl PeerSession {
    pub fn connect(peer: &PeerConfig) -> io::Result<Self> {
        let stream = TcpStream::connect(peer.address)?;
        let mut session = Self::new(stream, peer);
        session.state = SessionState::Connect;
        session.open_outbound(peer)?;
        Ok(session)
    }

    pub fn accept(stream: TcpStream, peer: &PeerConfig) -> io::Result<Self> {
        let mut session = Self::new(stream, peer);
        session.state = SessionState::Connect;
        session.open_inbound(peer)?;
        Ok(session)
    }

    fn new(stream: TcpStream, peer: &PeerConfig) -> Self {
        let hold = Duration::from_secs(u64::from(peer.hold_time));
        let keepalive = if peer.hold_time == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs(u64::from(peer.hold_time) / 3)
        };
        Self {
            stream,
            local_as: peer.local_as as u16,
            hold_time: hold,
            keepalive_interval: keepalive,
            state: SessionState::Idle,
        }
    }

    fn open_outbound(&mut self, peer: &PeerConfig) -> io::Result<()> {
        self.stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        bgp::send(&mut self.stream, &bgp::open_for(peer))?;
        self.state = SessionState::OpenSent;
        let remote = receive_until_message(&mut self.stream)?;
        let remote_hold = self.verify_open(remote, peer)?;
        self.negotiate_timers(remote_hold);
        self.state = SessionState::OpenConfirm;
        bgp::send(&mut self.stream, &Message::Keepalive)?;
        self.wait_for_keepalive()?;
        self.state = SessionState::Established;
        Ok(())
    }

    fn open_inbound(&mut self, peer: &PeerConfig) -> io::Result<()> {
        self.stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        let remote = receive_until_message(&mut self.stream)?;
        let remote_hold = self.verify_open(remote, peer)?;
        self.negotiate_timers(remote_hold);
        bgp::send(&mut self.stream, &bgp::open_for(peer))?;
        self.state = SessionState::OpenSent;
        bgp::send(&mut self.stream, &Message::Keepalive)?;
        self.wait_for_keepalive()?;
        self.state = SessionState::Established;
        Ok(())
    }

    fn verify_open(&self, message: Message, peer: &PeerConfig) -> io::Result<u16> {
        match message {
            Message::Open { asn, hold_time, .. } if asn == peer.remote_as as u16 => {
                if hold_time != 0 && hold_time < 3 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "peer hold time is below 3 seconds",
                    ));
                }
                Ok(hold_time)
            }
            Message::Open { asn, .. } => Err(io::Error::other(format!(
                "peer AS mismatch: expected {}, got {asn}",
                peer.remote_as
            ))),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer did not send OPEN",
            )),
        }
    }

    fn negotiate_timers(&mut self, remote_hold: u16) {
        let local_hold = self.hold_time.as_secs() as u16;
        let hold = match (local_hold, remote_hold) {
            (0, value) | (value, 0) => value,
            (left, right) => left.min(right),
        };
        self.hold_time = Duration::from_secs(u64::from(hold));
        self.keepalive_interval = if hold == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs(u64::from(hold) / 3)
        };
    }

    fn wait_for_keepalive(&mut self) -> io::Result<()> {
        loop {
            match bgp::receive(&mut self.stream) {
                Ok(Message::Keepalive) => return Ok(()),
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
                    continue
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn announce(&mut self, route: &Route) -> io::Result<()> {
        self.send_update(Message::Update {
            route: Some(route.clone()),
            withdraw: None,
            local_as: self.local_as,
        })
    }

    pub fn withdraw(&mut self, prefix: Prefix) -> io::Result<()> {
        self.send_update(Message::Update {
            route: None,
            withdraw: Some(prefix),
            local_as: self.local_as,
        })
    }

    fn export(
        &mut self,
        policy: &Policy,
        routes: &[Route],
        commands: &Receiver<PeerCommand>,
    ) -> io::Result<()> {
        for route in routes {
            if policy.allows(route) {
                self.announce(route)?;
            }
        }
        self.serve(commands)
    }

    fn send_update(&mut self, message: Message) -> io::Result<()> {
        if self.state != SessionState::Established {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "BGP session is not Established",
            ));
        }
        bgp::send(&mut self.stream, &message)
    }

    fn serve(&mut self, commands: &Receiver<PeerCommand>) -> io::Result<()> {
        let mut last_rx = Instant::now();
        let mut last_tx = Instant::now();
        loop {
            if self.hold_time != Duration::ZERO && last_rx.elapsed() >= self.hold_time {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "BGP hold timer expired",
                ));
            }
            if self.keepalive_interval != Duration::ZERO
                && last_tx.elapsed() >= self.keepalive_interval
            {
                bgp::send(&mut self.stream, &Message::Keepalive)?;
                last_tx = Instant::now();
            }
            while let Ok(command) = commands.try_recv() {
                match command {
                    PeerCommand::Announce(route) => self.announce(&route)?,
                    PeerCommand::Withdraw(prefix) => self.withdraw(prefix)?,
                    PeerCommand::Stop => {
                        return Err(io::Error::new(io::ErrorKind::Interrupted, "shutdown"));
                    }
                }
            }
            match bgp::receive(&mut self.stream) {
                Ok(Message::Keepalive) | Ok(Message::Update { .. }) => last_rx = Instant::now(),
                Ok(Message::Notification { code, subcode }) => {
                    return Err(io::Error::other(format!(
                        "peer notification {code}/{subcode}"
                    )))
                }
                Ok(Message::Open { .. }) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected OPEN after Established",
                    ))
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

fn receive_until_message(stream: &mut TcpStream) -> io::Result<Message> {
    loop {
        match bgp::receive(stream) {
            Ok(message) => return Ok(message),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
    }
}
