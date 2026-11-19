use std::{
    collections::HashMap,
    io::{self, BufRead, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    bgp::{self, Message},
    config::{Config, PeerConfig, PolicyAction, PolicyRule},
    policy::{Overrides, Policy},
    route::{
        format_community, format_extended_community, Prefix, Route, RouteStore, ATTRIBUTES,
        OVERRIDES,
    },
};

// RFC 4271 suggests a 4 minute hold time while waiting for OPEN.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(240);
const JSON: &str = "application/json";

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
    PolicyChanged,
    Inbound(TcpStream),
    Stop,
}

struct SharedState {
    router_id: Ipv4Addr,
    routes: RouteStore,
    peers: HashMap<String, PeerConfig>,
    statuses: HashMap<String, String>,
    policies: HashMap<String, Vec<PolicyRule>>,
    overrides: HashMap<String, Overrides>,
    workers: HashMap<String, Worker>,
}

// A deleted peer's worker may still be dialling; the id tells it apart from a re-added peer
// of the same name.
struct Worker {
    id: u64,
    commands: Sender<PeerCommand>,
}

static NEXT_WORKER: AtomicU64 = AtomicU64::new(0);

type State = Arc<Mutex<SharedState>>;

pub fn run(config: Config) -> io::Result<()> {
    let mut routes = RouteStore::default();
    for route in config.routes.clone() {
        routes.add(route);
    }
    let state = Arc::new(Mutex::new(SharedState {
        router_id: config.router_id,
        routes,
        peers: HashMap::new(),
        statuses: HashMap::new(),
        policies: HashMap::new(),
        overrides: HashMap::new(),
        workers: HashMap::new(),
    }));
    let listener = TcpListener::bind(config.listen)?;
    {
        let mut locked = state
            .lock()
            .map_err(|_| io::Error::other("state lock poisoned"))?;
        for peer in config.peers {
            start_peer(&mut locked, &state, peer);
        }
    }
    let accept_state = Arc::clone(&state);
    thread::spawn(move || accept_peers(listener, accept_state));

    let api_state = Arc::clone(&state);
    thread::spawn(move || api_server(config.api_listen, api_state));

    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim() == "quit" {
            break;
        }
        if let Err(error) = apply_command(&line, &state) {
            eprintln!("command error: {error}");
        }
    }
    if let Ok(state) = state.lock() {
        for worker in state.workers.values() {
            let _ = worker.commands.send(PeerCommand::Stop);
        }
    }
    Ok(())
}

// Registers the peer and starts its worker thread, which dials it and retries until stopped.
fn start_peer(state: &mut SharedState, shared: &State, peer: PeerConfig) {
    let (commands, receiver) = mpsc::channel();
    let name = peer.name.clone();
    state.statuses.insert(name.clone(), "Idle".into());
    state.policies.insert(name.clone(), peer.policy.clone());
    let id = NEXT_WORKER.fetch_add(1, Ordering::Relaxed);
    state.workers.insert(name.clone(), Worker { id, commands });
    state.peers.insert(name, peer.clone());
    let shared = Arc::clone(shared);
    thread::spawn(move || run_peer(peer, receiver, id, shared));
}

fn is_current(state: &SharedState, name: &str, me: u64) -> bool {
    state
        .workers
        .get(name)
        .is_some_and(|worker| worker.id == me)
}

fn run_peer(peer: PeerConfig, commands: Receiver<PeerCommand>, me: u64, state: State) {
    let mut retry_delay = Duration::from_secs(1);
    let mut inbound = None;
    loop {
        set_status(&state, &peer.name, me, "Connecting");
        let session = match inbound.take() {
            Some(stream) => PeerSession::accept(stream, &peer),
            None => PeerSession::connect(&peer),
        };
        match session.and_then(|mut session| {
            let (policy, routes) = snapshot(&state, &peer.name, me)?;
            set_status(&state, &peer.name, me, "Established");
            session.export_initial(&policy, &routes)?;
            session.serve(&commands, policy, &state, &peer.name, me)
        }) {
            Ok(()) => retry_delay = Duration::from_secs(1),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                set_status(&state, &peer.name, me, "Stopped");
                return;
            }
            Err(error) => {
                set_status(&state, &peer.name, me, "Error");
                eprintln!("peer {} error: {error}", peer.name);
            }
        }
        // Wait out the retry delay, but take an inbound connection or a shutdown at once.
        let deadline = Instant::now() + retry_delay;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match commands.recv_timeout(left) {
                Ok(PeerCommand::Inbound(stream)) => {
                    inbound = Some(stream);
                    break;
                }
                Ok(PeerCommand::Stop) | Err(RecvTimeoutError::Disconnected) => {
                    set_status(&state, &peer.name, me, "Stopped");
                    return;
                }
                // Route and policy changes are read from shared state on the next connect.
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => break,
            }
        }
        retry_delay = (retry_delay * 2).min(Duration::from_secs(30));
    }
}

fn snapshot(state: &State, name: &str, me: u64) -> io::Result<(Policy, Vec<Route>)> {
    let state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    if !is_current(&state, name, me) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "peer deleted"));
    }
    Ok((policy_for(&state, name), state.routes.list().to_vec()))
}

fn policy_for(state: &SharedState, name: &str) -> Policy {
    Policy::new(
        state.policies.get(name).map(Vec::as_slice).unwrap_or(&[]),
        state.overrides.get(name).map(Vec::as_slice).unwrap_or(&[]),
    )
}

/// Rejects a route whose UPDATE would not fit in one message, as is or with any peer's overrides.
fn check_for_peers(state: &SharedState, route: &Route) -> Result<(), String> {
    bgp::check_route(route)?;
    for (name, overrides) in &state.overrides {
        bgp::check_route(&Policy::new(&[], overrides).apply(route))
            .map_err(|error| format!("with peer {name}'s overrides: {error}"))?;
    }
    Ok(())
}

fn set_status(state: &State, name: &str, me: u64, status: &str) {
    if let Ok(mut state) = state.lock() {
        if is_current(&state, name, me) {
            state.statuses.insert(name.into(), status.into());
        }
    }
}

// Inbound connections go to the peer's own worker, so each peer has one session.
fn accept_peers(listener: TcpListener, state: State) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let commands = stream.peer_addr().ok().and_then(|address| {
            let state = state.lock().ok()?;
            let peer = state
                .peers
                .values()
                .find(|peer| peer.address.ip() == address.ip())?;
            state
                .workers
                .get(&peer.name)
                .map(|worker| worker.commands.clone())
        });
        let Some(commands) = commands else {
            eprintln!("rejected inbound BGP connection from unknown peer");
            continue;
        };
        let _ = commands.send(PeerCommand::Inbound(stream));
    }
}

fn apply_command(line: &str, state: &State) -> Result<(), String> {
    let mut fields = line.split_whitespace();
    match fields.next() {
        Some("announce") => {
            let prefix: Prefix = fields
                .next()
                .ok_or("announce needs PREFIX NEXT_HOP")?
                .parse()?;
            let next_hop = fields
                .next()
                .ok_or("announce needs PREFIX NEXT_HOP")?
                .parse()
                .map_err(|_| "invalid next hop".to_string())?;
            let mut route = Route::new(prefix, next_hop);
            for attribute in fields {
                let (key, value) = attribute
                    .split_once('=')
                    .ok_or_else(|| format!("expected KEY=VALUE, got {attribute}"))?;
                route.set_attribute(key, value)?;
            }
            let mut state = state.lock().map_err(|_| "state lock poisoned")?;
            check_for_peers(&state, &route)?;
            if state.routes.add(route.clone()) {
                broadcast_announce(&state, route);
            }
        }
        Some("withdraw") => {
            let prefix: Prefix = fields.next().ok_or("withdraw needs PREFIX")?.parse()?;
            let mut state = state.lock().map_err(|_| "state lock poisoned")?;
            if state.routes.remove(prefix).is_some() {
                broadcast_withdraw(&state, prefix);
            }
        }
        Some(command) => return Err(format!("unknown command: {command}")),
        None => {}
    }
    Ok(())
}

fn broadcast_announce(state: &SharedState, route: Route) {
    for (name, worker) in &state.workers {
        if state
            .policies
            .get(name)
            .map(|rules| Policy::from_rules(rules).allows(&route))
            .unwrap_or(false)
        {
            let _ = worker.commands.send(PeerCommand::Announce(route.clone()));
        }
    }
}

fn broadcast_withdraw(state: &SharedState, prefix: Prefix) {
    for worker in state.workers.values() {
        let _ = worker.commands.send(PeerCommand::Withdraw(prefix));
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
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        self.stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        bgp::send(&mut self.stream, &bgp::open_for(peer))?;
        self.state = SessionState::OpenSent;
        let remote = receive_until(&mut self.stream, deadline)?;
        let hold = self.verify_open(remote, peer)?;
        self.negotiate_timers(hold);
        self.state = SessionState::OpenConfirm;
        bgp::send(&mut self.stream, &Message::Keepalive)?;
        self.wait_for_keepalive(deadline)?;
        self.state = SessionState::Established;
        Ok(())
    }

    fn open_inbound(&mut self, peer: &PeerConfig) -> io::Result<()> {
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        self.stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        let remote = receive_until(&mut self.stream, deadline)?;
        let hold = self.verify_open(remote, peer)?;
        self.negotiate_timers(hold);
        bgp::send(&mut self.stream, &bgp::open_for(peer))?;
        self.state = SessionState::OpenSent;
        bgp::send(&mut self.stream, &Message::Keepalive)?;
        self.wait_for_keepalive(deadline)?;
        self.state = SessionState::Established;
        Ok(())
    }

    fn verify_open(&mut self, message: Message, peer: &PeerConfig) -> io::Result<u16> {
        let (error, code, subcode) = match message {
            Message::Open { asn, .. } if asn != peer.remote_as as u16 => (
                io::Error::other(format!(
                    "peer AS mismatch: expected {}, got {asn}",
                    peer.remote_as
                )),
                2,
                2,
            ),
            Message::Open { hold_time, .. } if hold_time != 0 && hold_time < 3 => (
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer hold time is below 3 seconds",
                ),
                2,
                6,
            ),
            Message::Open { hold_time, .. } => return Ok(hold_time),
            _ => (
                io::Error::new(io::ErrorKind::InvalidData, "peer did not send OPEN"),
                5,
                0,
            ),
        };
        let _ = bgp::send(&mut self.stream, &Message::Notification { code, subcode });
        Err(error)
    }

    fn negotiate_timers(&mut self, remote_hold: u16) {
        let local = self.hold_time.as_secs() as u16;
        let hold = match (local, remote_hold) {
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

    fn wait_for_keepalive(&mut self, deadline: Instant) -> io::Result<()> {
        loop {
            match receive_until(&mut self.stream, deadline)? {
                Message::Keepalive => return Ok(()),
                Message::Notification { code, subcode } => {
                    return Err(io::Error::other(format!(
                        "peer notification {code}/{subcode}"
                    )))
                }
                _ => {}
            }
        }
    }

    fn announce(&mut self, route: &Route) -> io::Result<()> {
        self.send_update(Message::Update {
            route: Some(route.clone()),
            withdraw: None,
            local_as: self.local_as,
        })
    }
    fn withdraw(&mut self, prefix: Prefix) -> io::Result<()> {
        self.send_update(Message::Update {
            route: None,
            withdraw: Some(prefix),
            local_as: self.local_as,
        })
    }

    fn export_initial(&mut self, policy: &Policy, routes: &[Route]) -> io::Result<()> {
        for route in routes {
            if policy.allows(route) {
                self.announce(&policy.apply(route))?;
            }
        }
        Ok(())
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

    fn serve(
        &mut self,
        commands: &Receiver<PeerCommand>,
        mut policy: Policy,
        state: &State,
        name: &str,
        me: u64,
    ) -> io::Result<()> {
        let mut last_rx = Instant::now();
        let mut last_tx = Instant::now();
        loop {
            if self.hold_time != Duration::ZERO && last_rx.elapsed() >= self.hold_time {
                let _ = bgp::send(
                    &mut self.stream,
                    &Message::Notification {
                        code: 4,
                        subcode: 0,
                    },
                );
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
                    PeerCommand::Announce(route) if policy.allows(&route) => {
                        self.announce(&policy.apply(&route))?
                    }
                    PeerCommand::Announce(_) => {}
                    PeerCommand::Withdraw(prefix) => self.withdraw(prefix)?,
                    PeerCommand::PolicyChanged => {
                        let (new_policy, routes) = snapshot(state, name, me)?;
                        for route in &routes {
                            match (policy.allows(route), new_policy.allows(route)) {
                                (true, false) => self.withdraw(route.prefix)?,
                                // Re-sending replaces the route at the peer (implicit withdraw).
                                (old, true)
                                    if !old || policy.apply(route) != new_policy.apply(route) =>
                                {
                                    self.announce(&new_policy.apply(route))?
                                }
                                _ => {}
                            }
                        }
                        policy = new_policy;
                    }
                    // RFC 4271 6.8: a new connection colliding with an Established one is closed.
                    // shortcut: collisions during OpenSent/OpenConfirm are not resolved by BGP ID;
                    // add that if peers flap while both sides dial at once.
                    PeerCommand::Inbound(_) => {}
                    PeerCommand::Stop => {
                        // Cease / Administrative Shutdown (RFC 4486).
                        let _ = bgp::send(
                            &mut self.stream,
                            &Message::Notification {
                                code: 6,
                                subcode: 2,
                            },
                        );
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
                Err(error) if is_timeout(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn receive_until(stream: &mut TcpStream, deadline: Instant) -> io::Result<Message> {
    loop {
        match bgp::receive(stream) {
            Err(error) if is_timeout(&error) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "BGP handshake timed out",
                    ));
                }
            }
            result => return result,
        }
    }
}

fn api_server(address: SocketAddr, state: State) {
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("API listener error: {error}");
            return;
        }
    };
    for stream in listener.incoming().flatten() {
        let state = Arc::clone(&state);
        thread::spawn(move || {
            if let Err(error) = handle_http(stream, address, &state) {
                eprintln!("API error: {error}");
            }
        });
    }
}

fn handle_http(mut stream: TcpStream, api_listen: SocketAddr, state: &State) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let request = read_request(&mut stream)?;
    let (head, body) = request.split_once("\r\n\r\n").unwrap_or((&request, ""));
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("");
    let path = first.next().unwrap_or("");
    let result: io::Result<(u16, &str, String)> = if !host_allowed(header(head, "host"), api_listen)
    {
        Ok((403, JSON, "{\"error\":\"forbidden host\"}".into()))
    } else if matches!(method, "POST" | "PUT")
        && !header(head, "content-type").is_some_and(|value| value.starts_with(JSON))
    {
        // Browsers send a text/plain POST cross-site without asking, so require JSON.
        Ok((
            415,
            JSON,
            "{\"error\":\"Content-Type must be application/json\"}".into(),
        ))
    } else {
        match (method, path) {
            ("GET", "/") => Ok((200, "text/html", UI.into())),
            ("GET", "/health") => Ok((200, JSON, "{\"status\":\"ok\"}".into())),
            ("GET", "/peers") => peers_json(state).map(|body| (200, JSON, body)),
            ("POST", "/peers") => add_peer_json(body, state).map(|body| (201, JSON, body)),
            ("DELETE", path) if path.starts_with("/peers/") => {
                delete_peer_json(&percent_decode(&path[7..]), state).map(|body| (200, JSON, body))
            }
            ("GET", "/routes") => routes_json(state).map(|body| (200, JSON, body)),
            ("GET", "/policies") => policies_json(state).map(|body| (200, JSON, body)),
            ("POST", "/routes") => add_route_json(body, state).map(|body| (201, JSON, body)),
            ("PUT", path) if path.starts_with("/overrides/") => {
                set_overrides_json(&percent_decode(&path[11..]), body, state)
                    .map(|body| (200, JSON, body))
            }
            ("PUT", path) if path.starts_with("/policies/") => {
                set_policy_json(&percent_decode(&path[10..]), body, state)
                    .map(|body| (200, JSON, body))
            }
            ("DELETE", path) if path.starts_with("/routes/") => {
                delete_route_json(&percent_decode(&path[8..]), state).map(|body| (200, JSON, body))
            }
            _ => Ok((404, JSON, "{\"error\":\"not found\"}".into())),
        }
    };
    let (status, content_type, response) = match result {
        Ok(response) => response,
        Err(error) => (
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::AlreadyExists
            ) {
                400
            } else if error.kind() == io::ErrorKind::NotFound {
                404
            } else {
                500
            },
            JSON,
            format!("{{\"error\":\"{}\"}}", json_string(&error.to_string())),
        ),
    };
    let response = format!("HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len());
    stream.write_all(response.as_bytes())
}

fn read_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let size = stream.read(&mut chunk)?;
        if size == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..size]);
        if bytes.len() > 65_536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]);
            let length = header(&head, "content-length")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            if bytes.len() - end - 4 >= length {
                break;
            }
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

// Rejects DNS-rebinding requests. An API bound to all addresses is open to any name anyway.
fn host_allowed(host: Option<&str>, api_listen: SocketAddr) -> bool {
    api_listen.ip().is_unspecified()
        || host.is_some_and(|host| {
            host == api_listen.to_string()
                || (api_listen.ip().is_loopback()
                    && host == format!("localhost:{}", api_listen.port()))
        })
}

fn percent_decode(value: &str) -> String {
    let mut bytes = Vec::new();
    let mut rest = value.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        let decoded = (byte == b'%')
            .then(|| tail.get(..2))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(decoded) => {
                bytes.push(decoded);
                rest = &tail[2..];
            }
            None => {
                bytes.push(byte);
                rest = tail;
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn invalid(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

// Only for values made of digits, dots, colons and letters, which need no escaping.
fn json_list(values: impl Iterator<Item = String>) -> String {
    format!(
        "[{}]",
        values
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn json_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
fn peers_json(state: &State) -> io::Result<String> {
    let state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    let mut peers: Vec<_> = state.peers.values().collect();
    peers.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(format!(
        "[{}]",
        peers
            .iter()
            .map(|peer| format!(
                "{{\"name\":\"{}\",\"address\":\"{}\",\"local_as\":{},\"remote_as\":{},\"hold_time\":{},\"status\":\"{}\"}}",
                json_string(&peer.name),
                peer.address,
                peer.local_as,
                peer.remote_as,
                peer.hold_time,
                json_string(
                    state
                        .statuses
                        .get(&peer.name)
                        .map(String::as_str)
                        .unwrap_or("Unknown")
                )
            ))
            .collect::<Vec<_>>()
            .join(",")
    ))
}
fn routes_json(state: &State) -> io::Result<String> {
    let state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    Ok(format!(
        "[{}]",
        state
            .routes
            .list()
            .iter()
            .map(|route| format!(
                "{{\"prefix\":\"{}\",\"next_hop\":\"{}\",\"med\":{},\"communities\":{},\"large_communities\":{},\"extended_communities\":{},\"prepend\":{},\"as_path\":[{}]}}",
                route.prefix,
                route.next_hop,
                route.med.map_or("null".into(), |med| med.to_string()),
                json_list(route.communities.iter().map(|value| format_community(*value))),
                json_list(
                    route
                        .large_communities
                        .iter()
                        .map(|[asn, one, two]| format!("{asn}:{one}:{two}"))
                ),
                json_list(route.extended_communities.iter().map(format_extended_community)),
                route.prepend,
                route
                    .as_path
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ))
            .collect::<Vec<_>>()
            .join(",")
    ))
}
fn policies_json(state: &State) -> io::Result<String> {
    let state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    Ok(format!(
        "[{}]",
        state
            .policies
            .iter()
            .map(|(name, rules)| format!(
                "{{\"peer\":\"{}\",\"rules\":[{}],\"overrides\":{{{}}}}}",
                json_string(name),
                rules.iter().map(rule_json).collect::<Vec<_>>().join(","),
                state
                    .overrides
                    .get(name)
                    .into_iter()
                    .flatten()
                    .map(|(key, value)| format!("\"{key}\":\"{}\"", json_string(value)))
                    .collect::<Vec<_>>()
                    .join(",")
            ))
            .collect::<Vec<_>>()
            .join(",")
    ))
}
fn rule_json(rule: &PolicyRule) -> String {
    format!(
        "{{\"action\":\"{}\",\"prefix\":\"{}\"}}",
        match rule.action {
            PolicyAction::Permit => "permit",
            PolicyAction::Deny => "deny",
        },
        rule.prefix
    )
}

fn field(body: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    let rest = &body[body.find(&marker)? + marker.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    if rest.starts_with('[') {
        return Some(rest[..=rest.find(']')?].to_string());
    }
    match rest.strip_prefix('"') {
        Some(rest) => Some(rest[..rest.find('"')?].to_string()),
        // Unquoted values such as numbers end at the next comma or brace.
        None => Some(
            rest[..rest.find([',', '}']).unwrap_or(rest.len())]
                .trim()
                .to_string(),
        ),
    }
}
fn add_route_json(body: &str, state: &State) -> io::Result<String> {
    let prefix: Prefix = field(body, "prefix")
        .ok_or_else(|| invalid("missing prefix"))?
        .parse()
        .map_err(invalid)?;
    let next_hop = field(body, "next_hop")
        .ok_or_else(|| invalid("missing next_hop"))?
        .parse()
        .map_err(invalid)?;
    let mut route = Route::new(prefix, next_hop);
    for key in ATTRIBUTES {
        if let Some(value) = field(body, key).filter(|value| !value.trim().is_empty()) {
            route.set_attribute(key, &value).map_err(invalid)?;
        }
    }
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    check_for_peers(&state, &route).map_err(invalid)?;
    if !state.routes.add(route.clone()) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "route already exists",
        ));
    }
    broadcast_announce(&state, route);
    Ok("{\"status\":\"announced\"}".into())
}
fn delete_route_json(path: &str, state: &State) -> io::Result<String> {
    let prefix: Prefix = path.parse().map_err(invalid)?;
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    if state.routes.remove(prefix).is_none() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
    }
    broadcast_withdraw(&state, prefix);
    Ok("{\"status\":\"withdrawn\"}".into())
}
fn add_peer_json(body: &str, shared: &State) -> io::Result<String> {
    let text = |key: &str| field(body, key).ok_or_else(|| invalid(format!("missing {key}")));
    let mut peer = PeerConfig {
        name: text("name")?,
        address: text("address")?
            .parse()
            .map_err(|_| invalid("invalid address, expected IP:PORT"))?,
        local_as: text("local_as")?
            .parse()
            .map_err(|_| invalid("invalid local_as"))?,
        remote_as: text("remote_as")?
            .parse()
            .map_err(|_| invalid("invalid remote_as"))?,
        hold_time: match field(body, "hold_time").filter(|value| !value.is_empty()) {
            Some(value) => value.parse().map_err(|_| invalid("invalid hold_time"))?,
            None => 90,
        },
        router_id: Ipv4Addr::UNSPECIFIED,
        policy: Vec::new(),
    };
    peer.validate().map_err(invalid)?;
    let mut state = shared
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    if state.peers.contains_key(&peer.name) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "peer already exists",
        ));
    }
    peer.router_id = state.router_id;
    start_peer(&mut state, shared, peer);
    Ok("{\"status\":\"added\"}".into())
}
fn delete_peer_json(name: &str, state: &State) -> io::Result<String> {
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    let worker = state
        .workers
        .remove(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "peer not found"))?;
    state.peers.remove(name);
    state.statuses.remove(name);
    state.policies.remove(name);
    state.overrides.remove(name);
    let _ = worker.commands.send(PeerCommand::Stop);
    Ok("{\"status\":\"deleted\"}".into())
}
fn set_overrides_json(name: &str, body: &str, state: &State) -> io::Result<String> {
    let mut overrides = Vec::new();
    let mut probe = Route::new("0.0.0.0/0".parse().map_err(invalid)?, Ipv4Addr::UNSPECIFIED);
    for key in OVERRIDES {
        if let Some(value) = field(body, key).filter(|value| !value.trim().is_empty()) {
            probe.set_attribute(key, &value).map_err(invalid)?;
            overrides.push((key.to_string(), value));
        }
    }
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    if !state.peers.contains_key(name) {
        return Err(io::Error::new(io::ErrorKind::NotFound, "peer not found"));
    }
    let policy = Policy::new(&[], &overrides);
    for route in state.routes.list() {
        bgp::check_route(&policy.apply(route))
            .map_err(|error| invalid(format!("{}: {error}", route.prefix)))?;
    }
    state.overrides.insert(name.into(), overrides);
    if let Some(worker) = state.workers.get(name) {
        let _ = worker.commands.send(PeerCommand::PolicyChanged);
    }
    Ok("{\"status\":\"updated\"}".into())
}
fn set_policy_json(name: &str, body: &str, state: &State) -> io::Result<String> {
    let rules = parse_rules(body).map_err(invalid)?;
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    if !state.peers.contains_key(name) {
        return Err(io::Error::new(io::ErrorKind::NotFound, "peer not found"));
    }
    state.policies.insert(name.into(), rules);
    if let Some(worker) = state.workers.get(name) {
        let _ = worker.commands.send(PeerCommand::PolicyChanged);
    }
    Ok("{\"status\":\"updated\"}".into())
}
fn parse_rules(body: &str) -> Result<Vec<PolicyRule>, String> {
    // An empty list is allowed (send nothing), so require the key to catch malformed bodies.
    if !body.contains("\"rules\"") {
        return Err("missing rules".into());
    }
    let mut rules = Vec::new();
    // Pieces with neither key are wrappers such as `"rules":[`.
    for item in body
        .split('{')
        .filter(|item| item.contains("\"action\"") || item.contains("\"prefix\""))
    {
        let action = field(item, "action").ok_or("missing action")?;
        let prefix = field(item, "prefix")
            .ok_or("missing prefix")?
            .parse()
            .map_err(|error: String| error)?;
        let action = match action.as_str() {
            "permit" => PolicyAction::Permit,
            "deny" => PolicyAction::Deny,
            _ => return Err("action must be permit or deny".into()),
        };
        rules.push(PolicyRule { action, prefix });
    }
    Ok(rules)
}

const UI: &str = include_str!("ui.html");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rules_sent_by_ui() {
        let rules = parse_rules(
            r#"{"rules":[{"action":"permit","prefix":"198.51.100.0/24"},{"action":"deny","prefix":"203.0.113.0/24"}]}"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].action, PolicyAction::Deny);
        assert!(parse_rules(r#"{"rules":[{"prefix":"198.51.100.0/24"}]}"#).is_err());
        assert!(parse_rules(r#"{"rules":[]}"#).unwrap().is_empty());
        assert!(parse_rules("{}").is_err());
    }

    #[test]
    fn field_allows_spaces() {
        let body = r#"{ "prefix" : "198.51.100.0/24", "next_hop":"192.0.2.1" }"#;
        assert_eq!(field(body, "prefix").as_deref(), Some("198.51.100.0/24"));
        assert_eq!(field(body, "next_hop").as_deref(), Some("192.0.2.1"));
    }

    #[test]
    fn field_reads_numbers() {
        let body = r#"{"name":"r2","local_as":65000,"remote_as": 65002 }"#;
        assert_eq!(field(body, "local_as").as_deref(), Some("65000"));
        assert_eq!(field(body, "remote_as").as_deref(), Some("65002"));
        assert_eq!(field(body, "hold_time"), None);
    }

    #[test]
    fn field_reads_arrays() {
        let body = r#"{"communities":["65000:1", "65000:2"],"med":5}"#;
        assert_eq!(
            field(body, "communities").as_deref(),
            Some(r#"["65000:1", "65000:2"]"#)
        );
        assert_eq!(field(body, "med").as_deref(), Some("5"));
    }

    #[test]
    fn decodes_encoded_prefix() {
        assert_eq!(percent_decode("198.51.100.0%2F24"), "198.51.100.0/24");
        assert_eq!(percent_decode("lab%20router%"), "lab router%");
    }

    #[test]
    fn rejects_foreign_host() {
        let api = "127.0.0.1:8080".parse().unwrap();
        assert!(host_allowed(Some("127.0.0.1:8080"), api));
        assert!(host_allowed(Some("localhost:8080"), api));
        assert!(!host_allowed(Some("evil.example:8080"), api));
        assert!(!host_allowed(None, api));
    }
}
