use std::{
    collections::{HashMap, VecDeque},
    io::{self, BufRead, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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

const LOG_LINES: usize = 500;
// (id, unix millis, text), newest last. Also echoed to stderr for journalctl.
static LOG: Mutex<VecDeque<(u64, u64, String)>> = Mutex::new(VecDeque::new());
static LOG_ID: AtomicU64 = AtomicU64::new(1);
// Lets the web page notice a restart, which restarts the log ids.
static BOOT: AtomicU64 = AtomicU64::new(0);

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_millis() as u64)
}

fn log(text: impl std::fmt::Display) {
    eprintln!("{text}");
    if let Ok(mut lines) = LOG.lock() {
        if lines.len() == LOG_LINES {
            lines.pop_front();
        }
        lines.push_back((
            LOG_ID.fetch_add(1, Ordering::Relaxed),
            now_millis(),
            text.to_string(),
        ));
    }
}

/// Log lines newer than `?after=ID` in `path`, as the page polls them.
fn log_json(path: &str) -> String {
    let after = path
        .split_once("after=")
        .and_then(|(_, value)| value.split('&').next()?.parse::<u64>().ok())
        .unwrap_or(0);
    let lines = LOG.lock().map(|lines| lines.clone()).unwrap_or_default();
    serde_json::json!({
        "boot": BOOT.load(Ordering::Relaxed),
        "lines": lines.iter().filter(|line| line.0 > after).map(|(id, time, text)| {
            serde_json::json!({ "id": id, "time": time, "text": text })
        }).collect::<Vec<_>>(),
    })
    .to_string()
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
    BOOT.store(now_millis(), Ordering::Relaxed);
    let listener = TcpListener::bind(config.listen)?;
    let api_listener = TcpListener::bind(config.api_listen)?;
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
    thread::spawn(move || api_server(api_listener, config.api_listen, api_state));

    // SIGINT and SIGTERM (systemctl stop) shut down like `quit`, so peers get a Cease.
    unsafe {
        signal(2, on_signal);
        signal(15, on_signal);
    }
    let console_state = Arc::clone(&state);
    // EOF only closes the optional console; background services keep running.
    thread::spawn(move || {
        for line in io::stdin().lock().lines().map_while(Result::ok) {
            if line.trim() == "quit" {
                SHUTDOWN.store(true, Ordering::Relaxed);
            } else if let Err(error) = apply_command(&line, &console_state) {
                log(format!("command error: {error}"));
            }
        }
    });
    while !SHUTDOWN.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }
    if let Ok(locked) = state.lock() {
        for worker in locked.workers.values() {
            let _ = worker.commands.send(PeerCommand::Stop);
        }
    }
    // Give established sessions up to 2 s to send their Cease notification.
    for _ in 0..20 {
        let up = state
            .lock()
            .is_ok_and(|s| s.statuses.values().any(|v| v == "Established"));
        if !up {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: i32) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
}

// Registers the peer and starts its worker thread, which dials it and retries until stopped.
fn start_peer(state: &mut SharedState, shared: &State, peer: PeerConfig) {
    log(format!("peer {} added ({})", peer.name, peer.address));
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
                log(format!("peer {} error: {error}", peer.name));
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
        if is_current(&state, name, me)
            && state.statuses.insert(name.into(), status.into()).as_deref() != Some(status)
        {
            log(format!("peer {name}: {status}"));
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
            log("rejected inbound BGP connection from unknown peer");
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
    log(format!(
        "announce {} next hop {}",
        route.prefix, route.next_hop
    ));
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
    log(format!("withdraw {prefix}"));
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
        let stream = TcpStream::connect_timeout(&peer.address, Duration::from_secs(5))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut session = Self::new(stream, peer);
        session.state = SessionState::Connect;
        session.open_outbound(peer)?;
        Ok(session)
    }

    pub fn accept(stream: TcpStream, peer: &PeerConfig) -> io::Result<Self> {
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
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
        let mut reader = bgp::MessageReader::default();
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
            match reader.receive(&mut self.stream) {
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
    let mut reader = bgp::MessageReader::default();
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "BGP handshake timed out",
            ));
        }
        match reader.receive(stream) {
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

fn api_server(listener: TcpListener, address: SocketAddr, state: State) {
    for stream in listener.incoming().flatten() {
        let state = Arc::clone(&state);
        thread::spawn(move || {
            if let Err(error) = handle_http(stream, address, &state) {
                log(format!("API error: {error}"));
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
            ("GET", path) if path == "/log" || path.starts_with("/log?") => {
                Ok((200, JSON, log_json(path)))
            }
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
            serde_json::json!({ "error": error.to_string() }).to_string(),
        ),
    };
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        415 => "Unsupported Media Type",
        _ => "Internal Server Error",
    };
    let response = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len());
    stream.write_all(response.as_bytes())
}

fn read_request(stream: &mut impl Read) -> io::Result<String> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    // The per-read timeout alone lets a client trickle bytes forever.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request too slow"));
        }
        let size = stream.read(&mut chunk)?;
        if size == 0 {
            return Err(invalid("incomplete HTTP request"));
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
            if header(&head, "transfer-encoding").is_some() {
                return Err(invalid("transfer encoding is unsupported"));
            }
            let length: usize = header(&head, "content-length")
                .map(str::parse)
                .transpose()
                .map_err(invalid)?
                .unwrap_or(0);
            if length > 65_536 - end - 4 {
                return Err(invalid("request too large"));
            }
            if bytes.len() - end - 4 >= length {
                bytes.truncate(end + 4 + length);
                return String::from_utf8(bytes).map_err(invalid);
            }
        }
    }
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

fn peers_json(state: &State) -> io::Result<String> {
    let state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    let mut peers: Vec<_> = state.peers.values().collect();
    peers.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(serde_json::Value::from_iter(peers.iter().map(|peer| {
        serde_json::json!({
            "name": peer.name,
            "address": peer.address.to_string(),
            "local_as": peer.local_as,
            "remote_as": peer.remote_as,
            "hold_time": peer.hold_time,
            "status": state.statuses.get(&peer.name).map_or("Unknown", String::as_str),
        })
    }))
    .to_string())
}
fn routes_json(state: &State) -> io::Result<String> {
    let state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    Ok(serde_json::Value::from_iter(state.routes.list().iter().map(|route| {
        serde_json::json!({
            "prefix": route.prefix.to_string(),
            "next_hop": route.next_hop.to_string(),
            "med": route.med,
            "communities": route.communities.iter().map(|v| format_community(*v)).collect::<Vec<_>>(),
            "large_communities": route.large_communities.iter().map(|[a, b, c]| format!("{a}:{b}:{c}")).collect::<Vec<_>>(),
            "extended_communities": route.extended_communities.iter().map(format_extended_community).collect::<Vec<_>>(),
            "prepend": route.prepend,
            "as_path": route.as_path,
        })
    }))
    .to_string())
}
fn policies_json(state: &State) -> io::Result<String> {
    let state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    Ok(
        serde_json::Value::from_iter(state.policies.iter().map(|(name, rules)| {
            let overrides: serde_json::Map<_, _> = state
                .overrides
                .get(name)
                .into_iter()
                .flatten()
                .map(|(key, value)| (key.clone(), value.clone().into()))
                .collect();
            serde_json::json!({
                "peer": name,
                "rules": rules.iter().map(|rule| serde_json::json!({
                    "action": if rule.action == PolicyAction::Permit { "permit" } else { "deny" },
                    "prefix": rule.prefix.to_string(),
                })).collect::<Vec<_>>(),
                "overrides": overrides,
            })
        }))
        .to_string(),
    )
}

/// The text of a JSON value for `set_attribute`; empty or null means "not given".
fn json_text(value: Option<&serde_json::Value>) -> Option<String> {
    match value? {
        serde_json::Value::String(text) => Some(text.clone()),
        value @ (serde_json::Value::Number(_) | serde_json::Value::Array(_)) => {
            Some(value.to_string())
        }
        _ => None,
    }
    .filter(|text| !text.trim().is_empty())
}

fn parse_body(body: &str) -> io::Result<serde_json::Value> {
    serde_json::from_str(body).map_err(invalid)
}

fn add_route_json(body: &str, state: &State) -> io::Result<String> {
    let body = parse_body(body)?;
    let text =
        |key: &str| json_text(body.get(key)).ok_or_else(|| invalid(format!("missing {key}")));
    let mut route = Route::new(
        text("prefix")?.parse().map_err(invalid)?,
        text("next_hop")?.parse().map_err(invalid)?,
    );
    for key in ATTRIBUTES {
        if let Some(value) = json_text(body.get(key)) {
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
    let body = parse_body(body)?;
    let text =
        |key: &str| json_text(body.get(key)).ok_or_else(|| invalid(format!("missing {key}")));
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
        hold_time: match json_text(body.get("hold_time")) {
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
    // Inbound connections are matched to a peer by IP alone.
    if state
        .peers
        .values()
        .any(|other| other.address.ip() == peer.address.ip())
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "another peer already uses this address",
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
    log(format!("peer {name} deleted"));
    Ok("{\"status\":\"deleted\"}".into())
}
fn parse_overrides(body: &str) -> io::Result<Overrides> {
    let value: serde_json::Value = serde_json::from_str(body).map_err(invalid)?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("overrides must be an object"))?;
    let mut overrides = Vec::new();
    let mut probe = Route::new("0.0.0.0/0".parse().map_err(invalid)?, Ipv4Addr::UNSPECIFIED);
    for (key, value) in object {
        if !OVERRIDES.contains(&key.as_str()) {
            return Err(invalid(format!("unknown override {key}")));
        }
        let text = match value {
            serde_json::Value::String(text) => text.clone(),
            serde_json::Value::Number(_) | serde_json::Value::Array(_) => value.to_string(),
            _ => return Err(invalid(format!("invalid override {key}"))),
        };
        if !text.trim().is_empty() {
            probe.set_attribute(key, &text).map_err(invalid)?;
            overrides.push((key.clone(), text));
        }
    }
    Ok(overrides)
}

fn set_overrides_json(name: &str, body: &str, state: &State) -> io::Result<String> {
    let overrides = parse_overrides(body)?;
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
    log(format!("policy updated for {name}"));
    Ok("{\"status\":\"updated\"}".into())
}
fn set_policy_json(name: &str, body: &str, state: &State) -> io::Result<String> {
    let rules = parse_rules(body).map_err(invalid)?;
    let value: serde_json::Value = serde_json::from_str(body).map_err(invalid)?;
    let overrides = value
        .get("overrides")
        .map(|value| parse_overrides(&value.to_string()))
        .transpose()?;
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    if !state.peers.contains_key(name) {
        return Err(io::Error::new(io::ErrorKind::NotFound, "peer not found"));
    }
    if let Some(overrides) = overrides {
        let policy = Policy::new(&rules, &overrides);
        for route in state.routes.list() {
            bgp::check_route(&policy.apply(route)).map_err(invalid)?;
        }
        state.overrides.insert(name.into(), overrides);
    }
    state.policies.insert(name.into(), rules);
    if let Some(worker) = state.workers.get(name) {
        let _ = worker.commands.send(PeerCommand::PolicyChanged);
    }
    log(format!("policy updated for {name}"));
    Ok("{\"status\":\"updated\"}".into())
}
fn parse_rules(body: &str) -> Result<Vec<PolicyRule>, String> {
    let value: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let entries = value
        .get("rules")
        .and_then(|v| v.as_array())
        .ok_or("rules must be an array")?;
    let mut rules = Vec::new();
    for item in entries {
        let action = match item.get("action").and_then(|v| v.as_str()) {
            Some("permit") => PolicyAction::Permit,
            Some("deny") => PolicyAction::Deny,
            _ => return Err("action must be permit or deny".into()),
        };
        let prefix = item
            .get("prefix")
            .and_then(|v| v.as_str())
            .ok_or("missing prefix")?
            .parse()?;
        rules.push(PolicyRule { action, prefix });
    }
    Ok(rules)
}

const UI: &str = include_str!("ui.html");

#[cfg(test)]
mod tests {
    use super::*;

    fn receive_one(stream: &mut TcpStream) -> Message {
        let mut reader = bgp::MessageReader::default();
        loop {
            match reader.receive(stream) {
                Err(error) if is_timeout(&error) => {}
                result => return result.unwrap(),
            }
        }
    }

    #[test]
    fn combined_policy_rejects_invalid_overrides_without_changes() {
        let peer = Config::parse("[[peer]]\nname=\"test\"\nlocal_as=65000\nremote_as=65001\n")
            .unwrap()
            .peers
            .remove(0);
        let state = Arc::new(Mutex::new(SharedState {
            router_id: Ipv4Addr::LOCALHOST,
            routes: RouteStore::default(),
            peers: HashMap::from([("test".into(), peer)]),
            statuses: HashMap::new(),
            policies: HashMap::new(),
            overrides: HashMap::new(),
            workers: HashMap::new(),
        }));
        assert!(set_policy_json("test", r#"{"rules":[],"overrides":null}"#, &state).is_err());
        assert!(state.lock().unwrap().policies.is_empty());
        set_policy_json("test", r#"{"rules":[],"overrides":{"med":"10"}}"#, &state).unwrap();
        let locked = state.lock().unwrap();
        assert!(locked.policies.contains_key("test"));
        assert_eq!(locked.overrides["test"], vec![("med".into(), "10".into())]);
    }

    #[test]
    fn rejects_incomplete_http_requests() {
        for request in [
            "GET / HTTP/1.1\r\n",
            "POST /routes HTTP/1.1\r\nContent-Length: 10\r\n\r\n{}",
            "GET / HTTP/1.1\r\nContent-Length: nope\r\n\r\n",
        ] {
            assert!(read_request(&mut request.as_bytes()).is_err());
        }
        assert!(read_request(&mut b"GET / HTTP/1.1\r\n\r\n".as_slice()).is_ok());
    }

    #[test]
    fn validates_override_objects() {
        for body in ["null", "[]", "{", r#"{"med":null}"#, r#"{"unknown":"1"}"#] {
            assert!(parse_overrides(body).is_err(), "{body}");
        }
        assert!(parse_overrides("{}").unwrap().is_empty());
        assert_eq!(
            parse_overrides(r#"{"med":10}"#).unwrap(),
            vec![("med".into(), "10".into())]
        );
    }

    #[test]
    fn session_announces_withdraws_and_stops() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = crate::config::Config::parse(
            "[[peer]]\nname=\"test\"\nlocal_as=65000\nremote_as=65001\n",
        )
        .unwrap()
        .peers
        .remove(0);
        peer.address = listener.local_addr().unwrap();
        let route = Route::new("192.0.2.0/24".parse().unwrap(), Ipv4Addr::LOCALHOST);
        let prefix = route.prefix;
        let (tx, rx) = mpsc::channel();
        let state = Arc::new(Mutex::new(SharedState {
            router_id: Ipv4Addr::LOCALHOST,
            routes: RouteStore::default(),
            peers: HashMap::new(),
            statuses: HashMap::new(),
            policies: HashMap::new(),
            overrides: HashMap::new(),
            workers: HashMap::new(),
        }));
        {
            let mut locked = state.lock().unwrap();
            locked.routes.add(route.clone());
            locked.workers.insert(
                "test".into(),
                Worker {
                    id: 1,
                    commands: tx.clone(),
                },
            );
        }
        let worker = thread::spawn(move || {
            let mut session = PeerSession::connect(&peer).unwrap();
            assert!(session.stream.write_timeout().unwrap().is_some());
            let policy = Policy::from_rules(&[PolicyRule {
                prefix,
                action: PolicyAction::Permit,
            }]);
            session.export_initial(&policy, &[route]).unwrap();
            session
                .serve(&rx, policy, &state, "test", 1)
                .unwrap_err()
                .kind()
        });
        let (mut remote, _) = listener.accept().unwrap();
        remote
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        remote
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert!(matches!(receive_one(&mut remote), Message::Open { .. }));
        bgp::send(
            &mut remote,
            &Message::Open {
                asn: 65001,
                hold_time: 90,
                router_id: Ipv4Addr::new(192, 0, 2, 2),
            },
        )
        .unwrap();
        assert_eq!(receive_one(&mut remote), Message::Keepalive);
        bgp::send(&mut remote, &Message::Keepalive).unwrap();
        assert!(matches!(receive_one(&mut remote), Message::Update { .. }));
        tx.send(PeerCommand::PolicyChanged).unwrap();
        let expected = Message::Update {
            route: None,
            withdraw: Some(prefix),
            local_as: 65000,
        }
        .encode()
        .unwrap();
        let mut actual = vec![0; expected.len()];
        remote.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
        tx.send(PeerCommand::Stop).unwrap();
        assert_eq!(
            receive_one(&mut remote),
            Message::Notification {
                code: 6,
                subcode: 2
            }
        );
        assert_eq!(worker.join().unwrap(), io::ErrorKind::Interrupted);
    }

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
        for body in [
            r#"{"rules":null}"#,
            r#"{"rules":{}}"#,
            r#"{"rules":[null]}"#,
            r#"{"rules":[]"#,
        ] {
            assert!(parse_rules(body).is_err(), "{body}");
        }
    }

    fn test_state() -> State {
        Arc::new(Mutex::new(SharedState {
            router_id: Ipv4Addr::LOCALHOST,
            routes: RouteStore::default(),
            peers: HashMap::new(),
            statuses: HashMap::new(),
            policies: HashMap::new(),
            overrides: HashMap::new(),
            workers: HashMap::new(),
        }))
    }

    #[test]
    fn json_bodies_are_parsed_properly() {
        let state = test_state();
        // The old text scanner read med=5 out of this note.
        add_route_json(
            r#"{"prefix":"192.0.2.0/24","next_hop":"192.0.2.1","note":"\"med\":5","communities":["65000:1","65000:2"],"prepend":2}"#,
            &state,
        )
        .unwrap();
        let locked = state.lock().unwrap();
        let route = &locked.routes.list()[0];
        assert_eq!(route.med, None);
        assert_eq!(route.communities.len(), 2);
        assert_eq!(route.prepend, 2);
    }

    #[test]
    fn peer_can_be_deleted_and_added_again() {
        let state = test_state();
        let body = r#"{"name":"r1","address":"127.0.0.1:1","local_as":65000,"remote_as":65001}"#;
        add_peer_json(body, &state).unwrap();
        let first = state.lock().unwrap().workers["r1"].id;
        // Same IP as a live peer is refused.
        let other = body.replace("r1", "r2");
        assert!(add_peer_json(&other, &state).is_err());
        delete_peer_json("r1", &state).unwrap();
        assert!(state.lock().unwrap().workers.is_empty());
        add_peer_json(body, &state).unwrap();
        let second = state.lock().unwrap().workers["r1"].id;
        assert_ne!(first, second);
        delete_peer_json("r1", &state).unwrap();
    }

    #[test]
    fn inbound_connection_reaches_its_peers_worker() {
        let state = test_state();
        let (tx, rx) = mpsc::channel();
        let peer = Config::parse(
            "[[peer]]\nname=\"test\"\naddress=\"127.0.0.1:179\"\nlocal_as=65000\nremote_as=65001\n",
        )
        .unwrap()
        .peers
        .remove(0);
        {
            let mut locked = state.lock().unwrap();
            locked.peers.insert("test".into(), peer);
            locked.workers.insert(
                "test".into(),
                Worker {
                    id: 1,
                    commands: tx,
                },
            );
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || accept_peers(listener, state));
        let _client = TcpStream::connect(address).unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(PeerCommand::Inbound(_))
        ));
    }

    #[test]
    fn log_returns_only_newer_lines() {
        log("first");
        log("second");
        let all: serde_json::Value = serde_json::from_str(&log_json("/log")).unwrap();
        let lines = all["lines"].as_array().unwrap();
        let id = lines.iter().find(|l| l["text"] == "first").unwrap()["id"]
            .as_u64()
            .unwrap();
        let newer: serde_json::Value =
            serde_json::from_str(&log_json(&format!("/log?after={id}"))).unwrap();
        let texts: Vec<_> = newer["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| &l["text"])
            .collect();
        assert!(texts.contains(&&serde_json::json!("second")));
        assert!(!texts.contains(&&serde_json::json!("first")));
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
