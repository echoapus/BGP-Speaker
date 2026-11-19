use std::{
    collections::HashMap,
    io::{self, BufRead, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    bgp::{self, Message},
    config::{Config, PeerConfig, PolicyAction, PolicyRule},
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
    SetPolicy(Policy),
    Stop,
}

#[derive(Clone)]
struct PeerHandle {
    name: String,
    commands: Sender<PeerCommand>,
}

struct SharedState {
    routes: RouteStore,
    peers: HashMap<String, PeerConfig>,
    statuses: HashMap<String, String>,
    policies: HashMap<String, Vec<PolicyRule>>,
}

type State = Arc<Mutex<SharedState>>;

pub fn run(config: Config) -> io::Result<()> {
    let mut routes = RouteStore::default();
    for route in config.routes.clone() {
        routes.add(route);
    }
    let state = Arc::new(Mutex::new(SharedState {
        routes,
        peers: config
            .peers
            .iter()
            .map(|peer| (peer.name.clone(), peer.clone()))
            .collect(),
        statuses: config
            .peers
            .iter()
            .map(|peer| (peer.name.clone(), "Idle".into()))
            .collect(),
        policies: config
            .peers
            .iter()
            .map(|peer| (peer.name.clone(), peer.policy.clone()))
            .collect(),
    }));

    let listener = TcpListener::bind(config.listen)?;
    let inbound_peers = config.peers.clone();
    let inbound_routes = config.routes.clone();
    thread::spawn(move || accept_peers(listener, inbound_peers, inbound_routes));

    let mut handles = Vec::new();
    for peer in config.peers {
        let (commands, receiver) = mpsc::channel();
        let handle = PeerHandle {
            name: peer.name.clone(),
            commands,
        };
        handles.push(handle.clone());
        let worker_state = Arc::clone(&state);
        thread::spawn(move || run_peer(peer, receiver, worker_state));
    }

    let api_state = Arc::clone(&state);
    let api_handles = handles.clone();
    thread::spawn(move || api_server(config.api_listen, api_state, api_handles));

    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim() == "quit" {
            break;
        }
        if let Err(error) = apply_command(&line, &state, &handles) {
            eprintln!("command error: {error}");
        }
    }
    for handle in handles {
        let _ = handle.commands.send(PeerCommand::Stop);
    }
    Ok(())
}

fn run_peer(peer: PeerConfig, commands: Receiver<PeerCommand>, state: State) {
    let mut policy = Policy::for_peer(&peer);
    let mut retry_delay = Duration::from_secs(1);
    loop {
        set_status(&state, &peer.name, "Connecting");
        match PeerSession::connect(&peer).and_then(|mut session| {
            set_status(&state, &peer.name, "Established");
            let routes = state
                .lock()
                .map_err(|_| io::Error::other("state lock poisoned"))?
                .routes
                .list()
                .to_vec();
            session.export_initial(&policy, &routes)?;
            session.serve(&commands, &mut policy)
        }) {
            Ok(()) => retry_delay = Duration::from_secs(1),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                set_status(&state, &peer.name, "Stopped");
                return;
            }
            Err(error) => {
                set_status(&state, &peer.name, "Error");
                eprintln!("peer {} error: {error}", peer.name);
            }
        }
        thread::sleep(retry_delay);
        retry_delay = (retry_delay * 2).min(Duration::from_secs(30));
    }
}

fn set_status(state: &State, name: &str, status: &str) {
    if let Ok(mut state) = state.lock() {
        state.statuses.insert(name.into(), status.into());
    }
}

fn accept_peers(listener: TcpListener, peers: Vec<PeerConfig>, routes: Vec<Route>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let peer = stream.peer_addr().ok().and_then(|address| {
            peers
                .iter()
                .find(|peer| peer.address.ip() == address.ip())
                .cloned()
        });
        let Some(peer) = peer else {
            eprintln!("rejected inbound BGP connection from unknown peer");
            continue;
        };
        let routes = routes.clone();
        thread::spawn(move || {
            let (_sender, receiver) = mpsc::channel();
            let policy = Policy::for_peer(&peer);
            match PeerSession::accept(stream, &peer).and_then(|mut session| {
                session.export_initial(&policy, &routes)?;
                session.serve(&receiver, &mut policy.clone())
            }) {
                Ok(()) => {}
                Err(error) => eprintln!("inbound peer {} error: {error}", peer.name),
            }
        });
    }
}

fn apply_command(line: &str, state: &State, handles: &[PeerHandle]) -> Result<(), String> {
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
            let route = Route { prefix, next_hop };
            let mut state = state.lock().map_err(|_| "state lock poisoned")?;
            if state.routes.add(route.clone()) {
                broadcast_announce(&state, handles, route);
            }
        }
        Some("withdraw") => {
            let prefix: Prefix = fields.next().ok_or("withdraw needs PREFIX")?.parse()?;
            let mut state = state.lock().map_err(|_| "state lock poisoned")?;
            if state.routes.remove(prefix).is_some() {
                broadcast_withdraw(handles, prefix);
            }
        }
        Some(command) => return Err(format!("unknown command: {command}")),
        None => {}
    }
    Ok(())
}

fn broadcast_announce(state: &SharedState, handles: &[PeerHandle], route: Route) {
    for handle in handles {
        if state
            .policies
            .get(&handle.name)
            .map(|rules| Policy::from_rules(rules).allows(&route))
            .unwrap_or(false)
        {
            let _ = handle.commands.send(PeerCommand::Announce(route.clone()));
        }
    }
}

fn broadcast_withdraw(handles: &[PeerHandle], prefix: Prefix) {
    for handle in handles {
        let _ = handle.commands.send(PeerCommand::Withdraw(prefix));
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
        let hold = self.verify_open(remote, peer)?;
        self.negotiate_timers(hold);
        self.state = SessionState::OpenConfirm;
        bgp::send(&mut self.stream, &Message::Keepalive)?;
        self.wait_for_keepalive()?;
        self.state = SessionState::Established;
        Ok(())
    }

    fn open_inbound(&mut self, peer: &PeerConfig) -> io::Result<()> {
        self.stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        let remote = receive_until_message(&mut self.stream)?;
        let hold = self.verify_open(remote, peer)?;
        self.negotiate_timers(hold);
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
                self.announce(route)?;
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

    fn serve(&mut self, commands: &Receiver<PeerCommand>, policy: &mut Policy) -> io::Result<()> {
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
                    PeerCommand::Announce(route) if policy.allows(&route) => {
                        self.announce(&route)?
                    }
                    PeerCommand::Announce(_) => {}
                    PeerCommand::Withdraw(prefix) => self.withdraw(prefix)?,
                    PeerCommand::SetPolicy(new_policy) => *policy = new_policy,
                    PeerCommand::Stop => {
                        return Err(io::Error::new(io::ErrorKind::Interrupted, "shutdown"))
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

fn api_server(address: std::net::SocketAddr, state: State, handles: Vec<PeerHandle>) {
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("API listener error: {error}");
            return;
        }
    };
    for stream in listener.incoming().flatten() {
        let state = Arc::clone(&state);
        let handles = handles.clone();
        thread::spawn(move || {
            if let Err(error) = handle_http(stream, &state, &handles) {
                eprintln!("API error: {error}");
            }
        });
    }
}

fn handle_http(mut stream: TcpStream, state: &State, handles: &[PeerHandle]) -> io::Result<()> {
    let mut buffer = vec![0; 65_536];
    let size = stream.read(&mut buffer)?;
    let request = String::from_utf8_lossy(&buffer[..size]);
    let (head, body) = request.split_once("\r\n\r\n").unwrap_or((&request, ""));
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("");
    let path = first.next().unwrap_or("");
    let result: io::Result<(u16, &str, String)> = match (method, path) {
        ("GET", "/") => Ok((200, "text/html", UI.into())),
        ("GET", "/health") => Ok((200, "application/json", "{\"status\":\"ok\"}".into())),
        ("GET", "/peers") => Ok((200, "application/json", peers_json(state)?)),
        ("GET", "/routes") => Ok((200, "application/json", routes_json(state)?)),
        ("GET", "/policies") => Ok((200, "application/json", policies_json(state)?)),
        ("POST", "/routes") => Ok((
            201,
            "application/json",
            add_route_json(body, state, handles)?,
        )),
        ("PUT", path) if path.starts_with("/policies/") => Ok((
            200,
            "application/json",
            set_policy_json(&path[10..], body, state, handles)?,
        )),
        ("DELETE", path) if path.starts_with("/routes/") => Ok((
            200,
            "application/json",
            delete_route_json(&path[8..], state, handles)?,
        )),
        _ => Ok((404, "application/json", "{\"error\":\"not found\"}".into())),
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
            "application/json",
            format!("{{\"error\":\"{}\"}}", json_string(&error.to_string())),
        ),
    };
    let response = format!("HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len());
    stream.write_all(response.as_bytes())
}

fn json_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
fn peers_json(state: &State) -> io::Result<String> {
    let state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    Ok(format!(
        "[{}]",
        state
            .peers
            .values()
            .map(|peer| format!(
                "{{\"name\":\"{}\",\"address\":\"{}\",\"status\":\"{}\"}}",
                json_string(&peer.name),
                peer.address,
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
                "{{\"prefix\":\"{}\",\"next_hop\":\"{}\"}}",
                route.prefix, route.next_hop
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
                "{{\"peer\":\"{}\",\"rules\":[{}]}}",
                json_string(name),
                rules.iter().map(rule_json).collect::<Vec<_>>().join(",")
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
    let marker = format!("\"{key}\":\"");
    let start = body.find(&marker)? + marker.len();
    let end = body[start..].find('"')? + start;
    Some(body[start..end].to_string())
}
fn add_route_json(body: &str, state: &State, handles: &[PeerHandle]) -> io::Result<String> {
    let prefix: Prefix = field(body, "prefix")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing prefix"))?
        .parse()
        .map_err(io::Error::other)?;
    let next_hop = field(body, "next_hop")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing next_hop"))?
        .parse()
        .map_err(io::Error::other)?;
    let route = Route { prefix, next_hop };
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    if !state.routes.add(route.clone()) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "route already exists",
        ));
    }
    broadcast_announce(&state, handles, route);
    Ok("{\"status\":\"announced\"}".into())
}
fn delete_route_json(path: &str, state: &State, handles: &[PeerHandle]) -> io::Result<String> {
    let prefix: Prefix = path.parse().map_err(io::Error::other)?;
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    if state.routes.remove(prefix).is_none() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
    }
    broadcast_withdraw(handles, prefix);
    Ok("{\"status\":\"withdrawn\"}".into())
}
fn set_policy_json(
    name: &str,
    body: &str,
    state: &State,
    handles: &[PeerHandle],
) -> io::Result<String> {
    let rules =
        parse_rules(body).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("state lock poisoned"))?;
    if !state.peers.contains_key(name) {
        return Err(io::Error::new(io::ErrorKind::NotFound, "peer not found"));
    }
    state.policies.insert(name.into(), rules.clone());
    if let Some(handle) = handles.iter().find(|handle| handle.name == name) {
        let _ = handle
            .commands
            .send(PeerCommand::SetPolicy(Policy::from_rules(&rules)));
    }
    Ok("{\"status\":\"updated\"}".into())
}
fn parse_rules(body: &str) -> Result<Vec<PolicyRule>, String> {
    let mut rules = Vec::new();
    for item in body.split('{').skip(1) {
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
    if rules.is_empty() {
        return Err("rules must not be empty".into());
    }
    Ok(rules)
}

const UI: &str = r#"<!doctype html>
<meta charset="utf-8"><title>Megaphone</title>
<h1>Megaphone</h1>
<form id="add"><input name="prefix" placeholder="198.51.100.0/24" required><input name="next_hop" placeholder="192.0.2.1" required><button>Announce route</button></form>
<form id="policy"><input name="peer" placeholder="peer name" required><textarea name="rules" placeholder="permit:198.51.100.0/24\ndeny:203.0.113.0/24" required></textarea><button>Save policy</button></form>
<button onclick="load()">Refresh</button><p id="error"></p><h2>Peers</h2><pre id="peers"></pre><h2>Routes</h2><pre id="routes"></pre>
<script>
const error = document.getElementById('error');
async function load(){
  const [p,r] = await Promise.all([fetch('/peers').then(x=>x.json()), fetch('/routes').then(x=>x.json())]);
  peers.textContent=JSON.stringify(p,null,2);
  routes.innerHTML='';
  r.forEach(x=>{const row=document.createElement('div'); row.textContent=x.prefix+' via '+x.next_hop+' '; const b=document.createElement('button'); b.textContent='Withdraw'; b.onclick=async()=>{await fetch('/routes/'+encodeURIComponent(x.prefix),{method:'DELETE'});load()}; row.appendChild(b); routes.appendChild(row)});
}
add.onsubmit=async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(add));const response=await fetch('/routes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});if(!response.ok)error.textContent=(await response.json()).error;else{error.textContent='';add.reset();load()}};
policy.onsubmit=async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(policy));const rules=data.rules.split(/\s+/).filter(Boolean).map(rule=>{const [action,prefix]=rule.split(':');return {action,prefix}});const response=await fetch('/policies/'+encodeURIComponent(data.peer),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({rules})});if(!response.ok)error.textContent=(await response.json()).error;else error.textContent='Policy updated'};
load();
</script>"#;
