use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
};

use crate::route::{Prefix, Route};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyAction {
    Permit,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    pub prefix: Prefix,
    pub action: PolicyAction,
}

#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub name: String,
    pub address: SocketAddr,
    pub remote_as: u32,
    pub local_as: u32,
    pub router_id: Ipv4Addr,
    pub hold_time: u16,
    pub policy: Vec<PolicyRule>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub router_id: Ipv4Addr,
    pub peers: Vec<PeerConfig>,
    pub routes: Vec<Route>,
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let text =
            fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let mut listen = "0.0.0.0:179".parse().unwrap();
        let mut router_id = Ipv4Addr::new(127, 0, 0, 1);
        let mut peers = Vec::new();
        let mut routes = Vec::new();
        let mut section = String::new();
        let mut current_peer: Option<PeerConfig> = None;
        let mut current_route: Option<(Option<Prefix>, Option<Ipv4Addr>)> = None;

        for (line_number, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with("[[") && line.ends_with("]]") {
                if section == "peer" {
                    peers.push(
                        current_peer
                            .take()
                            .ok_or_else(|| format!("line {}: empty peer", line_number + 1))?,
                    );
                }
                if section == "route" {
                    routes.push(route_from_parts(current_route.take(), line_number + 1)?);
                }
                section = line[2..line.len() - 2].trim().to_string();
                if section == "peer" {
                    current_peer = Some(default_peer());
                }
                if section == "route" {
                    current_route = Some((None, None));
                }
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                if section == "peer" {
                    peers.push(
                        current_peer
                            .take()
                            .ok_or_else(|| format!("line {}: empty peer", line_number + 1))?,
                    );
                }
                if section == "route" {
                    routes.push(route_from_parts(current_route.take(), line_number + 1)?);
                }
                section = line[1..line.len() - 1].trim().to_string();
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: expected key = value", line_number + 1))?;
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            match section.as_str() {
                "server" | "" => match key {
                    "listen" => {
                        listen = value
                            .parse()
                            .map_err(|_| format!("line {}: invalid listen", line_number + 1))?
                    }
                    "router_id" => {
                        router_id = value
                            .parse()
                            .map_err(|_| format!("line {}: invalid router_id", line_number + 1))?
                    }
                    _ => {
                        return Err(format!(
                            "line {}: unknown server key {key}",
                            line_number + 1
                        ))
                    }
                },
                "peer" => set_peer(
                    current_peer
                        .as_mut()
                        .ok_or("peer section is not an array")?,
                    key,
                    value,
                    line_number + 1,
                )?,
                "route" => set_route(
                    current_route
                        .as_mut()
                        .ok_or("route section is not an array")?,
                    key,
                    value,
                    line_number + 1,
                )?,
                _ => {
                    return Err(format!(
                        "line {}: unknown section [{section}]",
                        line_number + 1
                    ))
                }
            }
        }
        if section == "peer" {
            peers.push(current_peer.take().ok_or("empty peer")?);
        }
        if section == "route" {
            routes.push(route_from_parts(
                current_route.take(),
                text.lines().count(),
            )?);
        }
        if peers.is_empty() {
            return Err("at least one [[peer]] is required".into());
        }
        for peer in &peers {
            peer.validate()?;
        }
        Ok(Self {
            listen,
            router_id,
            peers,
            routes,
        })
    }
}

fn default_peer() -> PeerConfig {
    PeerConfig {
        name: String::new(),
        address: "127.0.0.1:179".parse().unwrap(),
        remote_as: 0,
        local_as: 0,
        router_id: Ipv4Addr::new(127, 0, 0, 1),
        hold_time: 90,
        policy: Vec::new(),
    }
}

fn set_peer(peer: &mut PeerConfig, key: &str, value: &str, line: usize) -> Result<(), String> {
    match key {
        "name" => peer.name = value.to_string(),
        "address" => {
            peer.address = value
                .parse()
                .map_err(|_| format!("line {line}: invalid peer address"))?
        }
        "remote_as" => {
            peer.remote_as = value
                .parse()
                .map_err(|_| format!("line {line}: invalid remote_as"))?
        }
        "local_as" => {
            peer.local_as = value
                .parse()
                .map_err(|_| format!("line {line}: invalid local_as"))?
        }
        "router_id" => {
            peer.router_id = value
                .parse()
                .map_err(|_| format!("line {line}: invalid peer router_id"))?
        }
        "hold_time" => {
            peer.hold_time = value
                .parse()
                .map_err(|_| format!("line {line}: invalid hold_time"))?
        }
        "permit" => {
            for prefix in
                parse_prefix_list(value).map_err(|error| format!("line {line}: {error}"))?
            {
                peer.policy.push(PolicyRule {
                    prefix,
                    action: PolicyAction::Permit,
                });
            }
        }
        "policy" => {
            peer.policy
                .extend(parse_policy_list(value).map_err(|error| format!("line {line}: {error}"))?);
        }
        _ => return Err(format!("line {line}: unknown peer key {key}")),
    }
    Ok(())
}

fn set_route(
    route: &mut (Option<Prefix>, Option<Ipv4Addr>),
    key: &str,
    value: &str,
    line: usize,
) -> Result<(), String> {
    match key {
        "prefix" => {
            route.0 = Some(
                value
                    .parse()
                    .map_err(|error| format!("line {line}: {error}"))?,
            )
        }
        "next_hop" => {
            route.1 = Some(
                value
                    .parse()
                    .map_err(|_| format!("line {line}: invalid next_hop"))?,
            )
        }
        _ => return Err(format!("line {line}: unknown route key {key}")),
    }
    Ok(())
}

fn route_from_parts(
    route: Option<(Option<Prefix>, Option<Ipv4Addr>)>,
    line: usize,
) -> Result<Route, String> {
    let (prefix, next_hop) = route.ok_or_else(|| format!("line {line}: empty route"))?;
    Ok(Route {
        prefix: prefix.ok_or_else(|| format!("line {line}: route needs prefix"))?,
        next_hop: next_hop.ok_or_else(|| format!("line {line}: route needs next_hop"))?,
    })
}

fn parse_prefix_list(value: &str) -> Result<Vec<Prefix>, String> {
    value
        .trim_matches(['[', ']'])
        .split(',')
        .map(|item| item.trim().trim_matches('"').parse())
        .collect()
}

fn parse_policy_list(value: &str) -> Result<Vec<PolicyRule>, String> {
    value
        .trim_matches(['[', ']'])
        .split(',')
        .map(|item| {
            let item = item.trim().trim_matches('"');
            let (action, prefix) = item
                .split_once(':')
                .ok_or_else(|| format!("invalid policy rule: {item}"))?;
            let action = match action {
                "permit" => PolicyAction::Permit,
                "deny" => PolicyAction::Deny,
                _ => return Err(format!("invalid policy action: {action}")),
            };
            Ok(PolicyRule {
                prefix: prefix.parse()?,
                action,
            })
        })
        .collect()
}

impl PeerConfig {
    fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("peer name is required".into());
        }
        if self.remote_as == 0 || self.local_as == 0 {
            return Err(format!("peer {} must have non-zero ASNs", self.name));
        }
        if self.remote_as > u16::MAX as u32 || self.local_as > u16::MAX as u32 {
            return Err(format!(
                "peer {} ASNs above 65535 are not supported yet",
                self.name
            ));
        }
        if self.hold_time != 0 && self.hold_time < 3 {
            return Err(format!(
                "peer {} hold_time must be 0 or at least 3",
                self.name
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let config = Config::parse(
            r#"
            [server]
            listen = "0.0.0.0:179"
            router_id = "192.0.2.1"
            [[peer]]
            name = "r1"
            address = "127.0.0.1:1179"
            local_as = 65000
            remote_as = 65001
            permit = ["198.51.100.0/24"]
            [[route]]
            prefix = "198.51.100.0/24"
            next_hop = "192.0.2.1"
        "#,
        )
        .unwrap();
        assert_eq!(config.peers[0].policy.len(), 1);
        assert_eq!(config.routes.len(), 1);
    }
}
