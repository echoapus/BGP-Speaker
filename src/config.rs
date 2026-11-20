use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
};

use crate::{
    bgp,
    route::{Prefix, Route},
};

// Prefix, next hop, and attribute lines (key, value, line number) of one [[route]].
type RouteParts = (
    Option<Prefix>,
    Option<Ipv4Addr>,
    Vec<(String, String, usize)>,
);

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
    pub api_listen: SocketAddr,
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
        let mut api_listen = "127.0.0.1:8080".parse().unwrap();
        let mut router_id = Ipv4Addr::new(127, 0, 0, 1);
        let mut peers = Vec::new();
        let mut routes = Vec::new();
        let mut section = String::new();
        let mut current_peer: Option<PeerConfig> = None;
        let mut current_route: Option<RouteParts> = None;

        for (line_number, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with("[[") && line.ends_with("]]") {
                finish_section(
                    &section,
                    &mut current_peer,
                    &mut current_route,
                    &mut peers,
                    &mut routes,
                    line_number + 1,
                )?;
                section = line[2..line.len() - 2].trim().to_string();
                if section == "peer" {
                    current_peer = Some(default_peer());
                }
                if section == "route" {
                    current_route = Some((None, None, Vec::new()));
                }
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                finish_section(
                    &section,
                    &mut current_peer,
                    &mut current_route,
                    &mut peers,
                    &mut routes,
                    line_number + 1,
                )?;
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
                    "api_listen" => {
                        api_listen = value
                            .parse()
                            .map_err(|_| format!("line {}: invalid api_listen", line_number + 1))?
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
        finish_section(
            &section,
            &mut current_peer,
            &mut current_route,
            &mut peers,
            &mut routes,
            text.lines().count(),
        )?;
        let mut names = std::collections::HashSet::new();
        for peer in &mut peers {
            if !names.insert(peer.name.clone()) {
                return Err(format!("duplicate peer name: {}", peer.name));
            }
            peer.validate()?;
            // The BGP identifier is ours, not the peer's, so every session sends the server's.
            peer.router_id = router_id;
        }
        Ok(Self {
            listen,
            api_listen,
            router_id,
            peers,
            routes,
        })
    }
}

// Closes the [[peer]] or [[route]] section being read.
fn finish_section(
    section: &str,
    peer: &mut Option<PeerConfig>,
    route: &mut Option<RouteParts>,
    peers: &mut Vec<PeerConfig>,
    routes: &mut Vec<Route>,
    line: usize,
) -> Result<(), String> {
    match section {
        "peer" => peers.push(
            peer.take()
                .ok_or_else(|| format!("line {line}: empty peer"))?,
        ),
        "route" => routes.push(route_from_parts(route.take(), line)?),
        _ => {}
    }
    Ok(())
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

fn set_route(route: &mut RouteParts, key: &str, value: &str, line: usize) -> Result<(), String> {
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
        _ => route.2.push((key.to_string(), value.to_string(), line)),
    }
    Ok(())
}

fn route_from_parts(route: Option<RouteParts>, line: usize) -> Result<Route, String> {
    let (prefix, next_hop, attributes) =
        route.ok_or_else(|| format!("line {line}: empty route"))?;
    let mut route = Route::new(
        prefix.ok_or_else(|| format!("line {line}: route needs prefix"))?,
        next_hop.ok_or_else(|| format!("line {line}: route needs next_hop"))?,
    );
    for (key, value, line) in attributes {
        route
            .set_attribute(&key, &value)
            .map_err(|error| format!("line {line}: {error}"))?;
    }
    bgp::check_route(&route).map_err(|error| format!("line {line}: {error}"))?;
    Ok(route)
}

fn parse_prefix_list(value: &str) -> Result<Vec<Prefix>, String> {
    value
        .trim_matches(['[', ']'])
        .split(',')
        .map(|item| item.trim().trim_matches('"'))
        .filter(|item| !item.is_empty())
        .map(|item| item.parse())
        .collect()
}

fn parse_policy_list(value: &str) -> Result<Vec<PolicyRule>, String> {
    value
        .trim_matches(['[', ']'])
        .split(',')
        .map(|item| item.trim().trim_matches('"'))
        .filter(|item| !item.is_empty())
        .map(|item| {
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
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("peer name is required".into());
        }
        // Names go into API paths and JSON unescaped beyond quotes, so keep them plain.
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            return Err(format!(
                "peer name {} may only use letters, digits, '-', '_' and '.'",
                self.name
            ));
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
    fn rejects_duplicate_peer_names() {
        let peer = "[[peer]]\nname = \"r1\"\nlocal_as = 65000\nremote_as = 65001\n";
        assert!(Config::parse(&peer.repeat(2))
            .unwrap_err()
            .contains("duplicate peer name"));
    }

    #[test]
    fn accepts_shared_peer_ip_and_empty_permit() {
        let peer = |name: &str, port: u16| {
            format!("[[peer]]\nname = \"{name}\"\naddress = \"127.0.0.1:{port}\"\nlocal_as = 65000\nremote_as = 65001\npermit = []\n")
        };
        let config = Config::parse(&(peer("a", 1) + &peer("b", 2))).unwrap();
        assert_eq!(config.peers.len(), 2);
        assert!(config.peers[0].policy.is_empty());
    }

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
            med = 10
            communities = ["65000:100", "65000:200"]
            extended_communities = ["rt:65000:1"]
            large_communities = ["65000:1:2"]
            prepend = 2
        "#,
        )
        .unwrap();
        assert_eq!(config.peers[0].policy.len(), 1);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].communities.len(), 2);
        assert_eq!(config.routes[0].prepend, 2);
        assert_eq!(config.peers[0].router_id, Ipv4Addr::new(192, 0, 2, 1));
    }
}
