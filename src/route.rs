use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Prefix {
    pub rd: Option<[u8; 8]>,
    pub address: IpAddr,
    pub length: u8,
}

impl Prefix {
    pub fn new(address: IpAddr, length: u8) -> Result<Self, String> {
        let (value, bits) = match address {
            IpAddr::V4(ip) => (u128::from(u32::from(ip)), 32),
            IpAddr::V6(ip) => (u128::from(ip), 128),
        };
        if length > bits {
            return Err(format!("invalid prefix length: {length}"));
        }
        let host_mask = if length == bits {
            0
        } else {
            u128::MAX >> (128 - (bits - length))
        };
        if value & host_mask != 0 {
            return Err(format!("address {address} has host bits set for /{length}"));
        }
        Ok(Self {
            address,
            length,
            rd: None,
        })
    }

    pub fn wire_bytes(self) -> Vec<u8> {
        let octets = match self.address {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let bytes = usize::from(self.length.div_ceil(8));
        let mut result = vec![self.length];
        result.extend_from_slice(&octets[..bytes]);
        result
    }

    pub fn family(self) -> &'static str {
        match (self.address.is_ipv4(), self.rd.is_some()) {
            (true, false) => "ipv4-unicast",
            (false, false) => "ipv6-unicast",
            (true, true) => "vpnv4",
            (false, true) => "vpnv6",
        }
    }

    pub fn vpn_wire_bytes(self, label: u32) -> Vec<u8> {
        let mut bytes = vec![self.length + 88];
        bytes.extend_from_slice(&((label << 4) | 1).to_be_bytes()[1..]);
        bytes.extend(self.rd.expect("VPN prefix has RD"));
        bytes.extend_from_slice(&self.wire_bytes()[1..]);
        bytes
    }

    pub fn rd_text(self) -> Option<String> {
        self.rd.map(|rd| {
            let mut community = rd;
            community[0] = rd[1];
            community[1] = 2;
            format_extended_community(&community)[3..].to_string()
        })
    }
}

impl FromStr for Prefix {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (rd, value) = match value.split_once('@') {
            Some((rd, prefix)) => (Some(parse_rd(rd)?), prefix),
            None => (None, value),
        };
        let (address, length) = value
            .split_once('/')
            .ok_or_else(|| format!("invalid prefix: {value}"))?;
        let address = address
            .parse()
            .map_err(|_| format!("invalid IP address: {address}"))?;
        let length = length
            .parse()
            .map_err(|_| format!("invalid prefix length: {length}"))?;
        let mut prefix = Self::new(address, length)?;
        prefix.rd = rd;
        Ok(prefix)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(rd) = self.rd_text() {
            write!(formatter, "{rd}@")?;
        }
        write!(formatter, "{}/{}", self.address, self.length)
    }
}

/// Route attributes that can be set from config, the API or the console.
pub const ATTRIBUTES: [&str; 7] = [
    "label",
    "as_path",
    "med",
    "communities",
    "large_communities",
    "extended_communities",
    "prepend",
];
/// Attributes a peer's policy can override: the next hop plus `ATTRIBUTES`.
pub const OVERRIDES: [&str; 7] = [
    "next_hop",
    "as_path",
    "med",
    "communities",
    "large_communities",
    "extended_communities",
    "prepend",
];
// Keep the whole AS_PATH in one segment (at most 255 ASes): 1 + 32 + 200.
const MAX_PREPEND: u8 = 32;
const MAX_AS_PATH: usize = 200;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub label: Option<u32>,
    pub prefix: Prefix,
    pub next_hop: IpAddr,
    pub med: Option<u32>,
    pub communities: Vec<u32>,
    pub large_communities: Vec<[u32; 3]>,
    pub extended_communities: Vec<[u8; 8]>,
    /// Extra copies of the local AS added to the AS_PATH.
    pub prepend: u8,
    /// ASes sent after the local AS (and its prepends), as if the route came from them.
    pub as_path: Vec<u16>,
}

impl Route {
    pub fn new(prefix: Prefix, next_hop: impl Into<IpAddr>) -> Self {
        Self {
            label: None,
            prefix,
            next_hop: next_hop.into(),
            med: None,
            communities: Vec::new(),
            large_communities: Vec::new(),
            extended_communities: Vec::new(),
            prepend: 0,
            as_path: Vec::new(),
        }
    }

    /// Sets one of `OVERRIDES` from text. Lists are separated by commas or spaces.
    pub fn set_attribute(&mut self, key: &str, value: &str) -> Result<(), String> {
        let items = || {
            value
                .split(|c: char| c == ',' || c.is_whitespace())
                .map(|item| item.trim_matches(['"', '[', ']']))
                .filter(|item| !item.is_empty())
        };
        match key {
            "label" => {
                let label: u32 = value.parse().map_err(|_| "invalid MPLS label")?;
                if !(16..=1048575).contains(&label) {
                    return Err("MPLS label must be 16–1048575".into());
                }
                self.label = Some(label);
            }
            "next_hop" => {
                self.next_hop = value
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid next_hop: {value}"))?
            }
            "med" => {
                self.med = Some(
                    value
                        .trim()
                        .parse()
                        .map_err(|_| format!("invalid med: {value}"))?,
                )
            }
            "as_path" => {
                let path = items()
                    .map(|asn| {
                        asn.parse::<u16>().map_err(|_| {
                            format!("invalid AS {asn} in as_path: use 1-65535, 4-byte ASNs are not supported yet")
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if path.len() > MAX_AS_PATH {
                    return Err(format!("as_path may have at most {MAX_AS_PATH} ASes"));
                }
                self.as_path = path;
            }
            "prepend" => {
                let count: u8 = value
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid prepend: {value}"))?;
                if count > MAX_PREPEND {
                    return Err(format!("prepend must be at most {MAX_PREPEND}"));
                }
                self.prepend = count;
            }
            "communities" => {
                self.communities = items().map(parse_community).collect::<Result<_, _>>()?
            }
            "large_communities" => {
                self.large_communities = items()
                    .map(parse_large_community)
                    .collect::<Result<_, _>>()?
            }
            "extended_communities" => {
                self.extended_communities = items()
                    .map(parse_extended_community)
                    .collect::<Result<_, _>>()?
            }
            _ => return Err(format!("unknown route attribute {key}")),
        }
        Ok(())
    }
}

/// `65000:100` (RFC 1997).
fn parse_community(value: &str) -> Result<u32, String> {
    let error = || format!("invalid community {value}, expected ASN:VALUE");
    let (high, low) = value.split_once(':').ok_or_else(error)?;
    let high: u16 = high.parse().map_err(|_| error())?;
    let low: u16 = low.parse().map_err(|_| error())?;
    Ok(u32::from(high) << 16 | u32::from(low))
}

pub fn format_community(value: u32) -> String {
    format!("{}:{}", value >> 16, value & 0xffff)
}

/// `65000:1:2` (RFC 8092).
fn parse_large_community(value: &str) -> Result<[u32; 3], String> {
    let error = || format!("invalid large community {value}, expected ASN:VALUE:VALUE");
    let parts: Vec<u32> = value
        .split(':')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| error())?;
    parts.try_into().map_err(|_| error())
}

/// Route target or site of origin (RFC 4360, RFC 5668): `rt:65000:100`, `rt:4200000000:100`,
/// `rt:192.0.2.1:100`, and the same with `soo:`.
fn parse_extended_community(value: &str) -> Result<[u8; 8], String> {
    let error =
        || format!("invalid extended community {value}, expected rt|soo:ASN:N or rt|soo:IPv4:N");
    let mut parts = value.splitn(3, ':');
    let (Some(kind), Some(admin), Some(number)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(error());
    };
    let mut bytes = [0; 8];
    bytes[1] = match kind {
        "rt" => 2,
        "soo" => 3,
        _ => return Err(error()),
    };
    if let Ok(ip) = admin.parse::<Ipv4Addr>() {
        bytes[0] = 0x01;
        bytes[2..6].copy_from_slice(&ip.octets());
        bytes[6..8].copy_from_slice(&number.parse::<u16>().map_err(|_| error())?.to_be_bytes());
    } else {
        let asn: u32 = admin.parse().map_err(|_| error())?;
        if let Ok(asn) = u16::try_from(asn) {
            bytes[2..4].copy_from_slice(&asn.to_be_bytes());
            bytes[4..8].copy_from_slice(&number.parse::<u32>().map_err(|_| error())?.to_be_bytes());
        } else {
            bytes[0] = 0x02;
            bytes[2..6].copy_from_slice(&asn.to_be_bytes());
            bytes[6..8].copy_from_slice(&number.parse::<u16>().map_err(|_| error())?.to_be_bytes());
        }
    }
    Ok(bytes)
}

pub fn parse_rd(value: &str) -> Result<[u8; 8], String> {
    let mut rd = parse_extended_community(&format!("rt:{value}"))?;
    rd[1] = rd[0];
    rd[0] = 0;
    Ok(rd)
}

pub fn format_extended_community(bytes: &[u8; 8]) -> String {
    let kind = if bytes[1] == 2 { "rt" } else { "soo" };
    let u16_at = |i: usize| u16::from_be_bytes([bytes[i], bytes[i + 1]]);
    let u32_at =
        |i: usize| u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    match bytes[0] {
        0x01 => format!(
            "{kind}:{}:{}",
            Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]),
            u16_at(6)
        ),
        0x02 => format!("{kind}:{}:{}", u32_at(2), u16_at(6)),
        _ => format!("{kind}:{}:{}", u16_at(2), u32_at(4)),
    }
}

#[derive(Default)]
pub struct RouteStore {
    routes: Vec<Route>,
}

impl RouteStore {
    pub fn add(&mut self, route: Route) -> bool {
        if self
            .routes
            .iter()
            .any(|current| current.prefix == route.prefix)
        {
            return false;
        }
        self.routes.push(route);
        true
    }

    pub fn remove(&mut self, prefix: Prefix) -> Option<Route> {
        self.routes
            .iter()
            .position(|route| route.prefix == prefix)
            .map(|index| self.routes.remove(index))
    }

    pub fn list(&self) -> &[Route] {
        &self.routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_rejects_host_bits() {
        assert!("192.0.2.1/24".parse::<Prefix>().is_err());
        assert!("2001:db8::1/64".parse::<Prefix>().is_err());
        assert!("2001:db8::/129".parse::<Prefix>().is_err());
        for prefix in [
            "::/0",
            "::1/128",
            "2001:db8::/32",
            "0.0.0.0/0",
            "192.0.2.1/32",
        ] {
            assert_eq!(prefix.parse::<Prefix>().unwrap().to_string(), prefix);
        }
    }

    #[test]
    fn parses_and_formats_attributes() {
        let mut route = Route::new("192.0.2.0/24".parse().unwrap(), Ipv4Addr::LOCALHOST);
        route
            .set_attribute("communities", "65000:100, 65535:666")
            .unwrap();
        route
            .set_attribute("large_communities", r#"["65000:1:2"]"#)
            .unwrap();
        route
            .set_attribute(
                "extended_communities",
                "rt:65000:100 soo:192.0.2.1:7 rt:4200000000:9",
            )
            .unwrap();
        assert_eq!(route.communities, [65000 << 16 | 100, 65535 << 16 | 666]);
        assert_eq!(format_community(route.communities[1]), "65535:666");
        assert_eq!(route.large_communities, [[65000, 1, 2]]);
        assert_eq!(
            route.extended_communities[0],
            [0, 2, 0xfd, 0xe8, 0, 0, 0, 100]
        );
        let formatted: Vec<_> = route
            .extended_communities
            .iter()
            .map(format_extended_community)
            .collect();
        assert_eq!(
            formatted,
            ["rt:65000:100", "soo:192.0.2.1:7", "rt:4200000000:9"]
        );
        assert!(route.set_attribute("communities", "70000:1").is_err());
        assert!(route
            .set_attribute("extended_communities", "rt:192.0.2.1:70000")
            .is_err());
        assert!(route.set_attribute("prepend", "33").is_err());
        route.set_attribute("as_path", "65010 13335").unwrap();
        assert_eq!(route.as_path, [65010, 13335]);
        assert!(route.set_attribute("as_path", "4200000000").is_err());
        assert!(route.set_attribute("origin", "igp").is_err());
    }

    #[test]
    fn store_adds_and_removes_routes() {
        let prefix = "192.0.2.0/24".parse().unwrap();
        let route = Route::new(prefix, "198.51.100.1".parse::<IpAddr>().unwrap());
        let mut store = RouteStore::default();
        assert!(store.add(route.clone()));
        assert!(!store.add(route));
        assert!(store.remove(prefix).is_some());
        assert!(store.list().is_empty());
    }

    #[test]
    fn vpn_identity_keeps_overlapping_routes_separate() {
        let mut store = RouteStore::default();
        for prefix in ["10.0.0.0/24", "65000:1@10.0.0.0/24", "65000:2@10.0.0.0/24"] {
            let prefix: Prefix = prefix.parse().unwrap();
            assert!(store.add(Route::new(prefix, Ipv4Addr::LOCALHOST)));
            assert_eq!(prefix.to_string().parse::<Prefix>().unwrap(), prefix);
        }
        assert_eq!(store.list().len(), 3);
        store
            .remove("65000:1@10.0.0.0/24".parse().unwrap())
            .unwrap();
        assert_eq!(store.list().len(), 2);
        for rd in ["65000:10", "192.0.2.1:10", "4200000000:10"] {
            let prefix: Prefix = format!("{rd}@2001:db8::/32").parse().unwrap();
            assert_eq!(prefix.rd_text().as_deref(), Some(rd));
        }
        assert!("65000:4294967296@10.0.0.0/24".parse::<Prefix>().is_err());
    }
}
