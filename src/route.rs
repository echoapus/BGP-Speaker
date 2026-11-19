use std::{fmt, net::Ipv4Addr, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Prefix {
    pub address: Ipv4Addr,
    pub length: u8,
}

impl Prefix {
    pub fn new(address: Ipv4Addr, length: u8) -> Result<Self, String> {
        if length > 32 {
            return Err(format!("invalid IPv4 prefix length: {length}"));
        }
        let value = u32::from(address);
        let mask = if length == 0 {
            0
        } else {
            u32::MAX << (32 - length)
        };
        let network = Ipv4Addr::from(value & mask);
        if network != address {
            return Err(format!("address {address} has host bits set for /{length}"));
        }
        Ok(Self { address, length })
    }

    pub fn wire_bytes(self) -> Vec<u8> {
        let octets = self.address.octets();
        let bytes = usize::from(self.length.div_ceil(8));
        let mut result = vec![self.length];
        result.extend_from_slice(&octets[..bytes]);
        result
    }
}

impl FromStr for Prefix {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, length) = value
            .split_once('/')
            .ok_or_else(|| format!("invalid prefix: {value}"))?;
        let address = address
            .parse()
            .map_err(|_| format!("invalid IPv4 address: {address}"))?;
        let length = length
            .parse()
            .map_err(|_| format!("invalid prefix length: {length}"))?;
        Self::new(address, length)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.address, self.length)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub prefix: Prefix,
    pub next_hop: Ipv4Addr,
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
    }

    #[test]
    fn store_adds_and_removes_routes() {
        let prefix = "192.0.2.0/24".parse().unwrap();
        let route = Route {
            prefix,
            next_hop: "198.51.100.1".parse().unwrap(),
        };
        let mut store = RouteStore::default();
        assert!(store.add(route.clone()));
        assert!(!store.add(route));
        assert!(store.remove(prefix).is_some());
        assert!(store.list().is_empty());
    }
}
