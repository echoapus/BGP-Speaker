use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, TcpStream},
    time::{Duration, Instant},
};

use crate::{
    config::PeerConfig,
    route::{Prefix, Route},
};

const MARKER: [u8; 16] = [0xff; 16];
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);
// RFC 4271 limit; RFC 8654 extended messages are not negotiated.
const MAX_MESSAGE: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Open {
        asn: u16,
        hold_time: u16,
        router_id: Ipv4Addr,
        ipv6_unicast: bool,
        vpn: [bool; 2],
    },
    Keepalive,
    Update {
        route: Option<Route>,
        withdraw: Option<Prefix>,
        local_as: u16,
    },
    Notification {
        code: u8,
        subcode: u8,
    },
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut body = Vec::new();
        let kind = match self {
            Self::Open {
                asn,
                hold_time,
                router_id,
                ipv6_unicast,
                vpn,
            } => {
                body.extend([
                    4,
                    (asn >> 8) as u8,
                    *asn as u8,
                    (hold_time >> 8) as u8,
                    *hold_time as u8,
                ]);
                body.extend_from_slice(&router_id.octets());
                // Multiprotocol IPv4 and optionally IPv6 unicast capabilities.
                // (RFC 4760). Without it many routers show the family as "NoNeg". Route
                // refresh and 4-byte ASN are not advertised because they are not implemented.
                body.extend([
                    8 + u8::from(*ipv6_unicast) * 8 + vpn.iter().filter(|v| **v).count() as u8 * 8,
                    2,
                    6,
                    1,
                    4,
                    0,
                    1,
                    0,
                    1,
                ]);
                if *ipv6_unicast {
                    body.extend([2, 6, 1, 4, 0, 2, 0, 1]);
                }
                for (index, enabled) in vpn.iter().enumerate() {
                    if *enabled {
                        body.extend([2, 6, 1, 4, 0, index as u8 + 1, 0, 128]);
                    }
                }
                1
            }
            Self::Keepalive => 4,
            Self::Notification { code, subcode } => {
                body.extend([*code, *subcode]);
                3
            }
            Self::Update {
                route,
                withdraw,
                local_as,
            } => {
                let mut withdrawn = Vec::new();
                if let Some(prefix) = withdraw {
                    if prefix.address.is_ipv4() && prefix.rd.is_none() {
                        withdrawn.extend(prefix.wire_bytes());
                    }
                }
                body.push((withdrawn.len() >> 8) as u8);
                body.push(withdrawn.len() as u8);
                body.extend(withdrawn);
                if let Some(route) = route {
                    validate_route(route)?;
                    if route.prefix.address.is_ipv4() != route.next_hop.is_ipv4() {
                        return Err("prefix and next hop must use the same IP family".into());
                    }
                    let attrs = encode_attributes(route, *local_as);
                    body.extend((attrs.len() as u16).to_be_bytes());
                    body.extend(attrs);
                    if route.prefix.address.is_ipv4() && route.prefix.rd.is_none() {
                        body.extend(route.prefix.wire_bytes());
                    }
                } else {
                    let mut attrs = Vec::new();
                    if let Some(prefix) =
                        withdraw.filter(|prefix| prefix.address.is_ipv6() || prefix.rd.is_some())
                    {
                        let mut value = vec![
                            0,
                            if prefix.address.is_ipv4() { 1 } else { 2 },
                            if prefix.rd.is_some() { 128 } else { 1 },
                        ];
                        if prefix.rd.is_some() {
                            let mut nlri = prefix.vpn_wire_bytes(0);
                            nlri[1..4].copy_from_slice(&[0x80, 0, 0]);
                            value.extend(nlri);
                        } else {
                            value.extend(prefix.wire_bytes());
                        }
                        push_attribute(&mut attrs, 0x80, 15, &value);
                    }
                    body.extend((attrs.len() as u16).to_be_bytes());
                    body.extend(attrs);
                }
                2
            }
        };
        let length = 19 + body.len();
        if length > MAX_MESSAGE {
            return Err(format!(
                "BGP message is {length} bytes, the limit is {MAX_MESSAGE}"
            ));
        }
        let mut result = Vec::with_capacity(length);
        result.extend(MARKER);
        result.extend_from_slice(&(length as u16).to_be_bytes());
        result.push(kind);
        result.extend(body);
        Ok(result)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 19 || bytes[..16] != MARKER {
            return Err("invalid BGP header".into());
        }
        let length = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
        if length != bytes.len() || !(19..=MAX_MESSAGE).contains(&length) {
            return Err("invalid BGP length".into());
        }
        let body = &bytes[19..];
        match bytes[18] {
            1 if body.len() >= 10 && body[0] == 4 && usize::from(body[9]) + 10 == body.len() => {
                Ok(Self::Open {
                    asn: u16::from_be_bytes([body[1], body[2]]),
                    hold_time: u16::from_be_bytes([body[3], body[4]]),
                    router_id: Ipv4Addr::new(body[5], body[6], body[7], body[8]),
                    ipv6_unicast: ipv6_capability(&body[10..])?,
                    vpn: [
                        has_capability(&body[10..], 1, 128)?,
                        has_capability(&body[10..], 2, 128)?,
                    ],
                })
            }
            2 => decode_update(body),
            3 if body.len() >= 2 => Ok(Self::Notification {
                code: body[0],
                subcode: body[1],
            }),
            4 if body.is_empty() => Ok(Self::Keepalive),
            _ => Err("invalid or unsupported BGP message".into()),
        }
    }
}

fn ipv6_capability(parameters: &[u8]) -> Result<bool, String> {
    has_capability(parameters, 2, 1)
}

fn has_capability(mut parameters: &[u8], afi: u8, safi: u8) -> Result<bool, String> {
    let mut supported = false;
    while !parameters.is_empty() {
        if parameters.len() < 2 || parameters.len() < 2 + usize::from(parameters[1]) {
            return Err("truncated OPEN parameter".into());
        }
        let length = usize::from(parameters[1]);
        if parameters[0] == 2 {
            let mut capabilities = &parameters[2..2 + length];
            while !capabilities.is_empty() {
                if capabilities.len() < 2 || capabilities.len() < 2 + usize::from(capabilities[1]) {
                    return Err("truncated OPEN capability".into());
                }
                let size = usize::from(capabilities[1]);
                if capabilities[0] == 1 && capabilities[2..2 + size] == [0, afi, 0, safi] {
                    supported = true;
                }
                capabilities = &capabilities[2 + size..];
            }
        }
        parameters = &parameters[2 + length..];
    }
    Ok(supported)
}

// Path attributes in type-code order. Flags: 0x40 well-known, 0x80 optional,
// 0xc0 optional transitive.
fn encode_attributes(route: &Route, local_as: u16) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attribute(&mut attrs, 0x40, 1, &[0]); // ORIGIN IGP
                                               // One AS_SEQUENCE segment: the local AS (plus prepends), then the route's own path.
    let local = 1 + usize::from(route.prepend);
    let mut path = vec![2, (local + route.as_path.len()) as u8];
    for asn in std::iter::repeat_n(local_as, local).chain(route.as_path.iter().copied()) {
        path.extend(asn.to_be_bytes());
    }
    push_attribute(&mut attrs, 0x40, 2, &path);
    if let IpAddr::V4(ip) = route.next_hop {
        if route.prefix.rd.is_none() {
            push_attribute(&mut attrs, 0x40, 3, &ip.octets());
        }
    }
    if route.prefix.rd.is_some() || route.next_hop.is_ipv6() {
        let vpn = route.prefix.rd.is_some();
        let mut hop = Vec::new();
        if vpn {
            hop.extend([0; 8]);
        }
        match route.next_hop {
            IpAddr::V4(ip) => hop.extend(ip.octets()),
            IpAddr::V6(ip) => hop.extend(ip.octets()),
        }
        let mut value = vec![
            0,
            if route.prefix.address.is_ipv4() { 1 } else { 2 },
            if vpn { 128 } else { 1 },
            hop.len() as u8,
        ];
        value.extend(hop);
        value.push(0);
        if vpn {
            value.extend(route.prefix.vpn_wire_bytes(route.label.unwrap_or(0)));
        } else {
            value.extend(route.prefix.wire_bytes());
        }
        push_attribute(&mut attrs, 0x80, 14, &value);
    }
    if let Some(med) = route.med {
        push_attribute(&mut attrs, 0x80, 4, &med.to_be_bytes());
    }
    if !route.communities.is_empty() {
        let value: Vec<u8> = route
            .communities
            .iter()
            .flat_map(|community| community.to_be_bytes())
            .collect();
        push_attribute(&mut attrs, 0xc0, 8, &value);
    }
    if !route.extended_communities.is_empty() {
        push_attribute(&mut attrs, 0xc0, 16, &route.extended_communities.concat());
    }
    if !route.large_communities.is_empty() {
        let value: Vec<u8> = route
            .large_communities
            .iter()
            .flatten()
            .flat_map(|part| part.to_be_bytes())
            .collect();
        push_attribute(&mut attrs, 0xc0, 32, &value);
    }
    attrs
}

fn push_attribute(attrs: &mut Vec<u8>, flags: u8, code: u8, value: &[u8]) {
    if value.len() > 255 {
        attrs.extend([flags | 0x10, code]); // extended length
        attrs.extend((value.len() as u16).to_be_bytes());
    } else {
        attrs.extend([flags, code, value.len() as u8]);
    }
    attrs.extend_from_slice(value);
}

/// Rejects a route whose UPDATE would not fit in one BGP message.
pub fn check_route(route: &Route) -> Result<(), String> {
    Message::Update {
        route: Some(route.clone()),
        withdraw: None,
        local_as: 0,
    }
    .encode()
    .map(|_| ())
}

fn validate_route(route: &Route) -> Result<(), String> {
    if route.prefix.rd.is_some() {
        if !matches!(route.label, Some(16..=1048575)) {
            return Err("VPN routes require an MPLS label (16–1048575)".into());
        }
        if !route.extended_communities.iter().any(|c| c[1] == 2) {
            return Err("VPN routes require a route target".into());
        }
    } else if route.label.is_some() {
        return Err("MPLS labels require a VPN route".into());
    }
    Ok(())
}

// Received routes are not used, so only the UPDATE framing is checked.
fn decode_update(body: &[u8]) -> Result<Message, String> {
    if body.len() < 4 {
        return Err("truncated UPDATE".into());
    }
    let withdrawn_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + withdrawn_len + 2 {
        return Err("truncated withdrawn routes".into());
    }
    let attrs_start = 2 + withdrawn_len;
    let attrs_len = u16::from_be_bytes([body[attrs_start], body[attrs_start + 1]]) as usize;
    if body.len() < attrs_start + 2 + attrs_len {
        return Err("truncated path attributes".into());
    }
    Ok(Message::Update {
        route: None,
        withdraw: None,
        local_as: 0,
    })
}

pub fn send(stream: &mut TcpStream, message: &Message) -> io::Result<()> {
    let bytes = message.encode().map_err(io::Error::other)?;
    stream.write_all(&bytes)
}

#[derive(Default)]
pub struct MessageReader {
    bytes: Vec<u8>,
    started: Option<Instant>,
}

impl MessageReader {
    // Length from the header once it is complete, checked against the RFC limits.
    fn frame_length(&self) -> io::Result<Option<usize>> {
        if self.bytes.len() < 19 {
            return Ok(None);
        }
        let length = u16::from_be_bytes([self.bytes[16], self.bytes[17]]) as usize;
        if !(19..=MAX_MESSAGE).contains(&length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid BGP length",
            ));
        }
        Ok(Some(length))
    }

    pub fn receive(&mut self, stream: &mut impl Read) -> io::Result<Message> {
        if self
            .started
            .is_some_and(|start| start.elapsed() >= MESSAGE_TIMEOUT)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "partial BGP message timed out",
            ));
        }
        let target = self.frame_length()?.unwrap_or(19);
        let have = self.bytes.len();
        if have < target {
            // Read straight into the buffer, never past this message.
            self.bytes.resize(target, 0);
            let result = stream.read(&mut self.bytes[have..]);
            self.bytes
                .truncate(have + result.as_ref().copied().unwrap_or(0));
            if result? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "BGP connection closed",
                ));
            }
            self.started.get_or_insert_with(Instant::now);
        }
        if self.frame_length()? == Some(self.bytes.len()) {
            let message = Message::decode(&self.bytes).map_err(io::Error::other)?;
            self.bytes.clear();
            self.started = None;
            return Ok(message);
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "partial BGP message",
        ))
    }
}

pub fn open_for(peer: &PeerConfig) -> Message {
    Message::Open {
        asn: peer.local_as as u16,
        hold_time: peer.hold_time,
        router_id: peer.router_id,
        ipv6_unicast: true,
        vpn: [true; 2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_updates_use_separate_safi_and_labeled_rd_nlri() {
        for (network, hop, afi) in [
            ("10.0.0.0/24", "192.0.2.1", 1),
            ("2001:db8::/32", "2001:db8::1", 2),
        ] {
            let prefix: Prefix = format!("65000:100@{network}").parse().unwrap();
            let mut route = Route::new(prefix, hop.parse::<IpAddr>().unwrap());
            assert!(check_route(&route).is_err());
            route.set_attribute("label", "1000").unwrap();
            assert!(check_route(&route).is_err());
            route
                .set_attribute("extended_communities", "rt:65000:100")
                .unwrap();
            let encoded = Message::Update {
                route: Some(route),
                withdraw: None,
                local_as: 65000,
            }
            .encode()
            .unwrap();
            let mut expected = vec![0x80, 14];
            let hop_bytes = if afi == 1 {
                vec![192, 0, 2, 1]
            } else {
                "2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec()
            };
            let mut value = vec![0, afi, 128, (8 + hop_bytes.len()) as u8];
            value.extend([0; 8]);
            value.extend(hop_bytes);
            value.push(0);
            value.extend([
                prefix.length + 88,
                0,
                0x3e,
                0x81,
                0,
                0,
                0xfd,
                0xe8,
                0,
                0,
                0,
                100,
            ]);
            value.extend_from_slice(&prefix.wire_bytes()[1..]);
            expected.push(value.len() as u8);
            expected.extend(value);
            assert!(encoded.windows(expected.len()).any(|part| part == expected));
            assert_eq!(&encoded[19..21], &[0, 0]);
            let withdrawn = Message::Update {
                route: None,
                withdraw: Some(prefix),
                local_as: 65000,
            }
            .encode()
            .unwrap();
            assert_eq!(
                &withdrawn[23..30],
                &[
                    0x80,
                    15,
                    (4 + prefix.vpn_wire_bytes(0).len() - 1) as u8,
                    0,
                    afi,
                    128,
                    prefix.length + 88
                ]
            );
            assert_eq!(&withdrawn[30..33], &[0x80, 0, 0]);
        }
    }

    #[test]
    fn vpn_capabilities_round_trip_independently() {
        for vpn in [[false, false], [true, false], [false, true], [true, true]] {
            let open = Message::Open {
                asn: 65000,
                hold_time: 90,
                router_id: Ipv4Addr::LOCALHOST,
                ipv6_unicast: false,
                vpn,
            };
            assert_eq!(Message::decode(&open.encode().unwrap()).unwrap(), open);
        }
    }

    #[test]
    fn ipv6_updates_and_capabilities() {
        let open = Message::Open {
            asn: 65000,
            hold_time: 90,
            router_id: Ipv4Addr::LOCALHOST,
            ipv6_unicast: true,
            vpn: [false; 2],
        };
        assert_eq!(Message::decode(&open.encode().unwrap()).unwrap(), open);
        assert!(ipv6_capability(&[2, 6, 1]).is_err());
        let route = Route::new(
            "2001:db8::/32".parse().unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap(),
        );
        let bytes = Message::Update {
            route: Some(route.clone()),
            withdraw: None,
            local_as: 65000,
        }
        .encode()
        .unwrap();
        let mut reach = vec![0x80, 14, 26, 0, 2, 1, 16];
        reach.extend(
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        reach.extend([0, 32, 0x20, 1, 0x0d, 0xb8]);
        assert!(bytes.windows(reach.len()).any(|part| part == reach));
        assert_eq!(&bytes[19..23], &[0, 0, 0, 40]);
        let withdraw = Message::Update {
            route: None,
            withdraw: Some(route.prefix),
            local_as: 65000,
        }
        .encode()
        .unwrap();
        assert_eq!(
            &withdraw[19..],
            &[0, 0, 0, 11, 0x80, 15, 8, 0, 2, 1, 32, 0x20, 1, 0x0d, 0xb8]
        );
        let mut invalid = route;
        invalid.next_hop = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(check_route(&invalid).is_err());
    }

    #[test]
    fn partial_messages_survive_polls_and_expire() {
        let bytes = Message::Keepalive.encode().unwrap();
        let mut reader = MessageReader::default();
        assert_eq!(
            reader.receive(&mut &bytes[..5]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            reader.receive(&mut &bytes[5..]).unwrap(),
            Message::Keepalive
        );
        reader.bytes.push(0xff);
        reader.started = Some(Instant::now() - MESSAGE_TIMEOUT);
        assert_eq!(
            reader.receive(&mut &[][..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn open_advertises_ipv4_unicast_and_round_trips() {
        let open = Message::Open {
            asn: 65000,
            hold_time: 90,
            router_id: Ipv4Addr::new(192, 0, 2, 1),
            ipv6_unicast: false,
            vpn: [false; 2],
        };
        let bytes = open.encode().unwrap();
        // Capabilities parameter: MP-BGP, AFI 1 (IPv4), SAFI 1 (unicast).
        assert_eq!(bytes[28..], [8, 2, 6, 1, 4, 0, 1, 0, 1]);
        assert_eq!(Message::decode(&bytes), Ok(open));
    }

    #[test]
    fn keepalive_round_trips() {
        let bytes = Message::Keepalive.encode().unwrap();
        assert_eq!(Message::decode(&bytes), Ok(Message::Keepalive));
    }

    #[test]
    fn rejects_truncated_message() {
        assert!(Message::decode(&[0xff; 19]).is_err());
    }

    #[test]
    fn encodes_withdrawal() {
        let bytes = Message::Update {
            route: None,
            withdraw: Some("198.51.100.0/24".parse().unwrap()),
            local_as: 65000,
        }
        .encode()
        .unwrap();
        let mut expected = vec![0xff; 16];
        expected.extend([0, 27, 2, 0, 4, 24, 198, 51, 100, 0, 0]);
        assert_eq!(bytes, expected);
        assert!(Message::decode(&bytes).is_ok());
    }

    #[test]
    fn encodes_announcement() {
        let bytes = Message::Update {
            route: Some(Route::new(
                "198.51.100.0/24".parse().unwrap(),
                Ipv4Addr::new(192, 0, 2, 1),
            )),
            withdraw: None,
            local_as: 65000,
        }
        .encode()
        .unwrap();
        let mut expected = vec![0xff; 16];
        expected.extend([0, 45, 2, 0, 0, 0, 18]);
        // ORIGIN IGP, AS_PATH AS_SEQUENCE [65000], NEXT_HOP 192.0.2.1
        expected.extend([0x40, 1, 1, 0]);
        expected.extend([0x40, 2, 4, 2, 1, 0xfd, 0xe8]);
        expected.extend([0x40, 3, 4, 192, 0, 2, 1]);
        expected.extend([24, 198, 51, 100]);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn encodes_optional_attributes() {
        let mut route = Route::new(
            "198.51.100.0/24".parse().unwrap(),
            Ipv4Addr::new(192, 0, 2, 1),
        );
        route.med = Some(10);
        route.prepend = 2;
        route.communities = vec![65000 << 16 | 100];
        route.extended_communities = vec![[0, 2, 0xfd, 0xe8, 0, 0, 0, 100]];
        route.large_communities = vec![[65000, 1, 2]];
        route.as_path = vec![13335];
        let attrs = encode_attributes(&route, 65000);
        let mut expected = vec![0x40, 1, 1, 0];
        // AS_SEQUENCE 65000 65000 65000 13335
        expected.extend([
            0x40, 2, 10, 2, 4, 0xfd, 0xe8, 0xfd, 0xe8, 0xfd, 0xe8, 0x34, 0x17,
        ]);
        expected.extend([0x40, 3, 4, 192, 0, 2, 1]);
        expected.extend([0x80, 4, 4, 0, 0, 0, 10]);
        expected.extend([0xc0, 8, 4, 0xfd, 0xe8, 0, 100]);
        expected.extend([0xc0, 16, 8, 0, 2, 0xfd, 0xe8, 0, 0, 0, 100]);
        expected.extend([0xc0, 32, 12, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(attrs, expected);
    }

    #[test]
    fn long_attribute_uses_extended_length() {
        let mut route = Route::new(
            "198.51.100.0/24".parse().unwrap(),
            Ipv4Addr::new(192, 0, 2, 1),
        );
        route.communities = vec![1; 64];
        let attrs = encode_attributes(&route, 65000);
        let start = attrs.len() - 256 - 4;
        assert_eq!(attrs[start..start + 4], [0xd0, 8, 1, 0]);
        assert!(check_route(&route).is_ok());
        route.communities = vec![1; 1100];
        assert!(check_route(&route).is_err());
    }
}
