use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpStream},
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
            } => {
                body.extend([
                    4,
                    (asn >> 8) as u8,
                    *asn as u8,
                    (hold_time >> 8) as u8,
                    *hold_time as u8,
                ]);
                body.extend_from_slice(&router_id.octets());
                body.extend([0]);
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
                    withdrawn.extend(prefix.wire_bytes());
                }
                body.push((withdrawn.len() >> 8) as u8);
                body.push(withdrawn.len() as u8);
                body.extend(withdrawn);
                if let Some(route) = route {
                    let attrs = encode_attributes(route, *local_as);
                    body.extend((attrs.len() as u16).to_be_bytes());
                    body.extend(attrs);
                    body.extend(route.prefix.wire_bytes());
                } else {
                    body.extend([0, 0]);
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
    push_attribute(&mut attrs, 0x40, 3, &route.next_hop.octets());
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
