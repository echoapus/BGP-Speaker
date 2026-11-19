use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpStream},
};

use crate::{
    config::PeerConfig,
    route::{Prefix, Route},
};

const MARKER: [u8; 16] = [0xff; 16];

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
                    let attrs = vec![
                        0x40,
                        1,
                        1,
                        0,
                        0x40,
                        2,
                        4,
                        2,
                        1,
                        (local_as >> 8) as u8,
                        *local_as as u8,
                        0x40,
                        3,
                        4,
                        route.next_hop.octets()[0],
                        route.next_hop.octets()[1],
                        route.next_hop.octets()[2],
                        route.next_hop.octets()[3],
                    ];
                    body.push(0);
                    body.push(attrs.len() as u8);
                    body.extend(attrs);
                    body.extend(route.prefix.wire_bytes());
                } else {
                    body.extend([0, 0]);
                }
                2
            }
        };
        let length = 19 + body.len();
        if length > u16::MAX as usize {
            return Err("BGP message is too large".into());
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
        if length != bytes.len() || !(19..=4096).contains(&length) {
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
    let nlri = &body[attrs_start + 2 + attrs_len..];
    if !nlri.is_empty() {
        parse_prefix(nlri).map(|_| Message::Update {
            route: None,
            withdraw: None,
            local_as: 0,
        })
    } else if withdrawn_len > 0 {
        parse_prefix(&body[2..2 + withdrawn_len]).map(|prefix| Message::Update {
            route: None,
            withdraw: Some(prefix),
            local_as: 0,
        })
    } else {
        Ok(Message::Update {
            route: None,
            withdraw: None,
            local_as: 0,
        })
    }
}

fn parse_prefix(bytes: &[u8]) -> Result<Prefix, String> {
    let length = *bytes.first().ok_or("missing prefix length")?;
    let count = usize::from(length.div_ceil(8));
    if length > 32 || bytes.len() < count + 1 {
        return Err("invalid prefix NLRI".into());
    }
    let mut octets = [0; 4];
    octets[..count].copy_from_slice(&bytes[1..count + 1]);
    Prefix::new(Ipv4Addr::from(octets), length)
}

pub fn send(stream: &mut TcpStream, message: &Message) -> io::Result<()> {
    let bytes = message.encode().map_err(io::Error::other)?;
    stream.write_all(&bytes)
}

pub fn receive(stream: &mut TcpStream) -> io::Result<Message> {
    let mut header = [0; 19];
    stream.read_exact(&mut header)?;
    let length = u16::from_be_bytes([header[16], header[17]]) as usize;
    if !(19..=4096).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid BGP length",
        ));
    }
    let mut bytes = header.to_vec();
    bytes.resize(length, 0);
    stream.read_exact(&mut bytes[19..])?;
    Message::decode(&bytes).map_err(io::Error::other)
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
        let prefix = "198.51.100.0/24".parse().unwrap();
        let bytes = Message::Update {
            route: None,
            withdraw: Some(prefix),
            local_as: 65000,
        }
        .encode()
        .unwrap();
        assert_eq!(
            Message::decode(&bytes).unwrap(),
            Message::Update {
                route: None,
                withdraw: Some(prefix),
                local_as: 0,
            }
        );
    }
}
