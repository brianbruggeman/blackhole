//! Bounded sans-I/O DHCPv4 primitives for the optional LAN adapter.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

pub const MAX_DHCP_PACKET: usize = 1500;
const FIXED_HEADER: usize = 236;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const OPTION_END: u8 = 255;
const OPTION_PAD: u8 = 0;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_SERVER_IDENTIFIER: u8 = 54;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl MessageType {
    fn from_wire(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'packet> {
    pub transaction_id: u32,
    pub client: [u8; 6],
    pub message_type: MessageType,
    pub requested_ip: Option<Ipv4Addr>,
    pub server_identifier: Option<Ipv4Addr>,
    pub broadcast: bool,
    packet: &'packet [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    InvalidOperation,
    InvalidHardwareAddress,
    InvalidCookie,
    MissingMessageType,
    InvalidOption,
    UnsupportedMessageType,
}

impl<'packet> Request<'packet> {
    pub fn parse(packet: &'packet [u8]) -> Result<Request<'packet>, ParseError> {
        if packet.len() > MAX_DHCP_PACKET || packet.len() < FIXED_HEADER + 4 {
            return Err(ParseError::TooShort);
        }
        if packet[0] != 1 || packet[1] != 1 || packet[2] != 6 {
            return Err(ParseError::InvalidOperation);
        }
        if packet[3] != 0 {
            return Err(ParseError::InvalidHardwareAddress);
        }
        if packet[236..240] != MAGIC_COOKIE {
            return Err(ParseError::InvalidCookie);
        }
        let transaction_id = u32::from_be_bytes(packet[4..8].try_into().unwrap());
        let mut client = [0u8; 6];
        client.copy_from_slice(&packet[28..34]);
        let flags = u16::from_be_bytes(packet[10..12].try_into().unwrap());
        let mut message_type = None;
        let mut requested_ip = None;
        let mut server_identifier = None;
        let mut cursor = 240;
        while cursor < packet.len() {
            let kind = packet[cursor];
            cursor += 1;
            if kind == OPTION_END {
                break;
            }
            if kind == OPTION_PAD {
                continue;
            }
            let length = *packet.get(cursor).ok_or(ParseError::InvalidOption)? as usize;
            cursor += 1;
            let end = cursor
                .checked_add(length)
                .ok_or(ParseError::InvalidOption)?;
            let value = packet.get(cursor..end).ok_or(ParseError::InvalidOption)?;
            match kind {
                OPTION_MESSAGE_TYPE if length == 1 => {
                    message_type = MessageType::from_wire(value[0]);
                }
                OPTION_REQUESTED_IP if length == 4 => {
                    let octets: [u8; 4] = value.try_into().unwrap();
                    requested_ip = Some(Ipv4Addr::from(octets));
                }
                OPTION_SERVER_IDENTIFIER if length == 4 => {
                    let octets: [u8; 4] = value.try_into().unwrap();
                    server_identifier = Some(Ipv4Addr::from(octets));
                }
                _ => {}
            }
            cursor = end;
        }
        Ok(Self {
            transaction_id,
            client,
            message_type: message_type.ok_or(ParseError::MissingMessageType)?,
            requested_ip,
            server_identifier,
            broadcast: flags & 0x8000 != 0,
            packet,
        })
    }

    #[must_use]
    pub fn packet_len(&self) -> usize {
        self.packet.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyConfig {
    pub server: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub dns: Option<Ipv4Addr>,
    pub lease_secs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    OutputTooSmall,
    InvalidLease,
}

pub fn encode_reply(
    request: &Request<'_>,
    message_type: MessageType,
    address: Ipv4Addr,
    config: ReplyConfig,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    if config.lease_secs == 0 {
        return Err(EncodeError::InvalidLease);
    }
    let required = 240
        + 3
        + 6
        + 6
        + config.router.is_some() as usize * 6
        + config.dns.is_some() as usize * 6
        + 1;
    if output.len() < required || output.len() > MAX_DHCP_PACKET {
        return Err(EncodeError::OutputTooSmall);
    }
    output[..required].fill(0);
    output[0] = 2;
    output[1] = 1;
    output[2] = 6;
    output[4..8].copy_from_slice(&request.transaction_id.to_be_bytes());
    output[10..12].copy_from_slice(&if request.broadcast { 0x8000u16 } else { 0 }.to_be_bytes());
    output[16..20].copy_from_slice(&address.octets());
    output[20..24].copy_from_slice(&config.server.octets());
    output[28..34].copy_from_slice(&request.client);
    output[236..240].copy_from_slice(&MAGIC_COOKIE);
    let mut cursor = 240;
    push_option(
        &mut output[cursor..],
        OPTION_MESSAGE_TYPE,
        &[message_type as u8],
    );
    cursor += 3;
    push_option(&mut output[cursor..], 1, &config.subnet_mask.octets());
    cursor += 6;
    if let Some(router) = config.router {
        push_option(&mut output[cursor..], 3, &router.octets());
        cursor += 6;
    }
    if let Some(dns) = config.dns {
        push_option(&mut output[cursor..], 6, &dns.octets());
        cursor += 6;
    }
    push_option(&mut output[cursor..], 51, &config.lease_secs.to_be_bytes());
    cursor += 6;
    output[cursor] = OPTION_END;
    Ok(cursor + 1)
}

fn push_option(output: &mut [u8], kind: u8, value: &[u8]) {
    output[0] = kind;
    output[1] = value.len() as u8;
    output[2..2 + value.len()].copy_from_slice(value);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pool {
    start: u32,
    end: u32,
}

impl Pool {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Option<Self> {
        let start = u32::from(start);
        let end = u32::from(end);
        (start <= end).then_some(Self { start, end })
    }

    pub fn allocate(
        &self,
        leases: &mut BTreeMap<[u8; 6], (Ipv4Addr, u64)>,
        client: [u8; 6],
        now_secs: u64,
        lease_secs: u32,
    ) -> Option<Ipv4Addr> {
        if lease_secs == 0 {
            return None;
        }
        leases.retain(|_, (_, expiry)| *expiry > now_secs);
        if let Some((address, expiry)) = leases.get_mut(&client) {
            *expiry = now_secs.saturating_add(u64::from(lease_secs));
            return Some(*address);
        }
        for candidate in self.start..=self.end {
            let address = Ipv4Addr::from(candidate);
            if !leases.values().any(|(used, _)| *used == address) {
                leases.insert(
                    client,
                    (address, now_secs.saturating_add(u64::from(lease_secs))),
                );
                return Some(address);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discover() -> Vec<u8> {
        let mut packet = vec![0u8; 240];
        packet[0] = 1;
        packet[1] = 1;
        packet[2] = 6;
        packet[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        packet[28..34].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
        packet[236..240].copy_from_slice(&MAGIC_COOKIE);
        packet.extend_from_slice(&[
            OPTION_MESSAGE_TYPE,
            1,
            MessageType::Discover as u8,
            OPTION_END,
        ]);
        packet
    }

    #[test]
    fn parses_bounded_discover_and_encodes_offer() {
        let packet = discover();
        let request = Request::parse(&packet).expect("discover");
        assert_eq!(request.transaction_id, 0x1234_5678);
        assert_eq!(request.client, [0, 1, 2, 3, 4, 5]);
        let mut output = [0u8; MAX_DHCP_PACKET];
        let length = encode_reply(
            &request,
            MessageType::Offer,
            Ipv4Addr::new(192, 0, 2, 20),
            ReplyConfig {
                server: Ipv4Addr::new(192, 0, 2, 1),
                subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
                router: None,
                dns: Some(Ipv4Addr::new(192, 0, 2, 1)),
                lease_secs: 300,
            },
            &mut output,
        )
        .expect("offer");
        assert_eq!(&output[16..20], &[192, 0, 2, 20]);
        assert_eq!(&output[240..243], &[OPTION_MESSAGE_TYPE, 1, 2]);
        assert!(length < MAX_DHCP_PACKET);
    }

    #[test]
    fn rejects_invalid_or_unbounded_packets() {
        assert_eq!(Request::parse(&[0; 239]), Err(ParseError::TooShort));
        let mut packet = discover();
        packet[0] = 2;
        assert_eq!(Request::parse(&packet), Err(ParseError::InvalidOperation));
        packet = vec![0; MAX_DHCP_PACKET + 1];
        assert_eq!(Request::parse(&packet), Err(ParseError::TooShort));
    }

    #[test]
    fn pool_reuses_live_leases_and_expires_them() {
        let pool =
            Pool::new(Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 11)).expect("pool");
        let mut leases = BTreeMap::new();
        let client = [0, 1, 2, 3, 4, 5];
        let first = pool.allocate(&mut leases, client, 10, 30).expect("first");
        assert_eq!(pool.allocate(&mut leases, client, 20, 30), Some(first));
        assert_eq!(
            pool.allocate(&mut leases, [6, 7, 8, 9, 10, 11], 20, 30),
            Some(Ipv4Addr::new(192, 0, 2, 11))
        );
        assert_eq!(
            pool.allocate(&mut leases, [12, 13, 14, 15, 16, 17], 51, 30),
            Some(first)
        );
    }
}
