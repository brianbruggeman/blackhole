//! Bounded sans-I/O DHCPv4 primitives for the optional LAN adapter.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::DhcpConfig;

pub const MAX_DHCP_PACKET: usize = 1500;
const FIXED_HEADER: usize = 236;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const OPTION_END: u8 = 255;
const OPTION_PAD: u8 = 0;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_SERVER_IDENTIFIER: u8 = 54;
const OPTION_DOMAIN_NAME: u8 = 15;

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
        let mut unsupported_message_type = false;
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
                    unsupported_message_type = message_type.is_none();
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
        if unsupported_message_type {
            return Err(ParseError::UnsupportedMessageType);
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
pub struct ReplyConfig<'domain> {
    pub server: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub dns: Option<Ipv4Addr>,
    pub dns_servers: &'domain [Ipv4Addr],
    pub domain_name: Option<&'domain str>,
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
    config: ReplyConfig<'_>,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    if config.lease_secs == 0 {
        return Err(EncodeError::InvalidLease);
    }
    let additional_dns_count = config.dns_servers.len().min(4);
    let dns_count = additional_dns_count.saturating_add(usize::from(config.dns.is_some()));
    let dns_option_bytes = if dns_count == 0 { 0 } else { 2 + dns_count * 4 };
    let required = 240
        + 3
        + 6
        + 6
        + config.router.is_some() as usize * 6
        + dns_option_bytes
        + config.domain_name.map_or(0, |name| 2 + name.len())
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
        let mut octets = [0u8; 20];
        octets[..4].copy_from_slice(&dns.octets());
        let count = additional_dns_count;
        for (index, address) in config.dns_servers[..count].iter().enumerate() {
            let start = (index + 1) * 4;
            octets[start..start + 4].copy_from_slice(&address.octets());
        }
        let octet_count = (count + 1) * 4;
        push_option(&mut output[cursor..], 6, &octets[..octet_count]);
        cursor += 2 + octet_count;
    } else if !config.dns_servers.is_empty() {
        let mut octets = [0u8; 16];
        for (index, address) in config.dns_servers.iter().take(4).enumerate() {
            let start = index * 4;
            octets[start..start + 4].copy_from_slice(&address.octets());
        }
        let octet_count = additional_dns_count * 4;
        push_option(&mut output[cursor..], 6, &octets[..octet_count]);
        cursor += 2 + octet_count;
    }
    if let Some(domain_name) = config.domain_name {
        push_option(
            &mut output[cursor..],
            OPTION_DOMAIN_NAME,
            domain_name.as_bytes(),
        );
        cursor += 2 + domain_name.len();
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

/// Handle for the opt-in DHCP adapter thread.
pub struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<std::io::Result<()>>>,
    address: std::net::SocketAddr,
}

impl Server {
    pub fn start(config: DhcpConfig) -> std::io::Result<Self> {
        let socket = std::net::UdpSocket::bind(&config.listen)?;
        let address = socket.local_addr()?;
        socket.set_broadcast(true)?;
        socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("blackhole-dhcp".into())
            .spawn(move || serve_socket(socket, config, thread_stop))
            .map_err(std::io::Error::other)?;
        Ok(Self {
            stop,
            thread: Some(thread),
            address,
        })
    }

    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.address
    }

    pub fn shutdown(mut self) -> std::io::Result<()> {
        self.stop.store(true, Ordering::Release);
        self.thread
            .take()
            .expect("DHCP thread present")
            .join()
            .map_err(|_| std::io::Error::other("DHCP thread panicked"))?
    }
}

fn serve_socket(
    socket: std::net::UdpSocket,
    config: DhcpConfig,
    stop: Arc<AtomicBool>,
) -> std::io::Result<()> {
    socket.set_broadcast(true)?;
    let server = config
        .server
        .parse::<Ipv4Addr>()
        .expect("validated DHCP server address");
    let subnet_mask = config
        .subnet_mask
        .parse::<Ipv4Addr>()
        .expect("validated DHCP subnet mask");
    let pool = Pool::new(
        config
            .pool_start
            .parse()
            .expect("validated DHCP pool start"),
        config.pool_end.parse().expect("validated DHCP pool end"),
    )
    .expect("validated DHCP pool");
    let router = config
        .router
        .as_deref()
        .map(|value| value.parse::<Ipv4Addr>().expect("validated DHCP router"));
    let dns = config
        .dns
        .as_deref()
        .map(|value| value.parse::<Ipv4Addr>().expect("validated DHCP DNS"));
    let dns_servers = config
        .dns_servers
        .iter()
        .map(|value| {
            value
                .parse::<Ipv4Addr>()
                .expect("validated DHCP DNS servers")
        })
        .collect::<Vec<_>>();
    let domain_name = config.domain_name.as_deref();
    let reply_config = ReplyConfig {
        server,
        subnet_mask,
        router,
        dns,
        dns_servers: &dns_servers,
        domain_name,
        lease_secs: config.lease_secs,
    };
    let mut leases = BTreeMap::new();
    let mut packet = [0u8; MAX_DHCP_PACKET];
    let mut output = [0u8; MAX_DHCP_PACKET];
    while !stop.load(Ordering::Acquire) {
        let (length, peer) = match socket.recv_from(&mut packet) {
            Ok(result) => result,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(error) => return Err(error),
        };
        let Ok(request) = Request::parse(&packet[..length]) else {
            continue;
        };
        let message_type = match request.message_type {
            MessageType::Discover => MessageType::Offer,
            MessageType::Request => MessageType::Ack,
            MessageType::Decline | MessageType::Release => continue,
            MessageType::Offer | MessageType::Ack | MessageType::Nak | MessageType::Inform => {
                continue;
            }
        };
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        leases.retain(|_, (_, expiry)| *expiry > now_secs);
        if leases.len() >= config.max_leases && !leases.contains_key(&request.client) {
            continue;
        }
        let requested = (request.message_type == MessageType::Request)
            .then_some(request.requested_ip)
            .flatten();
        let Some(address) = pool.allocate_requested(
            &mut leases,
            request.client,
            now_secs,
            config.lease_secs,
            requested,
        ) else {
            continue;
        };
        let Ok(response_length) =
            encode_reply(&request, message_type, address, reply_config, &mut output)
        else {
            continue;
        };
        let destination = if request.broadcast || peer.ip().is_unspecified() {
            SocketAddr::new(Ipv4Addr::BROADCAST.into(), 68)
        } else {
            peer
        };
        socket.send_to(&output[..response_length], destination)?;
    }
    Ok(())
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
        self.allocate_requested(leases, client, now_secs, lease_secs, None)
    }

    pub fn allocate_requested(
        &self,
        leases: &mut BTreeMap<[u8; 6], (Ipv4Addr, u64)>,
        client: [u8; 6],
        now_secs: u64,
        lease_secs: u32,
        requested: Option<Ipv4Addr>,
    ) -> Option<Ipv4Addr> {
        if lease_secs == 0 {
            return None;
        }
        leases.retain(|_, (_, expiry)| *expiry > now_secs);
        if let Some((address, expiry)) = leases.get_mut(&client) {
            if requested.is_some_and(|requested| requested != *address) {
                return None;
            }
            *expiry = now_secs.saturating_add(u64::from(lease_secs));
            return Some(*address);
        }
        if let Some(requested) = requested {
            if requested >= Ipv4Addr::from(self.start)
                && requested <= Ipv4Addr::from(self.end)
                && !leases.values().any(|(used, _)| *used == requested)
            {
                leases.insert(
                    client,
                    (requested, now_secs.saturating_add(u64::from(lease_secs))),
                );
                return Some(requested);
            }
            return None;
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
    use std::net::SocketAddr;

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
                dns_servers: &[Ipv4Addr::new(192, 0, 2, 2), Ipv4Addr::new(192, 0, 2, 3)],
                domain_name: Some("home.arpa"),
                lease_secs: 300,
            },
            &mut output,
        )
        .expect("offer");
        assert_eq!(&output[16..20], &[192, 0, 2, 20]);
        assert_eq!(&output[240..243], &[OPTION_MESSAGE_TYPE, 1, 2]);
        assert!(
            output[..length]
                .windows(14)
                .any(|window| window == [6, 12, 192, 0, 2, 1, 192, 0, 2, 2, 192, 0, 2, 3])
        );
        let domain_option = [
            OPTION_DOMAIN_NAME,
            "home.arpa".len() as u8,
            b'h',
            b'o',
            b'm',
            b'e',
            b'.',
            b'a',
            b'r',
            b'p',
            b'a',
        ];
        assert!(
            output[..length]
                .windows(domain_option.len())
                .any(|window| window == domain_option)
        );
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

        let mut packet = discover();
        packet[242] = 99;
        assert_eq!(
            Request::parse(&packet),
            Err(ParseError::UnsupportedMessageType)
        );
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
        assert_eq!(
            pool.allocate_requested(
                &mut leases,
                [18, 19, 20, 21, 22, 23],
                60,
                30,
                Some(Ipv4Addr::new(192, 0, 2, 11)),
            ),
            Some(Ipv4Addr::new(192, 0, 2, 11))
        );
        assert_eq!(
            pool.allocate_requested(
                &mut leases,
                [24, 25, 26, 27, 28, 29],
                60,
                30,
                Some(Ipv4Addr::new(192, 0, 2, 1)),
            ),
            None
        );
    }

    #[test]
    fn loopback_server_turns_discover_into_offer() {
        let config = DhcpConfig {
            listen: "127.0.0.1:0".into(),
            ..Default::default()
        };
        let server = Server::start(config).expect("server");
        let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("client");
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        client
            .send_to(&discover(), server.local_addr())
            .expect("discover");
        let mut response = [0u8; MAX_DHCP_PACKET];
        let (length, peer): (usize, SocketAddr) = client.recv_from(&mut response).expect("offer");
        assert_eq!(peer, server.local_addr());
        assert_eq!(response[0], 2);
        assert_eq!(&response[16..20], &[192, 0, 2, 100]);
        assert_eq!(&response[240..243], &[OPTION_MESSAGE_TYPE, 1, 2]);
        assert!(length < MAX_DHCP_PACKET);
        server.shutdown().expect("shutdown");
    }
}
