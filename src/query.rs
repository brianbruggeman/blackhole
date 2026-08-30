//! Borrowed DNS query views for the policy boundary.
//!
//! Wire validation and compression walking are delegated to Proxima's
//! `parse_message` codec. This module only narrows a validated message to the
//! single-question view required by Blackhole policy; it does not copy the
//! question name or allocate a dotted representation.

use proxima_protocols::dns::{Name, ParseError, parse_message};

pub const MAX_QUERY_BYTES: usize = 4096;

/// A validated DNS query borrowing all name data from the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryView<'packet> {
    pub id: u16,
    pub recursion_desired: bool,
    pub name: Name<'packet>,
    pub qtype: u16,
    pub qclass: u16,
}

/// Failure while narrowing a DNS message to Blackhole's one-question view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryParseError {
    Wire(ParseError),
    NotSingleQuestion,
    Oversized,
}

impl core::fmt::Display for QueryParseError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "invalid DNS message: {error}"),
            Self::NotSingleQuestion => formatter.write_str("DNS message is not one question"),
            Self::Oversized => write!(formatter, "DNS message exceeds {MAX_QUERY_BYTES} bytes"),
        }
    }
}

impl core::error::Error for QueryParseError {}

impl From<ParseError> for QueryParseError {
    fn from(error: ParseError) -> Self {
        Self::Wire(error)
    }
}

impl<'packet> QueryView<'packet> {
    /// Parse one complete DNS message without retaining or copying its bytes.
    pub fn parse(packet: &'packet [u8]) -> Result<Self, QueryParseError> {
        if packet.len() > MAX_QUERY_BYTES {
            return Err(QueryParseError::Oversized);
        }
        let message = parse_message(packet)?;
        if message.header.qdcount != 1 {
            return Err(QueryParseError::NotSingleQuestion);
        }
        let question = message
            .questions()
            .next()
            .ok_or(QueryParseError::NotSingleQuestion)??;
        Ok(Self {
            id: message.header.id,
            recursion_desired: message.header.flags.rd(),
            name: question.name,
            qtype: question.qtype,
            qclass: question.qclass,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &[u8], qtype: u16) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(name);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn parses_without_materializing_the_name() {
        let packet = query(b"\x07example\x03com\0", 1);
        let view = QueryView::parse(&packet).expect("valid query");
        assert_eq!(view.id, 0x1234);
        assert!(view.recursion_desired);
        assert_eq!(view.qtype, 1);
        assert_eq!(view.qclass, 1);
        let labels: Vec<&[u8]> = view.name.labels().collect();
        assert_eq!(labels, vec![b"example".as_slice(), b"com".as_slice()]);
    }

    #[test]
    fn rejects_truncated_and_multi_question_messages() {
        assert_eq!(
            QueryView::parse(&[0; 11]),
            Err(QueryParseError::Wire(ParseError::Short))
        );
        let mut packet = query(b"\0", 1);
        packet.extend_from_slice(b"\0\0\x1c\0\x01");
        packet[4] = 0;
        packet[5] = 2;
        assert_eq!(
            QueryView::parse(&packet),
            Err(QueryParseError::NotSingleQuestion)
        );
    }

    #[test]
    fn rejects_compression_pointer_loops() {
        let packet = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1];
        assert!(matches!(
            QueryView::parse(&packet),
            Err(QueryParseError::Wire(ParseError::Malformed(_)))
        ));
    }

    #[test]
    fn rejects_oversized_packets_before_codec_work() {
        assert_eq!(
            QueryView::parse(&vec![0; MAX_QUERY_BYTES + 1]),
            Err(QueryParseError::Oversized)
        );
    }
}
