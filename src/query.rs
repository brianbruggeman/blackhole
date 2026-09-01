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
    Response,
    InvalidFlags,
    UnsupportedName,
    NotSingleQuestion,
    Oversized,
}

impl QueryParseError {
    /// Stable low-cardinality cause labels for the runtime telemetry boundary.
    /// Wire details stay in the error text; metrics must not use attacker-
    /// controlled parser messages as label values.
    #[must_use]
    pub(crate) const fn telemetry_cause(&self) -> &'static str {
        match self {
            Self::Wire(ParseError::Short) => "query_wire_short",
            Self::Wire(ParseError::Malformed(_)) => "query_wire_malformed",
            Self::Response => "query_response",
            Self::InvalidFlags => "query_invalid_flags",
            Self::UnsupportedName => "query_unsupported_name",
            Self::NotSingleQuestion => "query_question_count",
            Self::Oversized => "query_oversized",
        }
    }
}

impl core::fmt::Display for QueryParseError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "invalid DNS message: {error}"),
            Self::Response => {
                formatter.write_str("DNS response received where a query was expected")
            }
            Self::InvalidFlags => {
                formatter.write_str("DNS query contains response or reserved flag bits")
            }
            Self::UnsupportedName => {
                formatter.write_str("DNS name contains non-ASCII labels; IDNA is unsupported")
            }
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
        if message.header.flags.is_response() {
            return Err(QueryParseError::Response);
        }
        if !valid_query_flags(packet) {
            return Err(QueryParseError::InvalidFlags);
        }
        if message.header.qdcount != 1 {
            return Err(QueryParseError::NotSingleQuestion);
        }
        let question = message
            .questions()
            .next()
            .ok_or(QueryParseError::NotSingleQuestion)??;
        if question.name.labels().any(|label| !label.is_ascii()) {
            return Err(QueryParseError::UnsupportedName);
        }
        Ok(Self {
            id: message.header.id,
            recursion_desired: message.header.flags.rd(),
            name: question.name,
            qtype: question.qtype,
            qclass: question.qclass,
        })
    }

    /// Materialize the business-layer query only after wire validation and
    /// policy matching have had the opportunity to use this borrowed view.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn to_owned(self) -> proxima_dns::DnsQuery {
        #[cfg(feature = "perf-instrument")]
        crate::perf::record_copy(
            crate::perf::Boundary::BorrowedToOwned,
            self.name
                .labels()
                .map(|label| label.len().saturating_add(1))
                .sum(),
        );
        proxima_dns::DnsQuery {
            id: self.id,
            recursion_desired: self.recursion_desired,
            name: self.name.to_dotted(),
            qtype: self.qtype,
            qclass: self.qclass,
        }
    }
}

/// Return whether the fixed DNS header flags are valid for a query.
///
/// QR, AA, and TC are response-state bits; RA is supplied by a resolver in a
/// response. The opcode, Z, and RCODE fields must be zero. AD/CD remain
/// available for DNSSEC-aware clients.
pub(crate) fn valid_query_flags(packet: &[u8]) -> bool {
    packet.len() >= 4 && packet[2] & 0x7e == 0 && packet[3] & 0xcf == 0
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
    fn rejects_response_messages_at_the_query_boundary() {
        let mut packet = query(b"\x07example\x03com\0", 1);
        packet[2] |= 0x80;
        assert_eq!(QueryView::parse(&packet), Err(QueryParseError::Response));
    }

    #[test]
    fn rejects_response_and_reserved_query_flags() {
        for mask in [
            [0x04, 0x00],
            [0x02, 0x00],
            [0x00, 0x80],
            [0x00, 0x40],
            [0x00, 0x01],
        ] {
            let mut packet = query(b"\x07example\x03com\0", 1);
            packet[2] |= mask[0];
            packet[3] |= mask[1];
            assert_eq!(
                QueryView::parse(&packet),
                Err(QueryParseError::InvalidFlags),
                "flags {:02x}{:02x} must not enter policy",
                packet[2],
                packet[3]
            );
        }
    }

    #[test]
    fn rejects_non_ascii_names_instead_of_lossy_canonicalization() {
        let packet = query(b"\x01\xff\0", 1);
        assert_eq!(
            QueryView::parse(&packet),
            Err(QueryParseError::UnsupportedName)
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

    #[test]
    fn parser_failures_have_stable_telemetry_causes() {
        assert_eq!(
            QueryParseError::Wire(ParseError::Short).telemetry_cause(),
            "query_wire_short"
        );
        assert_eq!(
            QueryParseError::Wire(ParseError::Malformed("pointer")).telemetry_cause(),
            "query_wire_malformed"
        );
        assert_eq!(
            QueryParseError::Response.telemetry_cause(),
            "query_response"
        );
        assert_eq!(
            QueryParseError::InvalidFlags.telemetry_cause(),
            "query_invalid_flags"
        );
        assert_eq!(
            QueryParseError::UnsupportedName.telemetry_cause(),
            "query_unsupported_name"
        );
        assert_eq!(
            QueryParseError::NotSingleQuestion.telemetry_cause(),
            "query_question_count"
        );
        assert_eq!(
            QueryParseError::Oversized.telemetry_cause(),
            "query_oversized"
        );
    }
}
