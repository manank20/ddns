use crate::{read_u16_be, write_u16_be, DnsError};
use core::fmt::{Display, Formatter};
use fixed_buffer::FixedBuf;

/// > TYPE fields are used in resource records.  Note that these types are a subset of QTYPEs.
///
/// <https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2>
///
/// > A record type is defined to store a host's IPv6 address.  A host that has more than one
/// > IPv6 address must have more than one such record.
///
/// <https://datatracker.ietf.org/doc/html/rfc3596#section-2>
///
/// > QTYPE fields appear in the question part of a query.  QTYPES are a superset of TYPEs, hence
/// > all TYPEs are valid QTYPEs.
///
/// <https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3>
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DnsType {
    /// IPv4 address
    A,
    /// IPv6 address
    AAAA,
    /// The canonical name for an alias
    CNAME,
    /// Mail exchange
    MX,
    /// Authoritative name server
    NS,
    /// Domain name pointer
    PTR,
    /// Marks the start of a zone of authority
    SOA,
    /// Text string
    TXT,
    ANY,
    Unknown(u16),
}
impl DnsType {
    #[must_use]
    pub fn new(value: u16) -> Self {
        match value {
            1 => DnsType::A,
            28 => DnsType::AAAA,
            5 => DnsType::CNAME,
            15 => DnsType::MX,
            2 => DnsType::NS,
            12 => DnsType::PTR,
            6 => DnsType::SOA,
            16 => DnsType::TXT,
            255 => DnsType::ANY,
            other => DnsType::Unknown(other),
        }
    }

    #[must_use]
    pub fn num(&self) -> u16 {
        match self {
            DnsType::A => 1,
            DnsType::AAAA => 28,
            DnsType::CNAME => 5,
            DnsType::MX => 15,
            DnsType::NS => 2,
            DnsType::PTR => 12,
            DnsType::SOA => 6,
            DnsType::TXT => 16,
            DnsType::ANY => 255,
            DnsType::Unknown(other) => *other,
        }
    }

    /// # Errors
    /// Returns an error when `buf` does not contain a valid two-byte type code.
    pub fn read<const N: usize>(buf: &mut FixedBuf<N>) -> Result<Self, DnsError> {
        Ok(Self::new(read_u16_be(buf)?))
    }

    /// # Errors
    /// Returns an error when `buf` fills up.
    pub fn write<const N: usize>(&self, out: &mut FixedBuf<N>) -> Result<(), DnsError> {
        write_u16_be(out, self.num())
    }
}
impl Display for DnsType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            DnsType::A => write!(f, "A"),
            DnsType::AAAA => write!(f, "AAAA"),
            DnsType::CNAME => write!(f, "CNAME"),
            DnsType::MX => write!(f, "MX"),
            DnsType::NS => write!(f, "NS"),
            DnsType::PTR => write!(f, "PTR"),
            DnsType::SOA => write!(f, "SOA"),
            DnsType::TXT => write!(f, "TXT"),
            DnsType::ANY => write!(f, "ANY"),
            DnsType::Unknown(n) => write!(f, "Unknown({n})"),
        }
    }
}
