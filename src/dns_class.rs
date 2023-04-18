use crate::{read_u16_be, write_u16_be, DnsError};
use fixed_buffer::FixedBuf;

/// > `CLASS` fields appear in resource records.  The following `CLASS` mnemonics and values are
/// > defined:
/// >
/// > - `IN` 1 the Internet
/// > - `CS` 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
/// > - `CH` 3 the CHAOS class
/// > - `HS` 4 Hesiod [Dyer 87]
/// >
/// >
/// > `QCLASS` fields appear in the question section of a query.  `QCLASS` values are a superset of
/// > `CLASS` values; every `CLASS` is a valid `QCLASS`.  In addition to `CLASS` values, the following
/// > `QCLASSes` are defined:
/// >
/// > - `*` 255 any class
///
/// <https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4>
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsClass {
    Internet,
    Any,
    Unknown(u16),
}
impl DnsClass {
    #[must_use]
    pub fn new(value: u16) -> Self {
        match value {
            1 => DnsClass::Internet,
            255 => DnsClass::Any,
            other => DnsClass::Unknown(other),
        }
    }

    #[must_use]
    pub fn num(&self) -> u16 {
        match self {
            DnsClass::Internet => 1,
            DnsClass::Any => 255,
            DnsClass::Unknown(other) => *other,
        }
    }

    /// # Errors
    /// Returns an error when `buf` does not contain two bytes.
    pub fn read<const N: usize>(buf: &mut FixedBuf<N>) -> Result<Self, DnsError> {
        Ok(Self::new(read_u16_be(buf)?))
    }

    /// # Errors
    /// Returns an error when `buf` is full.
    pub fn write<const N: usize>(&self, out: &mut FixedBuf<N>) -> Result<(), DnsError> {
        write_u16_be(out, self.num())
    }
}
