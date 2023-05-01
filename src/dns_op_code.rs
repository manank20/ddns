/// > `OPCODE`  A four bit field that specifies kind of query in this message.
/// >         This value is set by the originator of a query and copied into
/// >         the response.  The values are:
/// > - `0` a standard query (`QUERY`)
/// > - `1` an inverse query (`IQUERY`)
/// > - `2` a server status request (`STATUS`)
/// > - `3-15` reserved for future use
///
/// <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsOpCode {
    Query,
    InverseQuery,
    Status,
    Reserved(u8),
}
impl DnsOpCode {
    #[must_use]
    pub fn new(value: u8) -> Self {
        match value {
            0 => DnsOpCode::Query,
            1 => DnsOpCode::InverseQuery,
            2 => DnsOpCode::Status,
            other => DnsOpCode::Reserved(other),
        }
    }

    #[must_use]
    pub fn num(&self) -> u8 {
        match self {
            DnsOpCode::Query => 0,
            DnsOpCode::InverseQuery => 1,
            DnsOpCode::Status => 2,
            DnsOpCode::Reserved(other) => *other,
        }
    }
}
