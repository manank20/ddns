use crate::{read_u16_be, read_u8, write_u16_be, DnsError, DnsOpCode, DnsResponseCode};
use fixed_buffer::FixedBuf;

/// > 4.1.1. Header section format
/// >
/// > The header contains the following fields:
/// >
/// > ```text
/// >                                 1  1  1  1  1  1
/// >   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > |                      ID                       |
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > |                    QDCOUNT                    |
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > |                    ANCOUNT                    |
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > |                    NSCOUNT                    |
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > |                    ARCOUNT                    |
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > ```
///
/// <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DnsMessageHeader {
    /// > `ID` A 16 bit identifier assigned by the program that generates any kind of query.  This
    /// > identifier is copied the corresponding reply and can be used by the requester to match up
    /// > replies to outstanding queries.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>
    pub id: u16,
    /// > `QR` A one bit field that specifies whether this message is a query (`0`),
    /// > or a response (`1`).
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>
    pub is_response: bool,
    /// > `OPCODE`  A four bit field that specifies kind of query in this message.
    /// >         This value is set by the originator of a query and copied into
    /// >         the response.  The values are:
    /// > - `0` a standard query (`QUERY`)
    /// > - `1` an inverse query (`IQUERY`)
    /// > - `2` a server status request (`STATUS`)
    /// > - `3-15` reserved for future use
    ///
    /// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    pub op_code: DnsOpCode,
    /// > `AA` Authoritative Answer - this bit is valid in responses, and specifies that the
    /// > responding name server is an authority for the domain name in question section.
    /// >
    /// > Note that the contents of the answer section may have multiple owner names because of
    /// > aliases.  The AA bit corresponds to the name which matches the query name, or the first
    /// > owner name in the answer section.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>
    pub authoritative_answer: bool,
    /// > `TC` TrunCation - specifies that this message was truncated due to length greater than
    /// > that permitted on the transmission channel.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>
    pub truncated: bool,
    /// > `RD` Recursion Desired - this bit may be set in a query and is copied into the response.
    /// > If RD is set, it directs the name server to pursue the query recursively.  Recursive query
    /// > support is optional.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>
    pub recursion_desired: bool,
    /// > `RA` Recursion Available - this be is set or cleared in a response, and denotes whether
    /// > recursive query support is available in the name server.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>
    pub recursion_available: bool,
    pub response_code: DnsResponseCode,
    pub question_count: u16,
    pub answer_count: u16,
    pub name_server_count: u16,
    pub additional_count: u16,
}
impl DnsMessageHeader {
    /// # Errors
    /// Returns an error when `buf` does not contain a valid message header.
    pub fn read<const N: usize>(buf: &mut FixedBuf<N>) -> Result<Self, DnsError> {
        let id = read_u16_be(buf)?;
        let b = read_u8(buf)?;
        let is_response = (b >> 7) == 1;
        let op_code = DnsOpCode::new((b >> 3) & 0xF);
        let authoritative_answer = ((b >> 2) & 1) == 1;
        let truncated = ((b >> 1) & 1) == 1;
        let recursion_desired = (b & 1) == 1;
        let b = read_u8(buf)?;
        let recursion_available = (b >> 7) == 1;
        let response_code = DnsResponseCode::new(b & 0xF);
        let question_count = read_u16_be(buf)?;
        let answer_count = read_u16_be(buf)?;
        let name_server_count = read_u16_be(buf)?;
        let additional_count = read_u16_be(buf)?;
        Ok(Self {
            id,
            is_response,
            op_code,
            authoritative_answer,
            truncated,
            recursion_desired,
            recursion_available,
            response_code,
            question_count,
            answer_count,
            name_server_count,
            additional_count,
        })
    }

    /// # Errors
    /// Returns an error when `buf` fills up.
    pub fn write<const N: usize>(&self, out: &mut FixedBuf<N>) -> Result<(), DnsError> {
        let bytes: [u8; 2] = self.id.to_be_bytes();
        out.write_bytes(&bytes)
            .map_err(|_| DnsError::ResponseBufferFull)?;
        let b = (u8::from(self.is_response) << 7)
            | (self.op_code.num() << 3)
            | (u8::from(self.authoritative_answer) << 2)
            | (u8::from(self.truncated) << 1)
            | u8::from(self.recursion_desired);
        out.write_bytes(&[b])
            .map_err(|_| DnsError::ResponseBufferFull)?;
        let b = (u8::from(self.recursion_available) << 7) | self.response_code.num();
        out.write_bytes(&[b])
            .map_err(|_| DnsError::ResponseBufferFull)?;
        for count in [
            self.question_count,
            self.answer_count,
            self.name_server_count,
            self.additional_count,
        ] {
            write_u16_be(out, count)?;
        }
        Ok(())
    }
}
