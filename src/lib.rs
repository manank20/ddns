#![forbid(unsafe_code)]

mod dns_class;
mod dns_message;
mod dns_message_header;
mod dns_name;
mod dns_op_code;
mod dns_question;
mod dns_record;
mod dns_response_code;
mod dns_type;
mod server;

pub use dns_class::DnsClass;
pub use dns_message::DnsMessage;
pub use dns_message_header::DnsMessageHeader;
pub use dns_name::DnsName;
pub use dns_op_code::DnsOpCode;
pub use dns_question::DnsQuestion;
pub use dns_record::DnsRecord;
pub use dns_response_code::DnsResponseCode;
pub use dns_type::DnsType;
pub use server::{process_datagram, serve_udp};

use fixed_buffer::FixedBuf;

fn read_exact<const N: usize, const M: usize>(buf: &mut FixedBuf<N>) -> Result<[u8; M], DnsError> {
    let mut result = [0_u8; M];
    buf.try_read_exact(&mut result).ok_or(DnsError::Truncated)?;
    Ok(result)
}

fn read_u8<const N: usize>(buf: &mut FixedBuf<N>) -> Result<u8, DnsError> {
    buf.try_read_byte().ok_or(DnsError::Truncated)
}

// fn write_u8<const N: usize>(out: &mut FixedBuf<N>, value: u8) -> Result<(), DnsError> {
//     out.write_bytes(&[value])
//         .map_err(|_| DnsError::ResponseBufferFull)?;
//     Ok(())
// }

fn read_u16_be<const N: usize>(buf: &mut FixedBuf<N>) -> Result<u16, DnsError> {
    let bytes: [u8; 2] = read_exact(buf)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32_be<const N: usize>(buf: &mut FixedBuf<N>) -> Result<u32, DnsError> {
    let bytes: [u8; 4] = read_exact(buf)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_bytes<const N: usize>(out: &mut FixedBuf<N>, bytes: &[u8]) -> Result<(), DnsError> {
    out.write_bytes(bytes)
        .map_err(|_| DnsError::ResponseBufferFull)?;
    Ok(())
}

fn write_u16_be<const N: usize>(out: &mut FixedBuf<N>, value: u16) -> Result<(), DnsError> {
    let bytes: [u8; 2] = value.to_be_bytes();
    out.write_bytes(&bytes)
        .map_err(|_| DnsError::ResponseBufferFull)?;
    Ok(())
}

fn write_u32_be<const N: usize>(out: &mut FixedBuf<N>, value: u32) -> Result<(), DnsError> {
    let bytes: [u8; 4] = value.to_be_bytes();
    out.write_bytes(&bytes)
        .map_err(|_| DnsError::ResponseBufferFull)?;
    Ok(())
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum DnsError {
    InvalidClass,
    InvalidLabel,
    InvalidOpCode,
    NameTooLong,
    NoQuestion,
    NotARequest,
    NotFound,
    ResponseBufferFull,
    QueryHasAdditionalRecords,
    QueryHasAnswer,
    QueryHasNameServer,
    TooManyAdditional,
    TooManyAnswers,
    TooManyLabels,
    TooManyNameServers,
    TooManyQuestions,
    Truncated,
    Internal(String),
    Unreachable(&'static str, u32),
}
