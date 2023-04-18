use crate::{DnsError, DnsMessage, DnsName, DnsOpCode, DnsRecord, DnsType};
use fixed_buffer::FixedBuf;
use multimap::MultiMap;
use prob_rate_limiter::ProbRateLimiter;
use std::convert::TryFrom;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

/// # Errors
/// Returns `Err` when the request is malformed or the server is not configured to answer the
/// request.
pub fn process_request(
    name_to_records: &MultiMap<&DnsName, &DnsRecord>,
    request: &DnsMessage,
) -> Result<DnsMessage, DnsError> {
    if request.header.is_response {
        return Err(DnsError::NotARequest);
    }
    if request.header.op_code != DnsOpCode::Query {
        return Err(DnsError::InvalidOpCode);
    }
    // NOTE: We only answer the first question.
    let question = request.questions.first().ok_or(DnsError::NoQuestion)?;
    // u16::try_from(self.questions.len()).map_err(|_| ProcessError::TooManyQuestions)?,
    let records = name_to_records
        .get_vec(&question.name)
        .ok_or(DnsError::NotFound)?;
    if question.typ == DnsType::ANY {
        request.answer_response(records.iter().copied())
    } else {
        request.answer_response(
            records
                .iter()
                .filter(|record| record.typ() == question.typ)
                .copied(),
        )
    }
}

/// # Errors
/// Returns `Err` when the request is malformed or the server is not configured to answer the
/// request.
#[allow(clippy::implicit_hasher)]
pub fn process_datagram(
    name_to_records: &MultiMap<&DnsName, &DnsRecord>,
    bytes: &mut FixedBuf<512>,
) -> Result<FixedBuf<512>, DnsError> {
    //println!("process_datagram: bytes = {:?}", bytes.readable());
    let request = DnsMessage::read(bytes)?;
    //println!("process_datagram: request = {:?}", request);
    let response = process_request(name_to_records, &request)?;
    //println!("process_datagram: response = {:?}", response);
    let mut out: FixedBuf<512> = FixedBuf::new();
    response.write(&mut out)?;
    //println!("process_datagram: out = {:?}", out.readable());
    Ok(out)
}

/// # Errors
/// Returns `Err` when socket operations fail.
#[allow(clippy::missing_panics_doc)]
pub fn serve_udp(
    permit: &permit::Permit,
    sock: &std::net::UdpSocket,
    mut response_bytes_rate_limiter: ProbRateLimiter,
    records: &[DnsRecord],
) -> Result<(), String> {
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| format!("error setting socket read timeout: {e}"))?;
    let local_addr = sock
        .local_addr()
        .map_err(|e| format!("error getting socket local address: {e}"))?;
    let name_to_records: MultiMap<&DnsName, &DnsRecord> =
        records.iter().map(|x| (x.name(), x)).collect();
    while !permit.is_revoked() {
        // > Messages carried by UDP are restricted to 512 bytes (not counting the IP
        // > or UDP headers).  Longer messages are truncated and the TC bit is set in
        // > the header.
        // https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1
        let mut buf: FixedBuf<512> = FixedBuf::new();
        let addr = match sock.recv_from(buf.writable()) {
            // Can this happen?  The docs are not clear.
            Ok((len, _)) if len > buf.writable().len() => continue,
            Ok((len, addr)) => {
                buf.wrote(len);
                addr
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                continue
            }
            Err(e) => return Err(format!("error reading socket {local_addr:?}: {e}")),
        };
        let now = Instant::now();
        if !response_bytes_rate_limiter.attempt(now) {
            println!("dropping request");
            continue;
        }
        let out = match process_datagram(&name_to_records, &mut buf) {
            Ok(buf) => buf,
            Err(e) => {
                println!("dropping bad request: {e:?}");
                continue;
            }
        };
        if out.is_empty() {
            unreachable!();
        }
        response_bytes_rate_limiter.record(u32::try_from(out.len()).unwrap());
        let sent_len = sock
            .send_to(out.readable(), addr)
            .map_err(|e| format!("error sending response to {addr:?}: {e}"))?;
        if sent_len != out.len() {
            return Err(format!(
                "sent only {sent_len} bytes of {} byte response to {addr:?}",
                out.len()
            ));
        }
    }
    Ok(())
}
