use crate::{
    read_exact, read_u16_be, read_u32_be, write_bytes, write_u16_be, write_u32_be, DnsClass,
    DnsError, DnsName, DnsType,
};
use core::fmt::{Debug, Formatter};
use fixed_buffer::FixedBuf;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// > 4.1.3. Resource record format
/// >
/// > The answer, authority, and additional sections all share the same format: a variable number
/// > of resource records, where the number of records is specified in the corresponding count
/// > field in the header.  Each resource record has the following format:
/// >
/// > ```text
/// >                                 1  1  1  1  1  1
/// >   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > |                                               |
/// > /                                               /
/// > /                      NAME                     /
/// > |                                               |
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > |                      TYPE                     |
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > |                     CLASS                     |
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > |                      TTL                      |
/// > |                                               |
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > |                   RDLENGTH                    |
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/// > /                     RDATA                     /
/// > /                                               /
/// > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// > ```
/// > where:
/// > - NAME: a domain name to which this resource record pertains.
/// > - TYPE: two octets containing one of the RR type codes.  This field specifies the meaning of
/// >   the data in the RDATA field.
/// > - CLASS: two octets which specify the class of the data in the RDATA field.
/// > - TTL:  a 32 bit unsigned integer that specifies the time interval (in seconds) that the
/// >   resource record may be cached before it should be discarded.  Zero values are interpreted
/// >   to mean that the RR can only be used for the transaction in progress, and should not be
/// >   cached.
/// > - RDLENGTH: an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
/// > - RDATA:  a variable length string of octets that describes the resource.  The format of this
/// >   information varies according to the TYPE and CLASS of the resource record.  For example,
/// >   the if the TYPE is A and the CLASS is IN, the RDATA field is a 4 octet ARPA Internet
/// >   address.
///
/// <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3>
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DnsRecord {
    A(DnsName, std::net::Ipv4Addr),
    AAAA(DnsName, std::net::Ipv6Addr),
    CNAME(DnsName, DnsName),
    Unknown(DnsName, DnsType),
}
impl DnsRecord {
    /// # Errors
    /// Returns an error when `buf` does not contain a valid resource record.
    pub fn read_rdata<const N: usize>(buf: &mut FixedBuf<N>) -> Result<FixedBuf<65535>, DnsError> {
        let len = read_u16_be(buf)?;
        if buf.len() < (len as usize) {
            return Err(DnsError::Truncated);
        }
        let borrowed_rdata = buf.read_bytes(len as usize);
        let mut rdata: FixedBuf<65535> = FixedBuf::new();
        rdata
            .write_bytes(borrowed_rdata)
            .map_err(|_| DnsError::Unreachable(file!(), line!()))?;
        Ok(rdata)
    }

    /// # Errors
    /// Returns an error when `buf` is full or `bytes` is longer than 65,535 bytes.
    pub fn write_rdata<const N: usize>(
        bytes: &[u8],
        out: &mut FixedBuf<N>,
    ) -> Result<(), DnsError> {
        let len =
            u16::try_from(bytes.len()).map_err(|_| DnsError::Unreachable(file!(), line!()))?;
        write_u16_be(out, len)?;
        write_bytes(out, bytes)?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when `name` is not a valid DNS name
    /// or `ipv4_addr` is not a valid IPv4 address.
    pub fn new_a(name: &str, ipv4_addr: &str) -> Result<Self, String> {
        let dns_name = DnsName::new(name)?;
        let ip_addr: IpAddr = ipv4_addr
            .parse()
            .map_err(|e| format!("failed parsing {ipv4_addr:?} as an IP address: {e}"))?;
        match ip_addr {
            IpAddr::V4(addr) => Ok(Self::A(dns_name, addr)),
            IpAddr::V6(addr) => Err(format!(
                "cannot create an A record with ipv6 address {addr:?}"
            )),
        }
    }

    /// # Errors
    /// Returns an error when `name` is not a valid DNS name
    /// or `ipv6_addr` is not a valid IPv6 address.
    pub fn new_aaaa(name: &str, ipv6_addr: &str) -> Result<Self, String> {
        let dns_name = DnsName::new(name)?;
        let ip_addr: IpAddr = ipv6_addr
            .parse()
            .map_err(|e| format!("failed parsing {ipv6_addr:?} as an IP address: {e}"))?;
        match ip_addr {
            IpAddr::V4(addr) => Err(format!(
                "cannot create an AAAA record with ipv4 address {addr:?}"
            )),
            IpAddr::V6(addr) => Ok(Self::AAAA(dns_name, addr)),
        }
    }

    /// # Errors
    /// Returns an error when `name` or `target` are not both valid DNS names.
    pub fn new_cname(name: &str, target: &str) -> Result<Self, String> {
        let dns_name = DnsName::new(name)?;
        let dns_name_target = DnsName::new(target)?;
        Ok(Self::CNAME(dns_name, dns_name_target))
    }

    #[must_use]
    pub fn name(&self) -> &DnsName {
        match self {
            DnsRecord::A(dns_name, _)
            | DnsRecord::AAAA(dns_name, _)
            | DnsRecord::CNAME(dns_name, _)
            | DnsRecord::Unknown(dns_name, _) => dns_name,
        }
    }

    #[must_use]
    pub fn typ(&self) -> DnsType {
        match self {
            DnsRecord::A(_, _) => DnsType::A,
            DnsRecord::AAAA(_, _) => DnsType::AAAA,
            DnsRecord::CNAME(_, _) => DnsType::CNAME,
            DnsRecord::Unknown(_, typ) => DnsType::Unknown(typ.num()),
        }
    }

    /// # Errors
    /// Returns an error when `buf` does not contain a valid resource record.
    pub fn read<const N: usize>(buf: &mut FixedBuf<N>) -> Result<Self, DnsError> {
        let name = DnsName::read(buf)?;
        let typ = DnsType::read(buf)?;
        let class = DnsClass::read(buf)?;
        if class != DnsClass::Internet && class != DnsClass::Any {
            return Err(DnsError::InvalidClass);
        }
        let _ttl_seconds = read_u32_be(buf)?;
        let mut rdata = Self::read_rdata(buf)?;
        match typ {
            DnsType::A => {
                let octets: [u8; 4] = read_exact(&mut rdata)?;
                Ok(DnsRecord::A(name, Ipv4Addr::from(octets)))
            }
            DnsType::AAAA => {
                let octets: [u8; 16] = read_exact(&mut rdata)?;
                Ok(DnsRecord::AAAA(name, Ipv6Addr::from(octets)))
            }
            DnsType::CNAME => Ok(DnsRecord::CNAME(name, DnsName::read(&mut rdata)?)),
            DnsType::MX
            | DnsType::NS
            | DnsType::PTR
            | DnsType::SOA
            | DnsType::TXT
            | DnsType::ANY
            | DnsType::Unknown(_) => Ok(DnsRecord::Unknown(name, typ)),
        }
    }

    /// # Errors
    /// Returns an error when `buf` is full.
    pub fn write<const N: usize>(&self, out: &mut FixedBuf<N>) -> Result<(), DnsError> {
        self.name().write(out)?;
        self.typ().write(out)?;
        DnsClass::Internet.write(out)?;
        write_u32_be(out, 300)?; // TTL in seconds.
        match self {
            DnsRecord::A(_, ipv4_addr) => Self::write_rdata(&ipv4_addr.octets(), out),
            DnsRecord::AAAA(_, ipv6_addr) => Self::write_rdata(&ipv6_addr.octets(), out),
            DnsRecord::CNAME(_, target_name) => {
                Self::write_rdata(target_name.as_bytes()?.readable(), out)
            }
            DnsRecord::Unknown(_, _) => {
                Err(DnsError::Internal(format!("cannot write record {self:?}")))
            }
        }
    }
}
impl Debug for DnsRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            DnsRecord::A(name, addr) => write!(f, "DnsRecord::A({name},{addr})"),
            DnsRecord::AAAA(name, addr) => write!(f, "DnsRecord::AAAA({name},{addr})"),
            DnsRecord::CNAME(name, target) => write!(f, "DnsRecord::CNAME({name},{target})"),
            DnsRecord::Unknown(name, typ) => write!(f, "DnsRecord::Unknown({name},{typ})"),
        }
    }
}

#[cfg(test)]
#[test]
fn test_dns_record() {
    use std::net::{Ipv4Addr, Ipv6Addr};
    // Constructors
    assert_eq!(
        DnsRecord::A(DnsName::new("a.b").unwrap(), Ipv4Addr::new(1, 2, 3, 4)),
        DnsRecord::new_a("a.b", "1.2.3.4").unwrap()
    );
    assert_eq!(
        DnsRecord::AAAA(
            DnsName::new("a.b").unwrap(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)
        ),
        DnsRecord::new_aaaa("a.b", "2001:db8::").unwrap()
    );
    assert_eq!(
        DnsRecord::CNAME(DnsName::new("a.b").unwrap(), DnsName::new("c.d").unwrap()),
        DnsRecord::new_cname("a.b", "c.d").unwrap()
    );
    // Debug
    assert_eq!(
        "DnsRecord::A(a.b,1.2.3.4)",
        format!(
            "{:?}",
            DnsRecord::A(DnsName::new("a.b").unwrap(), Ipv4Addr::new(1, 2, 3, 4))
        )
    );
    assert_eq!(
        "DnsRecord::AAAA(a.b,2001:db8::)",
        format!(
            "{:?}",
            DnsRecord::AAAA(
                DnsName::new("a.b").unwrap(),
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)
            )
        )
    );
    assert_eq!(
        "DnsRecord::CNAME(a.b,c.d)",
        format!(
            "{:?}",
            DnsRecord::CNAME(DnsName::new("a.b").unwrap(), DnsName::new("c.d").unwrap())
        )
    );
}
