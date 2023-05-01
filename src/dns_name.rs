use crate::{read_u8, DnsError};
use core::convert::TryFrom;
use core::fmt::{Display, Formatter};
use fixed_buffer::FixedBuf;

/// > 2.3.1. Preferred name syntax
/// >
/// > The DNS specifications attempt to be as general as possible in the rules for constructing
/// > domain names.  The idea is that the name of any existing object can be expressed as a domain
/// > name with minimal changes.
/// >
/// > However, when assigning a domain name for an object, the prudent user will select a name
/// > which satisfies both the rules of the domain system and any existing rules for the object,
/// > whether these rules are published or implied by existing programs.
/// >
/// > For example, when naming a mail domain, the user should satisfy both the rules of this memo
/// > and those in [RFC-822](https://datatracker.ietf.org/doc/html/rfc822).  When creating a new
/// > host name, the old rules for HOSTS.TXT should be followed.  This avoids problems when old
/// > software is converted to use domain names.
/// >
/// > The following syntax will result in fewer problems with many
/// >
/// > applications that use domain names (e.g., mail, TELNET).
/// >
/// > `<domain> ::= <subdomain> | " "`
/// >
/// > `<subdomain> ::= <label> | <subdomain> "." <label>`
/// >
/// > `<label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]`
/// >
/// > `<ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>`
/// >
/// > `<let-dig-hyp> ::= <let-dig> | "-"`
/// >
/// > `<let-dig> ::= <letter> | <digit>`
/// >
/// > `<letter> ::=` any one of the 52 alphabetic characters `A` through `Z` in upper case
/// > and `a` through `z` in lower case
/// >
/// > `<digit> ::=` any one of the ten digits `0` through `9`
/// >
/// > Note that while upper and lower case letters are allowed in domain names, no significance is
/// > attached to the case.  That is, two names with the same spelling but different case are to be
/// > treated as if identical.
/// >
/// > The labels must follow the rules for ARPANET host names.  They must start with a letter, end
/// > with a letter or digit, and have as interior characters only letters, digits, and hyphen.
/// > There are also some restrictions on the length.  Labels must be 63 characters or less.
/// >
/// > For example, the following strings identify hosts in the Internet:
/// >
/// > `A.ISI.EDU XX.LCS.MIT.EDU SRI-NIC.ARPA`
///
/// <https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.1>
///
/// > Various objects and parameters in the DNS have size limits.  They are listed below.  Some
/// > could be easily changed, others are more fundamental.
/// >
/// > - labels: 63 octets or less
/// > - names: 255 octets or less
/// > - TTL: positive values of a signed 32 bit number.
/// > - UDP messages: 512 octets or less
///
/// <https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4>
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DnsName(String);
impl DnsName {
    fn is_letter(b: u8) -> bool {
        b.is_ascii_lowercase() || b.is_ascii_uppercase()
    }

    fn is_letter_digit(b: u8) -> bool {
        Self::is_letter(b) || b.is_ascii_digit()
    }

    fn is_letter_digit_hyphen(b: u8) -> bool {
        Self::is_letter_digit(b) || b == b'-'
    }

    fn is_valid_label(label: &str) -> bool {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        Self::is_letter(bytes[0])
            && bytes.iter().copied().all(Self::is_letter_digit_hyphen)
            && Self::is_letter_digit(*bytes.last().unwrap())
    }

    fn is_valid_name(value: &str) -> bool {
        if !value.is_ascii() {
            return false;
        }
        value.split('.').all(Self::is_valid_label)
    }

    /// # Errors
    /// Returns an error when `value` is not a valid DNS name.
    pub fn new(value: &str) -> Result<Self, String> {
        let trimmed = value.strip_suffix('.').unwrap_or(value);
        if trimmed.len() > 255 || !Self::is_valid_name(trimmed) {
            return Err(format!("not a valid DNS name: {value:?}"));
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    /// # Errors
    /// Returns an error when `buf` does not contain a valid name.
    pub fn read<const N: usize>(buf: &mut FixedBuf<N>) -> Result<DnsName, DnsError> {
        let mut value = String::new();
        for _ in 0..63 {
            let len = read_u8(buf)? as usize;
            if len == 0 {
                if value.len() > 255 {
                    return Err(DnsError::NameTooLong);
                }
                return Ok(Self(value));
            }
            if buf.readable().len() < len {
                return Err(DnsError::Truncated);
            }
            let label_bytes = buf.read_bytes(len);
            let label = std::str::from_utf8(label_bytes).map_err(|_| DnsError::InvalidLabel)?;
            if !Self::is_valid_label(label) {
                return Err(DnsError::InvalidLabel);
            }
            if !value.is_empty() {
                value.push('.');
            }
            value.push_str(label);
        }
        Err(DnsError::TooManyLabels)
    }

    /// # Errors
    /// Returns an error when `buf` fills up.
    pub fn write<const N: usize>(&self, out: &mut FixedBuf<N>) -> Result<(), DnsError> {
        for label in self.0.split('.') {
            if label.len() > 63 {
                return Err(DnsError::Unreachable(file!(), line!()));
            }
            let len =
                u8::try_from(label.len()).map_err(|_| DnsError::Unreachable(file!(), line!()))?;
            out.write_bytes(&[len])
                .map_err(|_| DnsError::ResponseBufferFull)?;
            out.write_bytes(label.as_bytes())
                .map_err(|_| DnsError::ResponseBufferFull)?;
        }
        out.write_bytes(&[0])
            .map_err(|_| DnsError::ResponseBufferFull)?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the name is longer than 255 bytes.  This cannot happen.
    pub fn as_bytes(&self) -> Result<FixedBuf<256>, DnsError> {
        let mut buf: FixedBuf<256> = FixedBuf::new();
        self.write(&mut buf)?;
        Ok(buf)
    }

    #[must_use]
    pub fn inner(&self) -> &str {
        &self.0
    }
}
impl Display for DnsName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "{}", self.0)
    }
}
impl std::convert::TryFrom<&'static str> for DnsName {
    type Error = String;

    fn try_from(value: &'static str) -> Result<Self, Self::Error> {
        DnsName::new(value)
    }
}

#[cfg(test)]
#[test]
fn test_err() {
    assert_eq!(
        <Result<DnsName, String>>::Err("not a valid DNS name: \"abc!\"".to_string()),
        DnsName::new("abc!")
    );
}

#[cfg(test)]
#[test]
fn test_new_label_separators() {
    DnsName::new(".").unwrap_err();
    assert_eq!("a", DnsName::new("a.").unwrap().inner());
    DnsName::new("a..").unwrap_err();
    DnsName::new(".a").unwrap_err();
    DnsName::new("b..a").unwrap_err();
    DnsName::new(".b.a").unwrap_err();
}

#[cfg(test)]
#[test]
fn test_new_label_charset() {
    const ALLOWED: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.";
    for c in ALLOWED.chars() {
        let value = format!("a{c}a");
        DnsName::new(&value).expect(&value);
    }
    for b in 0..=255_u8 {
        let c = char::from(b);
        if !ALLOWED.contains(c) {
            let value = format!("a{c}a");
            assert_eq!(
                <Result<DnsName, String>>::Err(format!("not a valid DNS name: {value:?}")),
                DnsName::new(&value)
            );
        }
    }
    assert_eq!(
        <Result<DnsName, String>>::Err("not a valid DNS name: \"a\u{263A}\"".to_string()),
        DnsName::new("a\u{263A}")
    );
}

#[cfg(test)]
#[test]
fn test_new_label_normalizing() {
    assert_eq!(
        "abcdefghijklmnopqrstuvwxyz",
        DnsName::new("abcdefghijklmnopqrstuvwxyz").unwrap().inner()
    );
    assert_eq!(
        "abcdefghijklmnopqrstuvwxyz",
        DnsName::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap().inner()
    );
    assert_eq!("a0123456789", DnsName::new("a0123456789").unwrap().inner());
    assert_eq!("a-b.c", DnsName::new("a-b.c").unwrap().inner());
    assert_eq!(
        "xyz321-654abc.def",
        DnsName::new("Xyz321-654abC.DeF").unwrap().inner()
    );
}

#[cfg(test)]
#[test]
fn test_new_label_format() {
    DnsName::new("a").unwrap();
    DnsName::new("1").unwrap_err();
    DnsName::new("1a").unwrap_err();
    DnsName::new("a1").unwrap();
    DnsName::new("a9876543210").unwrap();
    DnsName::new("-").unwrap_err();
    DnsName::new("a-").unwrap_err();
    DnsName::new("-a").unwrap_err();
    DnsName::new("a-.b").unwrap_err();
    DnsName::new("a.-b").unwrap_err();
    DnsName::new("a-b").unwrap();
    DnsName::new("a-0").unwrap();
    DnsName::new("a---b").unwrap();
}

#[cfg(test)]
#[test]
fn test_new_label_length() {
    DnsName::new("").unwrap_err();
    DnsName::new("a").unwrap();
    DnsName::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    DnsName::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap_err();
}

#[cfg(test)]
#[test]
fn test_new_name_length() {
    DnsName::new(concat!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ))
    .unwrap();
    DnsName::new(concat!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    ))
    .unwrap();
    DnsName::new(concat!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.a"
    ))
    .unwrap_err();
    DnsName::new(concat!(
        "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.",
        "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.",
        "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.",
        "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.",
        "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.",
        "a.a.a",
    ))
    .unwrap();
    DnsName::new(concat!(
        "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.",
        "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.",
        "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.",
        "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.",
        "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.",
        "a.a.aa",
    ))
    .unwrap_err();
}

// TODO: Test read()
// TODO: Test write()

#[cfg(test)]
#[test]
fn test_inner() {
    assert_eq!("abc", DnsName::new("abc").unwrap().inner());
}

#[cfg(test)]
#[test]
fn test_display() {
    assert_eq!(
        "example.com",
        format!("{}", DnsName::new("example.com").unwrap())
    );
}

// TODO: Test TryFrom
