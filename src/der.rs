//! Minimal BER/DER encoder+decoder tailored to the IMG4/IM4P/IM4M ASN.1 profile.
//! Only the subset of X.690 that Apple's img4 format uses is implemented:
//! short/long-form definite lengths, low- and high-tag-number identifiers
//! (needed for PRIVATE-class fourcc tags), and primitive/constructed content.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Universal,
    Application,
    Context,
    Private,
}

impl Class {
    fn from_bits(b: u8) -> Class {
        match b {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::Context,
            3 => Class::Private,
            _ => unreachable!(),
        }
    }

    fn bits(self) -> u8 {
        match self {
            Class::Universal => 0,
            Class::Application => 1,
            Class::Context => 2,
            Class::Private => 3,
        }
    }
}

pub mod universal {
    pub const BOOLEAN: u64 = 1;
    pub const INTEGER: u64 = 2;
    pub const OCTET_STRING: u64 = 4;
    pub const IA5_STRING: u64 = 22;
    pub const SEQUENCE: u64 = 16;
    pub const SET: u64 = 17;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    pub class: Class,
    pub constructed: bool,
    pub number: u64,
}

impl Tag {
    pub fn universal(number: u64, constructed: bool) -> Tag {
        Tag {
            class: Class::Universal,
            constructed,
            number,
        }
    }
    pub fn context(number: u64, constructed: bool) -> Tag {
        Tag {
            class: Class::Context,
            constructed,
            number,
        }
    }
    pub fn private(number: u64, constructed: bool) -> Tag {
        Tag {
            class: Class::Private,
            constructed,
            number,
        }
    }

    /// The PRIVATE-class tag number img4 uses to wrap a fourcc-named value:
    /// the 4 ASCII bytes of the fourcc, taken as one big-endian integer.
    pub fn private_fourcc(fourcc: &str, constructed: bool) -> Tag {
        let bytes = fourcc.as_bytes();
        assert_eq!(bytes.len(), 4, "fourcc must be exactly 4 bytes");
        let number = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
        Tag::private(number, constructed)
    }

    pub fn fourcc_from_number(number: u64) -> Option<String> {
        if number > u32::MAX as u64 {
            return None;
        }
        let b = (number as u32).to_be_bytes();
        if b.iter().all(|c| c.is_ascii_graphic()) {
            String::from_utf8(b.to_vec()).ok()
        } else {
            None
        }
    }

    fn encode(&self) -> Vec<u8> {
        let class_bits = self.class.bits() << 6;
        let constructed_bit = if self.constructed { 0x20 } else { 0x00 };
        if self.number < 0x1F {
            vec![class_bits | constructed_bit | (self.number as u8)]
        } else {
            let mut out = vec![class_bits | constructed_bit | 0x1F];
            out.extend(encode_base128(self.number));
            out
        }
    }
}

fn encode_base128(mut n: u64) -> Vec<u8> {
    let mut groups = vec![(n & 0x7F) as u8];
    n >>= 7;
    while n > 0 {
        groups.push((n & 0x7F) as u8 | 0x80);
        n >>= 7;
    }
    groups.reverse();
    let last = groups.len() - 1;
    for (i, g) in groups.iter_mut().enumerate() {
        if i != last {
            *g |= 0x80;
        }
    }
    groups
}

#[derive(Debug)]
pub enum DerError {
    Truncated,
    Invalid(String),
}

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DerError::Truncated => write!(f, "truncated BER/DER data"),
            DerError::Invalid(s) => write!(f, "invalid BER/DER data: {s}"),
        }
    }
}
impl std::error::Error for DerError {}

/// One decoded TLV: its tag, the raw bytes of its content (value), and the
/// total number of bytes consumed from the input (header + content).
pub struct Tlv<'a> {
    pub tag: Tag,
    pub content: &'a [u8],
    pub consumed: usize,
}

/// Decode a single TLV starting at the beginning of `data`.
pub fn read_tlv(data: &[u8]) -> Result<Tlv<'_>, DerError> {
    if data.is_empty() {
        return Err(DerError::Truncated);
    }
    let first = data[0];
    let class = Class::from_bits((first >> 6) & 0x3);
    let constructed = (first & 0x20) != 0;
    let mut pos = 1usize;
    let number: u64;
    if (first & 0x1F) == 0x1F {
        let mut n: u64 = 0;
        loop {
            let b = *data.get(pos).ok_or(DerError::Truncated)?;
            pos += 1;
            n = (n << 7) | (b & 0x7F) as u64;
            if b & 0x80 == 0 {
                break;
            }
        }
        number = n;
    } else {
        number = (first & 0x1F) as u64;
    }

    let len_byte = *data.get(pos).ok_or(DerError::Truncated)?;
    pos += 1;
    let length: usize;
    if len_byte & 0x80 == 0 {
        length = len_byte as usize;
    } else {
        let n_bytes = (len_byte & 0x7F) as usize;
        if n_bytes == 0 {
            return Err(DerError::Invalid("indefinite length not supported".into()));
        }
        let mut n: u64 = 0;
        for _ in 0..n_bytes {
            let b = *data.get(pos).ok_or(DerError::Truncated)?;
            pos += 1;
            n = (n << 8) | b as u64;
        }
        length = n as usize;
    }

    let content = data.get(pos..pos + length).ok_or(DerError::Truncated)?;
    Ok(Tlv {
        tag: Tag {
            class,
            constructed,
            number,
        },
        content,
        consumed: pos + length,
    })
}

fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        bytes.reverse();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend(bytes);
        out
    }
}

/// Encode a full TLV (tag header + length header + content bytes).
pub fn write_tlv(tag: Tag, content: &[u8]) -> Vec<u8> {
    let mut out = tag.encode();
    out.extend(encode_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encode an INTEGER's minimal two's-complement big-endian content bytes.
pub fn encode_integer(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 {
        let keep_msb = bytes[0];
        let next_msb = bytes[1];
        let redundant = (keep_msb == 0x00 && next_msb & 0x80 == 0)
            || (keep_msb == 0xFF && next_msb & 0x80 != 0);
        if redundant {
            bytes.remove(0);
        } else {
            break;
        }
    }
    bytes
}

pub fn decode_integer(content: &[u8]) -> i64 {
    if content.is_empty() {
        return 0;
    }
    let negative = content[0] & 0x80 != 0;
    let mut value: i64 = if negative { -1 } else { 0 };
    for &b in content {
        value = (value << 8) | b as i64;
    }
    value
}

/// Walk every top-level TLV inside `content` (the inside of a SEQUENCE/SET),
/// calling `f` with each one until the content is exhausted.
pub fn for_each_tlv<'a>(
    content: &'a [u8],
    mut f: impl FnMut(Tlv<'a>) -> Result<(), DerError>,
) -> Result<(), DerError> {
    let mut pos = 0usize;
    while pos < content.len() {
        let tlv = read_tlv(&content[pos..])?;
        let consumed = tlv.consumed;
        f(tlv)?;
        pos += consumed;
    }
    Ok(())
}
