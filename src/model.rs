//! Byte-exact IMG4 / IM4P / IM4M container model.
//!
//! Every field that this crate does not need to interpret (IM4M manifest
//! bytes, optional IM4P size/property blocks, IM4R) is kept as the exact raw
//! TLV bytes it was parsed from. Only `fourcc`, `description`, and the stored
//! payload bytes are exposed for mutation, so operations like `retype` are
//! byte-exact by construction: nothing we do not touch can change.

use crate::der::{self, read_tlv, universal, write_tlv, Class, DerError, Tag};
use std::fmt;

#[derive(Debug)]
pub enum Img4Error {
    Der(DerError),
    Invalid(String),
}

impl fmt::Display for Img4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Img4Error::Der(e) => write!(f, "{e}"),
            Img4Error::Invalid(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for Img4Error {}
impl From<DerError> for Img4Error {
    fn from(e: DerError) -> Self {
        Img4Error::Der(e)
    }
}

type Result<T> = std::result::Result<T, Img4Error>;

fn expect_ia5(tlv: &der::Tlv<'_>, expected: Option<&str>) -> Result<String> {
    if tlv.tag.number != universal::IA5_STRING || tlv.tag.class != Class::Universal {
        return Err(Img4Error::Invalid("expected IA5String".into()));
    }
    let s = String::from_utf8(tlv.content.to_vec())
        .map_err(|_| Img4Error::Invalid("IA5String is not valid ASCII/UTF-8".into()))?;
    if let Some(exp) = expected {
        if !s.eq_ignore_ascii_case(exp) {
            return Err(Img4Error::Invalid(format!("expected fourcc '{exp}', got '{s}'")));
        }
    }
    Ok(s)
}

fn ia5_tlv(s: &str) -> Vec<u8> {
    write_tlv(Tag::universal(universal::IA5_STRING, false), s.as_bytes())
}

fn octet_tlv(data: &[u8]) -> Vec<u8> {
    write_tlv(Tag::universal(universal::OCTET_STRING, false), data)
}

/// A detected IM4P payload compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Lzfse,
    Lzss,
}

impl Compression {
    pub fn name(self) -> &'static str {
        match self {
            Compression::None => "none",
            Compression::Lzfse => "lzfse",
            Compression::Lzss => "lzss",
        }
    }
}

/// Detect compression from the magic bytes of a *stored* IM4P payload.
pub fn detect_compression(data: &[u8]) -> Compression {
    if data.starts_with(b"complzss") {
        Compression::Lzss
    } else if data.starts_with(b"bvx") && contains(data, b"bvx$") {
        Compression::Lzfse
    } else {
        Compression::None
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// One `PAYP`/`MANP`/... property: a fourcc name plus its raw ASN.1 value TLV
/// (kept intact; the value's universal type varies: IA5String, Integer,
/// OctetString, ...).
#[derive(Debug)]
pub struct Property {
    pub fourcc: String,
    pub value_tlv: Vec<u8>,
}

impl Property {
    /// Parse the properties out of a raw `SEQUENCE { IA5 name, SET OF ... }`
    /// TLV content (the content *inside* that outer SEQUENCE's tag/len).
    pub fn parse_group(seq_content: &[u8]) -> Result<(String, Vec<Property>)> {
        let mut pos = 0usize;
        let name_tlv = read_tlv(&seq_content[pos..])?;
        let name = expect_ia5(&name_tlv, None)?;
        pos += name_tlv.consumed;

        let set_tlv = read_tlv(&seq_content[pos..])?;
        if set_tlv.tag.number != universal::SET || set_tlv.tag.class != Class::Universal {
            return Err(Img4Error::Invalid("expected SET OF properties".into()));
        }

        let mut props = Vec::new();
        der::for_each_tlv(set_tlv.content, |entry| {
            // Each entry is PRIVATE-tag(fourcc) wrapping a universal SEQUENCE{IA5 fourcc, value}.
            if entry.tag.class != Class::Private {
                return Err(DerError::Invalid("property entry is not PRIVATE class".into()));
            }
            let fourcc = Tag::fourcc_from_number(entry.tag.number)
                .ok_or_else(|| DerError::Invalid("non-ASCII property fourcc".into()))?;
            let inner = read_tlv(entry.content)?;
            if inner.tag.number != universal::SEQUENCE {
                return Err(DerError::Invalid("expected SEQUENCE inside property".into()));
            }
            let mut inner_pos = 0usize;
            let inner_name = read_tlv(&inner.content[inner_pos..])?;
            inner_pos += inner_name.consumed;
            let value = read_tlv(&inner.content[inner_pos..])?;
            let value_tlv = write_tlv(value.tag, value.content);
            props.push(Property { fourcc, value_tlv });
            let _ = inner_name;
            Ok(())
        })?;

        Ok((name, props))
    }

    /// Best-effort human-readable rendering of this property's value.
    pub fn describe_value(&self) -> String {
        match read_tlv(&self.value_tlv) {
            Ok(tlv) if tlv.tag.number == universal::IA5_STRING => {
                String::from_utf8_lossy(tlv.content).to_string()
            }
            Ok(tlv) if tlv.tag.number == universal::INTEGER => {
                let v = der::decode_integer(tlv.content);
                format!("{v} (0x{:x})", v as u64)
            }
            Ok(tlv) if tlv.tag.number == universal::BOOLEAN => {
                (!tlv.content.is_empty() && tlv.content[0] != 0).to_string()
            }
            Ok(tlv) => format!("<{} bytes>", tlv.content.len()),
            Err(_) => format!("<{} raw bytes>", self.value_tlv.len()),
        }
    }
}

/// An IM4P payload container: IA5 fourcc/description + stored payload bytes
/// + opaque passthrough for keybag, size hint, and PAYP properties.
pub struct Im4p {
    pub fourcc: String,
    pub description: String,
    /// The payload exactly as stored (may be LZFSE/LZSS-compressed or raw).
    pub payload: Vec<u8>,
    /// Raw OCTET STRING content of the optional keybag blob, if present.
    pub kbag: Option<Vec<u8>>,
    /// Raw full TLV bytes of the optional `SEQUENCE { INTEGER 1, INTEGER size }`.
    pub size_seq_tlv: Option<Vec<u8>>,
    /// Raw full TLV bytes of the inner `SEQUENCE { IA5 "PAYP", SET OF props }`
    /// found under the optional `[0]` context tag.
    pub properties_tlv: Option<Vec<u8>>,
}

impl Im4p {
    pub fn new(fourcc: &str, description: &str, payload: Vec<u8>) -> Self {
        Im4p {
            fourcc: fourcc.to_string(),
            description: description.to_string(),
            payload,
            kbag: None,
            size_seq_tlv: None,
            properties_tlv: None,
        }
    }

    pub fn compression(&self) -> Compression {
        detect_compression(&self.payload)
    }

    /// Declared decompressed size, when a size hint block is present.
    pub fn declared_size(&self) -> Option<i64> {
        let tlv = self.size_seq_tlv.as_ref()?;
        let outer = read_tlv(tlv).ok()?;
        let mut pos = 0usize;
        let first = read_tlv(&outer.content[pos..]).ok()?;
        pos += first.consumed;
        let second = read_tlv(&outer.content[pos..]).ok()?;
        let _ = first;
        Some(der::decode_integer(second.content))
    }

    pub fn set_size_hint(&mut self, size: i64) {
        let content = [
            write_tlv(Tag::universal(universal::INTEGER, false), &der::encode_integer(1)),
            write_tlv(Tag::universal(universal::INTEGER, false), &der::encode_integer(size)),
        ]
        .concat();
        self.size_seq_tlv = Some(write_tlv(Tag::universal(universal::SEQUENCE, true), &content));
    }

    pub fn properties(&self) -> Result<Vec<Property>> {
        match &self.properties_tlv {
            None => Ok(Vec::new()),
            Some(tlv) => {
                let outer = read_tlv(tlv)?;
                let (_name, props) = Property::parse_group(outer.content)?;
                Ok(props)
            }
        }
    }

    /// Parse an IM4P from a full top-level `SEQUENCE { IA5 "IM4P", ... }` TLV.
    pub fn parse(data: &[u8]) -> Result<Im4p> {
        let outer = read_tlv(data)?;
        if outer.tag.number != universal::SEQUENCE || outer.tag.class != Class::Universal {
            return Err(Img4Error::Invalid("expected top-level SEQUENCE".into()));
        }
        Self::parse_content(outer.content)
    }

    fn parse_content(content: &[u8]) -> Result<Im4p> {
        let mut pos = 0usize;

        let magic = read_tlv(&content[pos..])?;
        expect_ia5(&magic, Some("IM4P"))?;
        pos += magic.consumed;

        let fourcc_tlv = read_tlv(&content[pos..])?;
        let fourcc = expect_ia5(&fourcc_tlv, None)?;
        pos += fourcc_tlv.consumed;

        let desc_tlv = read_tlv(&content[pos..])?;
        let description = expect_ia5(&desc_tlv, None)?;
        pos += desc_tlv.consumed;

        let payload_tlv = read_tlv(&content[pos..])?;
        if payload_tlv.tag.number != universal::OCTET_STRING {
            return Err(Img4Error::Invalid("expected OCTET STRING payload".into()));
        }
        let payload = payload_tlv.content.to_vec();
        pos += payload_tlv.consumed;

        let mut kbag = None;
        if pos < content.len() {
            let peek = read_tlv(&content[pos..])?;
            if peek.tag.number == universal::OCTET_STRING && peek.tag.class == Class::Universal {
                kbag = Some(peek.content.to_vec());
                pos += peek.consumed;
            }
        }

        let mut size_seq_tlv = None;
        if pos < content.len() {
            let peek = read_tlv(&content[pos..])?;
            if peek.tag.number == universal::SEQUENCE && peek.tag.class == Class::Universal {
                size_seq_tlv = Some(write_tlv(peek.tag, peek.content));
                pos += peek.consumed;
            }
        }

        let mut properties_tlv = None;
        if pos < content.len() {
            let peek = read_tlv(&content[pos..])?;
            if peek.tag.class == Class::Context {
                // Store just the inner SEQUENCE bytes (content of the context tag).
                properties_tlv = Some(peek.content.to_vec());
                pos += peek.consumed;
            }
        }

        if pos != content.len() {
            return Err(Img4Error::Invalid("trailing data in IM4P".into()));
        }

        Ok(Im4p { fourcc, description, payload, kbag, size_seq_tlv, properties_tlv })
    }

    /// Serialize back to the full top-level `SEQUENCE { IA5 "IM4P", ... }` TLV.
    pub fn to_tlv_bytes(&self) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend(ia5_tlv("IM4P"));
        content.extend(ia5_tlv(&self.fourcc));
        content.extend(ia5_tlv(&self.description));
        content.extend(octet_tlv(&self.payload));
        if let Some(kbag) = &self.kbag {
            content.extend(octet_tlv(kbag));
        }
        if let Some(size_seq) = &self.size_seq_tlv {
            content.extend(size_seq);
        }
        if let Some(props) = &self.properties_tlv {
            content.extend(write_tlv(Tag::context(0, true), props));
        }
        write_tlv(Tag::universal(universal::SEQUENCE, true), &content)
    }
}

/// A full IMG4 container. The IM4P is parsed (so `info`/`retype` can reach
/// into it); the IM4M and IM4R are kept as opaque raw TLV bytes because this
/// crate never needs to understand or rebuild a manifest.
pub struct Img4 {
    pub im4p: Im4p,
    /// Raw full TLV bytes of the IM4M (content of the `[0]` context tag).
    pub im4m: Option<Vec<u8>>,
    /// Raw full TLV bytes of the IM4R (content of the `[1]` context tag).
    pub im4r: Option<Vec<u8>>,
}

impl Img4 {
    pub fn parse(data: &[u8]) -> Result<Img4> {
        let outer = read_tlv(data)?;
        if outer.tag.number != universal::SEQUENCE || outer.tag.class != Class::Universal {
            return Err(Img4Error::Invalid("expected top-level SEQUENCE".into()));
        }
        let content = outer.content;
        let mut pos = 0usize;

        let magic = read_tlv(&content[pos..])?;
        expect_ia5(&magic, Some("IMG4"))?;
        pos += magic.consumed;

        let im4p_tlv = read_tlv(&content[pos..])?;
        if im4p_tlv.tag.number != universal::SEQUENCE || im4p_tlv.tag.class != Class::Universal {
            return Err(Img4Error::Invalid("expected IM4P SEQUENCE".into()));
        }
        let im4p_full = write_tlv(im4p_tlv.tag, im4p_tlv.content);
        let im4p = Im4p::parse(&im4p_full)?;
        pos += im4p_tlv.consumed;

        let mut im4m = None;
        if pos < content.len() {
            let peek = read_tlv(&content[pos..])?;
            if peek.tag.class == Class::Context && peek.tag.number == 0 {
                im4m = Some(peek.content.to_vec());
                pos += peek.consumed;
            }
        }

        let mut im4r = None;
        if pos < content.len() {
            let peek = read_tlv(&content[pos..])?;
            if peek.tag.class == Class::Context && peek.tag.number == 1 {
                im4r = Some(peek.content.to_vec());
                pos += peek.consumed;
            }
        }

        if pos != content.len() {
            return Err(Img4Error::Invalid("trailing data in IMG4".into()));
        }

        Ok(Img4 { im4p, im4m, im4r })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend(ia5_tlv("IMG4"));
        content.extend(self.im4p.to_tlv_bytes());
        if let Some(im4m) = &self.im4m {
            content.extend(write_tlv(Tag::context(0, true), im4m));
        }
        if let Some(im4r) = &self.im4r {
            content.extend(write_tlv(Tag::context(1, true), im4r));
        }
        write_tlv(Tag::universal(universal::SEQUENCE, true), &content)
    }
}

/// Sniff whether `data` is an IM4P or an IMG4 top-level container by peeking
/// at its inner magic IA5String (bytes 2..6 as in the original wrapper's
/// `head -c20 | grep IM4P`, generalized to decode the TLV properly).
pub fn sniff_kind(data: &[u8]) -> Option<&'static str> {
    let outer = read_tlv(data).ok()?;
    if outer.tag.number != universal::SEQUENCE || outer.tag.class != Class::Universal {
        return None;
    }
    let magic = read_tlv(outer.content).ok()?;
    let s = expect_ia5(&magic, None).ok()?;
    match s.as_str() {
        "IM4P" => Some("IM4P"),
        "IMG4" => Some("IMG4"),
        "IM4M" => Some("IM4M"),
        _ => None,
    }
}
