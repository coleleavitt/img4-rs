//! Payload compression helpers (LZFSE via `lzfse_rust`; LZSS best-effort).

use std::io;

use crate::model::Compression;

#[derive(Debug)]
pub enum CompressionError {
    Io(io::Error),
    Lzfse(String),
    Lzss(String),
    Unsupported(&'static str),
}

impl std::fmt::Display for CompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionError::Io(e) => write!(f, "I/O error: {e}"),
            CompressionError::Lzfse(s) => write!(f, "LZFSE error: {s}"),
            CompressionError::Lzss(s) => write!(f, "LZSS error: {s}"),
            CompressionError::Unsupported(s) => write!(f, "unsupported: {s}"),
        }
    }
}
impl std::error::Error for CompressionError {}
impl From<io::Error> for CompressionError {
    fn from(e: io::Error) -> Self {
        CompressionError::Io(e)
    }
}

pub fn lzfse_compress(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let mut out = Vec::new();
    lzfse_rust::encode_bytes(data, &mut out)?;
    if !(out.starts_with(b"bvx2") && out.windows(4).any(|w| w == b"bvx$")) {
        return Err(CompressionError::Lzfse(
            "output missing bvx2/bvx$ markers".into(),
        ));
    }
    Ok(out)
}

pub fn lzfse_decompress(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let mut out = Vec::new();
    lzfse_rust::decode_bytes(data, &mut out).map_err(|e| CompressionError::Lzfse(e.to_string()))?;
    Ok(out)
}

/// Apple's "complzss" container: an 8-byte magic, an adler32 checksum of the
/// *decompressed* data, the decompressed size, the compressed size, a
/// version word, all big-endian, padded to a fixed 0x180-byte header,
/// followed by the raw LZSS stream.
const COMPLZSS_HEADER_LEN: usize = 0x180;

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

pub fn lzss_decompress(stored: &[u8]) -> Result<Vec<u8>, CompressionError> {
    if !stored.starts_with(b"complzss") || stored.len() < COMPLZSS_HEADER_LEN {
        return Err(CompressionError::Lzss("missing complzss header".into()));
    }
    let comp_len = u32::from_be_bytes(stored[0x10..0x14].try_into().unwrap()) as usize;
    let stream = &stored[COMPLZSS_HEADER_LEN..COMPLZSS_HEADER_LEN + comp_len];
    lzss_raw_decompress(stream)
}

pub fn lzss_compress(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let comp = lzss_raw_compress(data);
    let mut header = Vec::with_capacity(COMPLZSS_HEADER_LEN);
    header.extend_from_slice(b"complzss");
    header.extend_from_slice(&adler32(data).to_be_bytes());
    header.extend_from_slice(&(data.len() as u32).to_be_bytes());
    header.extend_from_slice(&(comp.len() as u32).to_be_bytes());
    header.extend_from_slice(&1u32.to_be_bytes());
    header.resize(COMPLZSS_HEADER_LEN, 0);
    header.extend(comp);
    Ok(header)
}

// Okumura LZSS as used by Apple's "complzss": 4096-byte ring buffer
// pre-filled with spaces, write cursor starting at N-F, flag bytes read LSB
// first (1 = literal, 0 = 2-byte reference: low 8 bits of the ring position,
// then high 4 bits of the position and `len - 3` in the low nibble).
const N: usize = 4096;
const F: usize = 18;
const THRESHOLD: usize = 3;

fn lzss_raw_decompress(src: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let mut out = Vec::new();
    let mut window = vec![b' '; N];
    let mut r = N - F;
    let mut pos = 0usize;
    while pos < src.len() {
        let flags = src[pos];
        pos += 1;
        for bit in 0..8 {
            if pos >= src.len() {
                break;
            }
            if flags >> bit & 1 != 0 {
                let c = src[pos];
                pos += 1;
                out.push(c);
                window[r] = c;
                r = (r + 1) % N;
            } else {
                if pos + 1 >= src.len() {
                    return Err(CompressionError::Lzss("truncated reference".into()));
                }
                let i = src[pos] as usize;
                let j = src[pos + 1] as usize;
                pos += 2;
                let offset = i | ((j & 0xF0) << 4);
                let len = (j & 0x0F) + THRESHOLD;
                for k in 0..len {
                    let c = window[(offset + k) % N];
                    out.push(c);
                    window[r] = c;
                    r = (r + 1) % N;
                }
            }
        }
    }
    Ok(out)
}

fn lzss_raw_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let flag_at = out.len();
        out.push(0);
        let mut flags = 0u8;
        for bit in 0..8 {
            if pos >= data.len() {
                break;
            }
            let max_len = F.min(data.len() - pos);
            let (mut best_len, mut best_off) = (0usize, 0usize);
            if max_len >= THRESHOLD {
                for cand in pos.saturating_sub(N - F)..pos {
                    let mut l = 0;
                    while l < max_len && data[cand + l] == data[pos + l] {
                        l += 1;
                    }
                    if l > best_len {
                        best_len = l;
                        best_off = cand;
                    }
                }
            }
            if best_len >= THRESHOLD {
                let ring = (N - F + best_off) % N;
                out.push((ring & 0xFF) as u8);
                out.push((((ring >> 4) & 0xF0) | (best_len - THRESHOLD)) as u8);
                pos += best_len;
            } else {
                flags |= 1 << bit;
                out.push(data[pos]);
                pos += 1;
            }
        }
        out[flag_at] = flags;
    }
    out
}

pub fn decompress_payload(stored: &[u8], kind: Compression) -> Result<Vec<u8>, CompressionError> {
    match kind {
        Compression::None => Ok(stored.to_vec()),
        Compression::Lzfse => lzfse_decompress(stored),
        Compression::Lzss => lzss_decompress(stored),
    }
}
