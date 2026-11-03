use std::fs;

use img4_rs::compression::*;
use img4_rs::model::*;

fn refdir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("reference")
}

fn small_refs() -> Vec<std::path::PathBuf> {
    let mut v: Vec<_> = fs::read_dir(refdir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| fs::metadata(p).unwrap().len() < 50_000_000)
        .collect();
    v.sort();
    v
}

#[test]
fn parses_all_small_references_and_roundtrips_bytes() {
    for p in small_refs() {
        let d = fs::read(&p).unwrap();
        match sniff_kind(&d) {
            Some("IM4P") => assert_eq!(Im4p::parse(&d).unwrap().to_tlv_bytes(), d, "{p:?}"),
            Some("IMG4") => assert_eq!(Img4::parse(&d).unwrap().to_bytes(), d, "{p:?}"),
            k => panic!("{p:?}: unexpected kind {k:?}"),
        }
    }
}

#[test]
fn retype_keeps_payload_and_properties() {
    let d = fs::read(refdir().join("stock_devicetree.im4p")).unwrap();
    let orig = Im4p::parse(&d).unwrap();
    assert_eq!(orig.fourcc, "dtre");
    let mut t = Im4p::parse(&d).unwrap();
    t.fourcc = "rdtr".into();
    let out = t.to_tlv_bytes();
    let back = Im4p::parse(&out).unwrap();
    assert_eq!(back.fourcc, "rdtr");
    assert_eq!(back.payload, orig.payload);
    assert_eq!(back.properties_tlv, orig.properties_tlv);
    assert_eq!(back.kbag, orig.kbag);
    assert_eq!(back.size_seq_tlv, orig.size_seq_tlv);
}

#[test]
fn kernelcache_properties_roundtrip() {
    let d = fs::read(refdir().join("known_good_kernelcache.img4")).unwrap();
    let img = Img4::parse(&d).unwrap();
    let props = img.im4p.properties().unwrap();
    println!(
        "props: {:?}",
        props.iter().map(|p| p.fourcc.clone()).collect::<Vec<_>>()
    );
    assert!(!props.is_empty());
    let mut r = img.im4p.to_tlv_bytes();
    let again = Im4p::parse(&r).unwrap();
    assert_eq!(again.properties_tlv, img.im4p.properties_tlv);
    assert_eq!(Img4::parse(&img.to_bytes()).unwrap().to_bytes(), d);
    r.clear();
}

#[test]
fn lzfse_roundtrip() {
    let raw: Vec<u8> = (0..100_000u32)
        .map(|i| ((i * 7) % 251) as u8 ^ (i / 1000) as u8)
        .collect();
    let c = lzfse_compress(&raw).unwrap();
    assert!(c.starts_with(b"bvx2"));
    assert_eq!(detect_compression(&c), Compression::Lzfse);
    assert_eq!(decompress_payload(&c, Compression::Lzfse).unwrap(), raw);
}

#[test]
fn lzss_roundtrip() {
    let raw: Vec<u8> = b"hello hello hello world "
        .iter()
        .cycle()
        .take(20_000)
        .cloned()
        .chain((0..5000u32).map(|i| (i * 31 % 256) as u8))
        .collect();
    let c = lzss_compress(&raw).unwrap();
    assert_eq!(detect_compression(&c), Compression::Lzss);
    assert_eq!(decompress_payload(&c, Compression::Lzss).unwrap(), raw);
}
