//! Runs the real `img4` binary. Needs no files from `reference/`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn img4(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_img4")).args(args).output().expect("run img4")
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn help_and_version_go_to_clap_not_legacy_mode() {
    for flag in ["--help", "-h"] {
        let out = img4(&[flag]);
        assert!(out.status.success(), "{flag}: {}", String::from_utf8_lossy(&out.stderr));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("Usage:") && stdout.contains("create"), "{flag}: {stdout}");
    }
    for flag in ["--version", "-V"] {
        let out = img4(&[flag]);
        assert!(out.status.success(), "{flag}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains(env!("CARGO_PKG_VERSION")));
    }
}

#[test]
fn legacy_wrap_and_extract_still_work() {
    let dir = scratch("legacy_wrap_and_extract");
    let raw = dir.join("payload.bin");
    let payload: Vec<u8> = (0..4096u32).map(|i| (i * 31 % 251) as u8).collect();
    std::fs::write(&raw, &payload).unwrap();

    // A minimal manifest: the top-level SEQUENCE is all the tool requires.
    let im4m = dir.join("IM4M");
    std::fs::write(&im4m, [0x30, 0x06, 0x16, 0x04, b'I', b'M', b'4', b'M']).unwrap();

    // build.sh shape: -i raw -o out -A -T fourcc -M manifest
    let img = dir.join("out.img4");
    let out = img4(&[
        "-i", raw.to_str().unwrap(), "-o", img.to_str().unwrap(),
        "-A", "-T", "rdsk", "-M", im4m.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let parsed = img4_rs::Img4::parse(&std::fs::read(&img).unwrap()).unwrap();
    assert_eq!(parsed.im4p.fourcc, "rdsk");
    assert_eq!(parsed.im4p.description, "Unknown");
    assert_eq!(parsed.im4p.payload, payload);

    // Legacy extract (no -M) writes the stored payload back out.
    let back = dir.join("back.bin");
    let out = img4(&["-i", img.to_str().unwrap(), "-o", back.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read(&back).unwrap(), payload);
}
