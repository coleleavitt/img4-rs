# img4-rs

A byte-exact IMG4 / IM4P / IM4M container tool and library in Rust.

It parses Apple's Image4 containers, lets you change the parts you care about (fourcc,
description, payload) and writes everything else back exactly as it was read. Fields it doesn't
interpret are kept as their original raw DER bytes: the IM4M manifest, IM4R, keybags, and the
IM4P size and property blocks. So retyping or re-wrapping a file can't change anything you didn't
touch, and parsing then re-serializing an unmodified file gives back the same bytes.

It also has a legacy flag interface (`-i -o -M -T -A`), so it drops in for the `img4` binary
that SSH-ramdisk build scripts (such as the ICH `build.sh`) call on Linux.

## Build

```console
$ cargo build --release
$ ./target/release/img4 info kernelcache.img4
```

## Commands

| command | what it does |
|---|---|
| `img4 info <FILE>` | Fourcc, description, stored size, compression, declared decompressed size, properties (e.g. kernelcache `kc*` values), keybag and IM4M presence. Accepts IM4P, IMG4 or a bare IM4M. |
| `img4 extract <IN> [-o OUT] [--decompress]` | Writes the payload exactly as stored, or decompressed with `--decompress`. Writes to stdout without `-o`. |
| `img4 create --input RAW --type FOURCC [--compress none\|lzfse\|lzss] [--description TEXT] -o OUT` | Wraps a raw file in a new IM4P. The description defaults to `Unknown`, as Apple's tool does. `lzfse` also records the decompressed size. |
| `img4 retype <IN> --type FOURCC -o OUT` | Changes only the fourcc. The payload, properties and keybag are byte-identical. |
| `img4 attach <IM4P> [--im4m MANIFEST] -o OUT` | Wraps an IM4P (or the IM4P inside an IMG4) into an IMG4, with the manifest bytes stored untouched. |

`img4 --help` lists the commands, and each one has its own `--help`, e.g. `img4 create --help`.

### Legacy mode

If the first argument starts with `-`, the tool uses the old flag interface:

| invocation | result |
|---|---|
| `img4 -i IN -o OUT -M IM4M [-T FOURCC]` | Builds an IMG4 with that manifest. If `IN` is already an IM4P or IMG4, its IM4P is reused, retyped if `-T` differs. Otherwise `IN` is wrapped raw as a new IM4P with type `-T` (default `data`) and description `Unknown`. |
| `img4 -i IN -o OUT` | If `IN` is an IM4P or IMG4, writes its payload **as stored** (not decompressed). Otherwise copies the file. |
| `-A` | Accepted and ignored, for call-site compatibility. |

For example, this is how the ICH build packages a ramdisk:
```console
$ img4 -i ramdisk.dmg -o ramdisk.img4 -A -T rdsk -M IM4M
```

## Library

```rust
use img4_rs::{compression, Im4p, Img4};

let data = std::fs::read("kernelcache.img4")?;
let img = Img4::parse(&data)?;
let im4p = &img.im4p;
println!("{} {:?} {} bytes stored", im4p.fourcc, im4p.description, im4p.payload.len());

// Stored bytes -> raw payload (LZFSE / LZSS / none, detected from the magic)
let raw = compression::decompress_payload(&im4p.payload, im4p.compression())?;

// Nothing that wasn't touched changes: re-serializing is byte-exact
assert_eq!(img.to_bytes(), data);

// Change only the fourcc; payload, properties and keybag stay byte-identical
let mut retyped = Im4p::parse(&im4p.to_tlv_bytes())?;
retyped.fourcc = "rkrn".into();
std::fs::write("retyped.im4p", retyped.to_tlv_bytes())?;
```

Modules:
- `model`: `Img4`, `Im4p`, `Property`, `Compression`, `sniff_kind`.
- `der`: the DER TLV reader and writer, including Apple's private-class fourcc tags.
- `compression`: LZFSE and the `complzss` LZSS container.

## Compatibility notes

- **Description.** New IM4Ps get the description `Unknown`, which is what Apple's `img4` writes
  when none is given. An empty description made ramdisk and trustcache `.img4` files exactly
  7 bytes smaller than ones built on macOS. With `Unknown`, a Linux-built ramdisk `.img4` is the
  same size as the macOS build, with the same IM4P header and identical IM4M.
- **LZFSE output is valid but not Apple's bytes.** Compression uses `lzfse_rust`. Its stream
  decompresses to the identical payload but isn't byte-identical to Apple's encoder; no
  third-party LZFSE encoder is. Boot verification doesn't depend on the compressed bytes, but
  re-compressing an Apple kernelcache won't reproduce Apple's file.
- **LZSS** is Apple's `complzss` layout: an 8-byte magic, then the Adler-32 of the decompressed
  data, the decompressed size, the compressed size and a version word, all big-endian, padded to
  a 0x180-byte header, then the raw LZSS stream. It's best-effort.
- **Not implemented:** keybag decryption (keybags are preserved, not used), and IM4M signing or
  validation (manifests are carried as opaque bytes).

## Tests

```console
$ cargo test
```

`tests/cli.rs` runs the binary itself (help, version, and the legacy wrap and extract flags) and
needs no extra files. The other tests round-trip real containers from `reference/`. That
directory is **not in git**, because
it holds Apple firmware and IM4Ms personalized to a specific device. To run the tests, put these
files there yourself: `known_good.img4`, `known_good_kernelcache.img4`,
`known_good_devicetree.img4`, `new_built.img4`, `new_devicetree.img4` and
`stock_devicetree.im4p`. Files over 50 MB, such as a ramdisk, are skipped by the round-trip test.
