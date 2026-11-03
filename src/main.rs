#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use img4_rs::compression;
use img4_rs::der::{Class, read_tlv, universal};
use img4_rs::model::{Im4p, sniff_kind};

#[derive(Parser)]
#[command(name = "img4", version, about = "Byte-exact IMG4/IM4P container tool")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Dump container structure: fourcc, description, stored payload size,
    /// compression magic, properties, IM4M presence.
    Info { file: PathBuf },

    /// Write the payload bytes exactly as stored, unless --decompress is given.
    Extract {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Decompress the payload before writing it (off by default: the
        /// stored bytes are written as-is).
        #[arg(long)]
        decompress: bool,
    },

    /// Wrap a raw binary into a new IM4P.
    Create {
        #[arg(long)]
        input: PathBuf,
        #[arg(long = "type")]
        fourcc: String,
        #[arg(long, value_enum, default_value = "none")]
        compress: CompressArg,
        #[arg(long, default_value = "Unknown")]
        description: String,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Change an IM4P's fourcc, preserving the stored payload and properties
    /// byte-exactly.
    Retype {
        input: PathBuf,
        #[arg(long = "type")]
        fourcc: String,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Wrap an IM4P (with an optional IM4M) into an IMG4.
    Attach {
        im4p: PathBuf,
        #[arg(long)]
        im4m: Option<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum CompressArg {
    None,
    Lzfse,
    Lzss,
}

fn main() -> ExitCode {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let result = if is_legacy_invocation(&raw_args) {
        run_legacy(&raw_args)
    } else {
        let cli = Cli::parse();
        match cli.command {
            Some(cmd) => run_command(cmd),
            None => {
                eprintln!("no command given; run `img4 --help`");
                Err("no command".into())
            }
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("img4: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The legacy `tools/linux/img4` wrapper is only ever invoked with flags
/// (`-i`, `-o`, `-M`, `-T`, `-A`), never a subcommand name. Detect that shape
/// so this binary is a drop-in replacement for build.sh's existing call sites.
/// clap's own top-level flags (`-h`/`--help`, `-V`/`--version`) are not legacy
/// flags, so they go to clap.
fn is_legacy_invocation(args: &[String]) -> bool {
    matches!(args.first(), Some(first) if first.starts_with('-')
        && !matches!(first.as_str(), "-h" | "--help" | "-V" | "--version"))
}

fn run_legacy(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut manifest: Option<PathBuf> = None;
    let mut fourcc_type: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" => {
                input = Some(PathBuf::from(args.get(i + 1).ok_or("-i needs a value")?));
                i += 2;
            }
            "-o" => {
                output = Some(PathBuf::from(args.get(i + 1).ok_or("-o needs a value")?));
                i += 2;
            }
            "-M" => {
                manifest = Some(PathBuf::from(args.get(i + 1).ok_or("-M needs a value")?));
                i += 2;
            }
            "-T" => {
                fourcc_type = Some(args.get(i + 1).ok_or("-T needs a value")?.clone());
                i += 2;
            }
            "-A" => {
                i += 1; // legacy no-op flag, kept for call-site compatibility
            }
            other => return Err(format!("unrecognized legacy flag '{other}'").into()),
        }
    }

    let input = input.ok_or("legacy mode needs -i")?;
    let output = output.ok_or("legacy mode needs -o")?;
    let in_data = fs::read(&input)?;
    let kind = sniff_kind(&in_data);

    if let Some(manifest) = manifest {
        let manifest_bytes = fs::read(&manifest)?;
        let im4p = if kind == Some("IM4P") || kind == Some("IMG4") {
            let mut im4p = if kind == Some("IMG4") {
                Img4Like::parse(&in_data)?.im4p
            } else {
                Im4p::parse(&in_data)?
            };
            if let Some(ref t) = fourcc_type {
                if !t.eq_ignore_ascii_case(&im4p.fourcc) {
                    im4p.fourcc = t.clone();
                }
            }
            im4p
        } else {
            let fourcc = fourcc_type.clone().unwrap_or_else(|| "data".to_string());
            // Apple's `img4` writes "Unknown" as the IM4P description when none is
            // supplied; match that so wrapped payloads are byte-identical to the
            // macOS toolchain (empty string made our files 7 bytes shorter).
            Im4p::new(&fourcc, "Unknown", in_data)
        };
        let img4 = Img4Like {
            im4p,
            im4m: Some(manifest_bytes),
            im4r: None,
        };
        fs::write(&output, img4.to_bytes())?;
    } else if kind == Some("IM4P") || kind == Some("IMG4") {
        fs::write(&output, load_im4p_from_any(&input)?.payload)?;
    } else {
        fs::copy(&input, &output)?;
    }

    Ok(())
}

/// Thin re-export alias so legacy mode can build an IMG4 without importing
/// the library's `Img4` name twice under different meanings.
use img4_rs::model::Img4 as Img4Like;

fn run_command(cmd: Command) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        Command::Info { file } => cmd_info(&file),
        Command::Extract {
            input,
            output,
            decompress,
        } => cmd_extract(&input, output.as_deref(), decompress),
        Command::Create {
            input,
            fourcc,
            compress,
            description,
            output,
        } => cmd_create(&input, &fourcc, compress, &description, &output),
        Command::Retype {
            input,
            fourcc,
            output,
        } => cmd_retype(&input, &fourcc, &output),
        Command::Attach { im4p, im4m, output } => cmd_attach(&im4p, im4m.as_deref(), &output),
    }
}

fn load_im4p_from_any(path: &Path) -> Result<Im4p, Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    match sniff_kind(&data) {
        Some("IM4P") => Ok(Im4p::parse(&data)?),
        Some("IMG4") => Ok(Img4Like::parse(&data)?.im4p),
        other => Err(format!(
            "{}: not an IM4P or IMG4 (sniffed: {other:?})",
            path.display()
        )
        .into()),
    }
}

fn cmd_info(file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(file)?;
    match sniff_kind(&data) {
        Some("IM4P") => print_im4p_info(&Im4p::parse(&data)?, None),
        Some("IMG4") => {
            let img4 = Img4Like::parse(&data)?;
            print_im4p_info(&img4.im4p, Some(img4.im4m.is_some()));
        }
        Some("IM4M") => println!("IM4M manifest ({} bytes)", data.len()),
        other => return Err(format!("unrecognized container (sniffed: {other:?})").into()),
    }
    Ok(())
}

fn print_im4p_info(im4p: &Im4p, im4m_present: Option<bool>) {
    println!("fourcc:          {}", im4p.fourcc);
    println!("description:     {:?}", im4p.description);
    println!("stored size:     {} bytes", im4p.payload.len());
    let compression = im4p.compression();
    println!("compression:     {}", compression.name());
    if let Some(size) = im4p.declared_size() {
        println!("declared size:   {size} bytes (decompressed)");
    }
    match im4p.properties() {
        Ok(props) if !props.is_empty() => {
            println!("properties:");
            for p in props {
                println!("  {} = {}", p.fourcc, p.describe_value());
            }
        }
        _ => println!("properties:      none"),
    }
    println!(
        "keybag:          {}",
        if im4p.kbag.is_some() {
            "present"
        } else {
            "none"
        }
    );
    if let Some(present) = im4m_present {
        println!(
            "IM4M:            {}",
            if present { "present" } else { "absent" }
        );
    }
}

fn cmd_extract(
    input: &Path,
    output: Option<&Path>,
    decompress: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let im4p = load_im4p_from_any(input)?;
    let bytes: Vec<u8> = if decompress {
        compression::decompress_payload(&im4p.payload, im4p.compression())?
    } else {
        im4p.payload.clone()
    };
    write_output(output, &bytes)
}

fn write_output(output: Option<&Path>, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    match output {
        Some(path) => fs::write(path, bytes)?,
        None => {
            use std::io::Write;
            std::io::stdout().write_all(bytes)?;
        }
    }
    Ok(())
}

fn cmd_create(
    input: &Path,
    fourcc: &str,
    compress: CompressArg,
    description: &str,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = fs::read(input)?;
    let mut im4p = Im4p::new(fourcc, description, raw.clone());
    match compress {
        CompressArg::None => {}
        CompressArg::Lzfse => {
            let compressed = compression::lzfse_compress(&raw)?;
            im4p.payload = compressed;
            im4p.set_size_hint(raw.len() as i64);
        }
        CompressArg::Lzss => {
            let compressed = compression::lzss_compress(&raw)?;
            im4p.payload = compressed;
        }
    }
    fs::write(output, im4p.to_tlv_bytes())?;
    Ok(())
}

fn cmd_retype(input: &Path, fourcc: &str, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut im4p = load_im4p_from_any(input)?;
    im4p.fourcc = fourcc.to_string();
    fs::write(output, im4p.to_tlv_bytes())?;
    Ok(())
}

fn cmd_attach(
    im4p_path: &Path,
    im4m_path: Option<&Path>,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let im4p = load_im4p_from_any(im4p_path)?;
    let im4m = match im4m_path {
        Some(p) => {
            let data = fs::read(p)?;
            // Accept either a raw IM4M TLV or something already wrapped;
            // store its top-level TLV bytes untouched either way.
            let tlv = read_tlv(&data)?;
            if tlv.tag.number != universal::SEQUENCE || tlv.tag.class != Class::Universal {
                return Err("manifest file is not a valid top-level SEQUENCE".into());
            }
            Some(data)
        }
        None => None,
    };
    let img4 = Img4Like {
        im4p,
        im4m,
        im4r: None,
    };
    fs::write(output, img4.to_bytes())?;
    Ok(())
}
