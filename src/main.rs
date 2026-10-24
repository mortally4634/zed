//! ZedCompress CLI (`zed`).
//!
//! zed c <out> <inputs>... [-l 0-9] [-p PW] [-c rabbit|chacha20|aes] [--keyfile F]
//! zed x <archive> [outdir] [-p PW] [--keyfile F]
//! zed l <archive> [-p PW] [--keyfile F]
//! zed v <archive> [-p PW] [--keyfile F]
//! zed selftest

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zedcompress::{compress, extract, human, list, self_test, verify, Cipher, Format};

#[derive(Parser)]
#[command(name = "zed", version, about = "ZedCompress - solid LZMA archiver with authenticated encryption")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compress files/folders into an archive (.zed, .zip or .tar.xz)
    #[command(visible_alias = "c")]
    Compress {
        /// Output archive path (extension picks the format)
        output: PathBuf,
        /// Files and/or folders to add
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// Compression level 0-9 (0 = store, 9 = max). Default 9.
        #[arg(short, long, default_value_t = 9)]
        level: u32,
        /// Password (enables encryption; .zed only)
        #[arg(short, long)]
        password: Option<String>,
        /// Cipher for encryption
        #[arg(short, long, default_value = "rabbit")]
        cipher: String,
        /// Extra key file mixed into the password (both then required)
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    /// Extract an archive
    #[command(visible_alias = "x")]
    Extract {
        archive: PathBuf,
        /// Output directory (default: current directory)
        outdir: Option<PathBuf>,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    /// List archive contents without extracting
    #[command(visible_alias = "l")]
    List {
        archive: PathBuf,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    /// Verify archive integrity (and MAC, if encrypted) without extracting
    #[command(visible_alias = "v")]
    Verify {
        archive: PathBuf,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    /// Run RFC-vector + roundtrip + tamper self-tests
    Selftest,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Compress { output, inputs, level, password, cipher, keyfile } => {
            if level > 9 {
                bail!("level must be 0-9");
            }
            let fmt = Format::from_path(&output)?;
            let cipher = Cipher::parse(&cipher)
                .ok_or_else(|| anyhow::anyhow!("unknown cipher '{cipher}' (rabbit|chacha20|aes)"))?;
            if password.is_some() && !fmt.supports_encryption() {
                bail!("encryption is only supported for .zed archives");
            }
            let (orig, size) = compress(&inputs, &output, level, password.as_deref(),
                                        keyfile.as_deref(), cipher, fmt)?;
            let ratio = if size > 0 { orig as f64 / size as f64 } else { 0.0 };
            let saved = if orig > 0 { 100.0 * (1.0 - size as f64 / orig as f64) } else { 0.0 };
            let enc = if password.is_some() {
                format!("  · encrypted ({})", cipher.name())
            } else {
                String::new()
            };
            println!(
                "wrote {}  ({} → {}, ratio {:.1}×, saved {:.1}%{})",
                output.display(), human(orig as f64), human(size as f64), ratio, saved, enc
            );
        }
        Cmd::Extract { archive, outdir, password, keyfile } => {
            let out = outdir.unwrap_or_else(|| PathBuf::from("."));
            extract(&archive, &out, password.as_deref(), keyfile.as_deref())?;
            println!("extracted {} → {}", archive.display(), out.display());
        }
        Cmd::List { archive, password, keyfile } => {
            let items = list(&archive, password.as_deref(), keyfile.as_deref())?;
            let mut total = 0u64;
            for (name, size) in &items {
                total += size;
                println!("{:>12}  {}", human(*size as f64), name);
            }
            println!("— {} files, {} uncompressed", items.len(), human(total as f64));
        }
        Cmd::Verify { archive, password, keyfile } => {
            let n = verify(&archive, password.as_deref(), keyfile.as_deref())?;
            println!("OK — {} entries intact ({})", n, archive.display());
        }
        Cmd::Selftest => self_test()?,
    }
    Ok(())
}
