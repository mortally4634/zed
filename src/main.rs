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
        /// Password (enables encryption; .zed only). Omit with -e to be prompted.
        #[arg(short, long)]
        password: Option<String>,
        /// Encrypt, prompting for the password interactively (hidden input)
        #[arg(short, long)]
        encrypt: bool,
        /// Cipher for encryption
        #[arg(short, long, default_value = "rabbit")]
        cipher: String,
        /// Extra key file mixed into the password (both then required)
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// Overwrite the output file if it already exists
        #[arg(short, long)]
        force: bool,
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

/// Prompt for a new password twice (hidden) and require the two to match.
fn prompt_new_password() -> Result<String> {
    let p1 = rpassword::prompt_password("Password: ")
        .map_err(|e| anyhow::anyhow!("could not read password: {e}"))?;
    if p1.is_empty() {
        bail!("password must not be empty");
    }
    let p2 = rpassword::prompt_password("Confirm:  ")
        .map_err(|e| anyhow::anyhow!("could not read password: {e}"))?;
    if p1 != p2 {
        bail!("passwords did not match");
    }
    Ok(p1)
}

/// Resolve the password for reading: use the supplied one, else prompt (hidden)
/// only if the archive is actually encrypted.
fn resolve_read_password(archive: &std::path::Path, supplied: Option<String>) -> Result<Option<String>> {
    if supplied.is_some() {
        return Ok(supplied);
    }
    if zedcompress::is_encrypted(archive)? {
        let p = rpassword::prompt_password("Password: ")
            .map_err(|e| anyhow::anyhow!("could not read password: {e}"))?;
        return Ok(Some(p));
    }
    Ok(None)
}

fn run() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Compress { output, inputs, level, password, encrypt, cipher, keyfile, force } => {
            if level > 9 {
                bail!("level must be 0-9");
            }
            if output.exists() && !force {
                bail!("{} already exists (use --force to overwrite)", output.display());
            }
            let fmt = Format::from_path(&output)?;
            let cipher = Cipher::parse(&cipher)
                .ok_or_else(|| anyhow::anyhow!("unknown cipher '{cipher}' (rabbit|chacha20|aes)"))?;
            if (password.is_some() || encrypt) && !fmt.supports_encryption() {
                bail!("encryption is only supported for .zed archives");
            }
            // -p sets it directly; -e (without -p) prompts with confirmation.
            let password = match (password, encrypt) {
                (Some(p), _) => Some(p),
                (None, true) => Some(prompt_new_password()?),
                (None, false) => None,
            };
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
            let password = resolve_read_password(&archive, password)?;
            let out = outdir.unwrap_or_else(|| PathBuf::from("."));
            extract(&archive, &out, password.as_deref(), keyfile.as_deref())?;
            println!("extracted {} → {}", archive.display(), out.display());
        }
        Cmd::List { archive, password, keyfile } => {
            let password = resolve_read_password(&archive, password)?;
            let items = list(&archive, password.as_deref(), keyfile.as_deref())?;
            let mut total = 0u64;
            for (name, size) in &items {
                total += size;
                println!("{:>12}  {}", human(*size as f64), name);
            }
            println!("— {} files, {} uncompressed", items.len(), human(total as f64));
        }
        Cmd::Verify { archive, password, keyfile } => {
            let password = resolve_read_password(&archive, password)?;
            let n = verify(&archive, password.as_deref(), keyfile.as_deref())?;
            println!("OK — {} entries intact ({})", n, archive.display());
        }
        Cmd::Selftest => self_test()?,
    }
    Ok(())
}
