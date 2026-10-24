//! Format dispatch and the multi-format public API (compress/extract/list/verify).

use anyhow::{anyhow, bail, Context, Result};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use xz2::read::XzDecoder;

use crate::crypto::Cipher;
use crate::filters::{sniff_executable, Filter};
use crate::format::{compress_zed, xz_writer, zed_tar_stream};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Zed,
    Zip,
    TarXz,
}

impl Format {
    pub fn from_path(p: &Path) -> Result<Format> {
        let s = p.to_string_lossy().to_ascii_lowercase();
        if s.ends_with(".zed") {
            Ok(Format::Zed)
        } else if s.ends_with(".zip") {
            Ok(Format::Zip)
        } else if s.ends_with(".tar.xz") || s.ends_with(".txz") {
            Ok(Format::TarXz)
        } else {
            bail!("unknown archive extension for {} (use .zed, .zip or .tar.xz)", p.display())
        }
    }
    pub fn supports_encryption(self) -> bool {
        matches!(self, Format::Zed)
    }
}

// ---------------------------- byte accounting ------------------------------
pub fn total_size(inputs: &[PathBuf]) -> u64 {
    let mut n = 0;
    for p in inputs {
        if p.is_dir() {
            for e in WalkDir::new(p).into_iter().flatten() {
                if e.file_type().is_file() {
                    n += e.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
        } else if let Ok(m) = fs::metadata(p) {
            n += m.len();
        }
    }
    n
}

pub fn human(mut n: f64) -> String {
    for unit in ["B", "KB", "MB", "GB", "TB"] {
        if n < 1024.0 || unit == "TB" {
            return if unit == "B" {
                format!("{n:.0} {unit}")
            } else {
                format!("{n:.1} {unit}")
            };
        }
        n /= 1024.0;
    }
    unreachable!()
}

pub(crate) fn bar(total: u64) -> indicatif::ProgressBar {
    let pb = indicatif::ProgressBar::new(total.max(1));
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "  {bar:32.cyan/blue} {bytes}/{total_bytes}  {bytes_per_sec}",
        )
        .unwrap()
        .progress_chars("█▉ "),
    );
    pb
}

pub(crate) fn add_inputs<W: Write>(b: &mut tar::Builder<W>, inputs: &[PathBuf],
                                   pb: &indicatif::ProgressBar) -> Result<()> {
    for p in inputs {
        if p.is_dir() {
            let parent = p.parent().unwrap_or_else(|| Path::new(""));
            for entry in WalkDir::new(p).sort_by_file_name() {
                let e = entry?;
                let path = e.path();
                let rel = path.strip_prefix(parent).unwrap_or(path);
                if e.file_type().is_dir() {
                    b.append_dir(rel, path)?;
                } else if e.file_type().is_file() {
                    b.append_path_with_name(path, rel)
                        .with_context(|| format!("adding {}", path.display()))?;
                    pb.inc(fs::metadata(path).map(|m| m.len()).unwrap_or(0));
                }
            }
        } else {
            let name = p.file_name().ok_or_else(|| anyhow!("bad path {}", p.display()))?;
            b.append_path_with_name(p, name)?;
            pb.inc(fs::metadata(p).map(|m| m.len()).unwrap_or(0));
        }
    }
    Ok(())
}

fn compress_tarxz(inputs: &[PathBuf], out: &Path, level: u32, filter: Filter, threads: u32,
                  pb: &indicatif::ProgressBar) -> Result<u64> {
    let file = std::io::BufWriter::new(File::create(out)?);
    let xz = xz_writer(file, level, filter, threads)?;
    let mut b = tar::Builder::new(xz);
    add_inputs(&mut b, inputs, pb)?;
    b.into_inner()?.finish()?;
    Ok(fs::metadata(out)?.len())
}

fn compress_zip(inputs: &[PathBuf], out: &Path, level: u32, pb: &indicatif::ProgressBar) -> Result<u64> {
    let file = File::create(out)?;
    let mut zw = zip::ZipWriter::new(file);
    let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(level as i64));
    for p in inputs {
        if p.is_dir() {
            let parent = p.parent().unwrap_or_else(|| Path::new(""));
            for entry in WalkDir::new(p).sort_by_file_name() {
                let e = entry?;
                let path = e.path();
                let rel = path.strip_prefix(parent).unwrap_or(path).to_string_lossy().replace('\\', "/");
                if e.file_type().is_file() {
                    zw.start_file(rel, opts)?;
                    io::copy(&mut File::open(path)?, &mut zw)?;
                    pb.inc(fs::metadata(path).map(|m| m.len()).unwrap_or(0));
                }
            }
        } else {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            zw.start_file(name, opts)?;
            io::copy(&mut File::open(p)?, &mut zw)?;
            pb.inc(fs::metadata(p).map(|m| m.len()).unwrap_or(0));
        }
    }
    zw.finish()?;
    Ok(fs::metadata(out)?.len())
}

// -------------------------------- public API -------------------------------
fn read_keyfile(keyfile: Option<&Path>) -> Result<Option<Vec<u8>>> {
    keyfile.map(|p| fs::read(p).with_context(|| format!("reading keyfile {}", p.display()))).transpose()
}

#[allow(clippy::too_many_arguments)]
pub fn compress(inputs: &[PathBuf], out: &Path, level: u32, password: Option<&str>,
                keyfile: Option<&Path>, cipher: Cipher, filter: Filter, threads: u32,
                format: Format) -> Result<(u64, u64, Filter)> {
    let original = total_size(inputs);
    let pb = bar(original);
    let kf = read_keyfile(keyfile)?;
    // Resolve Auto now so we can report the filter actually used.
    let filter = match filter {
        Filter::Auto if level > 0 => {
            if sniff_executable(inputs) { Filter::X86 } else { Filter::None }
        }
        Filter::Auto => Filter::None,
        f => f,
    };
    let size = match format {
        Format::Zed => compress_zed(inputs, out, level, password, kf.as_deref(), cipher, filter, threads, &pb)?,
        Format::TarXz => compress_tarxz(inputs, out, level, filter, threads, &pb)?,
        Format::Zip => compress_zip(inputs, out, level, &pb)?, // zip: no LZMA filters
    };
    pb.finish_and_clear();
    Ok((original, size, filter))
}

pub fn extract(archive: &Path, outdir: &Path, password: Option<&str>, keyfile: Option<&Path>) -> Result<()> {
    fs::create_dir_all(outdir)?;
    let kf = read_keyfile(keyfile)?;
    match Format::from_path(archive)? {
        Format::Zed => {
            let r = zed_tar_stream(archive, password, kf.as_deref())?;
            tar::Archive::new(r).unpack(outdir)?; // tar crate guards path traversal
        }
        Format::TarXz => {
            tar::Archive::new(XzDecoder::new(File::open(archive)?)).unpack(outdir)?;
        }
        Format::Zip => {
            let mut z = zip::ZipArchive::new(File::open(archive)?)?;
            for i in 0..z.len() {
                let mut e = z.by_index(i)?;
                let rel = match e.enclosed_name() {
                    Some(p) => p.to_owned(),
                    None => bail!("blocked unsafe path in zip: {}", e.name()),
                };
                let target = outdir.join(rel);
                if e.is_dir() {
                    fs::create_dir_all(&target)?;
                } else {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    io::copy(&mut e, &mut File::create(&target)?)?;
                }
            }
        }
    }
    Ok(())
}

pub fn list(archive: &Path, password: Option<&str>, keyfile: Option<&Path>) -> Result<Vec<(String, u64)>> {
    let kf = read_keyfile(keyfile)?;
    let mut out = Vec::new();
    match Format::from_path(archive)? {
        Format::Zed | Format::TarXz => {
            let r: Box<dyn Read> = match Format::from_path(archive)? {
                Format::Zed => zed_tar_stream(archive, password, kf.as_deref())?,
                _ => Box::new(XzDecoder::new(File::open(archive)?)),
            };
            let mut a = tar::Archive::new(r);
            for e in a.entries()? {
                let e = e?;
                if e.header().entry_type().is_file() {
                    out.push((e.path()?.to_string_lossy().into_owned(), e.header().size()?));
                }
            }
        }
        Format::Zip => {
            let mut z = zip::ZipArchive::new(File::open(archive)?)?;
            for i in 0..z.len() {
                let e = z.by_index(i)?;
                if !e.is_dir() {
                    out.push((e.name().to_string(), e.size()));
                }
            }
        }
    }
    Ok(out)
}

/// Returns the number of entries that read back cleanly (CRC/MAC validated).
pub fn verify(archive: &Path, password: Option<&str>, keyfile: Option<&Path>) -> Result<u64> {
    let kf = read_keyfile(keyfile)?;
    let mut n = 0u64;
    match Format::from_path(archive)? {
        Format::Zed | Format::TarXz => {
            let r: Box<dyn Read> = match Format::from_path(archive)? {
                Format::Zed => zed_tar_stream(archive, password, kf.as_deref())?, // MAC checked here
                _ => Box::new(XzDecoder::new(File::open(archive)?)),
            };
            let mut a = tar::Archive::new(r);
            for e in a.entries()? {
                let mut e = e?;
                io::copy(&mut e, &mut io::sink())?; // forces full decompress (xz CRC)
                n += 1;
            }
        }
        Format::Zip => {
            let mut z = zip::ZipArchive::new(File::open(archive)?)?;
            for i in 0..z.len() {
                let mut e = z.by_index(i)?;
                io::copy(&mut e, &mut io::sink())?; // zip verifies per-entry CRC32
                n += 1;
            }
        }
    }
    Ok(n)
}
