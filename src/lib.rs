//! ZedCompress core library.
//!
//! .zed format (v2): solid tar -> optional LZMA -> optional encryption.
//!   [0:4]  magic "ZED1"
//!   [4]    version (2)
//!   [5]    comp     0 = store, 1 = lzma
//!   [6]    cipher   0 = none, 1 = rabbit, 2 = chacha20, 3 = aes256-ctr
//!   [7]    reserved
//!   if encrypted: [8:12] kdf_iters(BE u32) [12:28] salt [28:44] iv
//!   then ciphertext, and the final 32 bytes are the HMAC-SHA256 tag,
//!   which authenticates the headers + ciphertext and is checked before
//!   anything is decrypted (encrypt-then-MAC).

mod crypto;

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write, BufWriter};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use xz2::read::XzDecoder;
use xz2::write::XzEncoder;

pub use crypto::Cipher;
use crypto::{derive_keys, make_keystream, Keystream};

type HmacSha256 = Hmac<Sha256>;
const ITERS: u32 = 200_000;

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

/// True if `archive` is an encrypted .zed (so the caller can prompt for a
/// password). Non-.zed formats are never encrypted here.
pub fn is_encrypted(archive: &Path) -> Result<bool> {
    if Format::from_path(archive)? != Format::Zed {
        return Ok(false);
    }
    let mut f = File::open(archive)?;
    let mut core = [0u8; 8];
    f.read_exact(&mut core)
        .map_err(|_| anyhow!("{} is not a valid .zed file", archive.display()))?;
    if &core[..4] != b"ZED1" {
        bail!("{} is not a valid .zed file (bad magic)", archive.display());
    }
    Ok(core[4] >= 2 && core[6] != 0)
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

// ------------------------- encrypt-then-MAC plumbing -----------------------
struct EncWriter<W: Write> {
    inner: W,
    cipher: Box<dyn Keystream>,
    mac: HmacSha256,
}
impl<W: Write> Write for EncWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut tmp = buf.to_vec();
        self.cipher.xor(&mut tmp);
        self.mac.update(&tmp);
        self.inner.write_all(&tmp)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

enum Sink<W: Write> {
    Plain(W),
    Enc(EncWriter<W>),
}
impl<W: Write> Write for Sink<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Sink::Plain(w) => w.write(buf),
            Sink::Enc(e) => e.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Sink::Plain(w) => w.flush(),
            Sink::Enc(e) => e.flush(),
        }
    }
}
impl<W: Write> Sink<W> {
    /// Finish: for encrypted sinks, append the (unencrypted) MAC tag.
    fn finalize(self) -> io::Result<()> {
        match self {
            Sink::Plain(mut w) => w.flush(),
            Sink::Enc(e) => {
                let EncWriter { mut inner, mac, cipher } = e;
                drop(cipher);
                let tag = mac.finalize().into_bytes();
                inner.write_all(&tag)?;
                inner.flush()
            }
        }
    }
}

struct DecReader<R: Read> {
    inner: R,
    cipher: Box<dyn Keystream>,
    remaining: u64,
}
impl<R: Read> Read for DecReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.remaining) as usize;
        let got = self.inner.read(&mut buf[..n])?;
        self.cipher.xor(&mut buf[..got]);
        self.remaining -= got as u64;
        Ok(got)
    }
}

fn xz_writer<W: Write>(w: W, level: u32) -> Result<XzEncoder<W>> {
    // preset 9 | EXTREME for the top level; plain preset otherwise.
    let preset = if level >= 9 { 9 | 0x8000_0000 } else { level };
    let stream = xz2::stream::Stream::new_easy_encoder(preset, xz2::stream::Check::Crc64)
        .map_err(|e| anyhow!("xz init failed: {e}"))?;
    Ok(XzEncoder::new_stream(w, stream))
}

// ------------------------------- tar helpers -------------------------------
fn add_inputs<W: Write>(b: &mut tar::Builder<W>, inputs: &[PathBuf],
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

// ------------------------------- .zed write --------------------------------
fn compress_zed(inputs: &[PathBuf], out: &Path, level: u32, password: Option<&str>,
                keyfile: Option<&[u8]>, cipher: Cipher, pb: &indicatif::ProgressBar) -> Result<u64> {
    let comp: u8 = if level == 0 { 0 } else { 1 };
    let encrypt = password.map(|p| !p.is_empty()).unwrap_or(false);
    let cipher_id = if encrypt { cipher.id() } else { 0 };

    let mut file = BufWriter::new(File::create(out)?);
    let mut hdr = vec![b'Z', b'E', b'D', b'1', 2, comp, cipher_id, 0];

    let sink: Sink<BufWriter<File>> = if encrypt {
        use rand::RngCore;
        let mut salt = [0u8; 16];
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut iv);
        hdr.extend_from_slice(&ITERS.to_be_bytes());
        hdr.extend_from_slice(&salt);
        hdr.extend_from_slice(&iv);
        let (ek, mk) = derive_keys(password.unwrap(), keyfile, &salt, ITERS);
        let mut mac = HmacSha256::new_from_slice(&mk).unwrap();
        mac.update(&hdr);
        file.write_all(&hdr)?;
        Sink::Enc(EncWriter { inner: file, cipher: make_keystream(cipher, &ek, &iv), mac })
    } else {
        file.write_all(&hdr)?;
        Sink::Plain(file)
    };

    if comp == 1 {
        let xz = xz_writer(sink, level)?;
        let mut b = tar::Builder::new(xz);
        add_inputs(&mut b, inputs, pb)?;
        let xz = b.into_inner()?;
        let sink = xz.finish()?;
        sink.finalize()?;
    } else {
        let mut b = tar::Builder::new(sink);
        add_inputs(&mut b, inputs, pb)?;
        let sink = b.into_inner()?;
        sink.finalize()?;
    }
    Ok(fs::metadata(out)?.len())
}

/// Build the decrypted + decompressed tar byte stream for a .zed, verifying
/// the MAC first for encrypted archives.
fn zed_tar_stream(archive: &Path, password: Option<&str>, keyfile: Option<&[u8]>)
    -> Result<Box<dyn Read>>
{
    let mut f = File::open(archive)?;
    let mut core = [0u8; 8];
    f.read_exact(&mut core)?;
    if &core[..4] != b"ZED1" {
        bail!("not a valid .zed file (bad magic)");
    }
    let (version, comp, cipher_id) = (core[4], core[5], core[6]);
    if version != 2 {
        bail!("unsupported .zed version {version}");
    }
    if cipher_id == 0 {
        return Ok(if comp == 1 {
            Box::new(XzDecoder::new(f))
        } else {
            Box::new(f)
        });
    }

    let password = password.ok_or_else(|| anyhow!("archive is encrypted; a password is required (-p)"))?;
    let mut crypto = [0u8; 36];
    f.read_exact(&mut crypto)?;
    let iters = u32::from_be_bytes(crypto[..4].try_into().unwrap());
    let salt = crypto[4..20].to_vec();
    let iv: [u8; 16] = crypto[20..36].try_into().unwrap();
    let total = fs::metadata(archive)?.len();
    let ct_len = total
        .checked_sub(8 + 36 + 32)
        .ok_or_else(|| anyhow!("corrupted .zed (too short)"))?;
    let (ek, mk) = derive_keys(password, keyfile, &salt, iters);

    // Pass 1: verify MAC over headers + ciphertext BEFORE decrypting.
    {
        let mut f1 = File::open(archive)?;
        let mut head = [0u8; 44];
        f1.read_exact(&mut head)?;
        let mut mac = HmacSha256::new_from_slice(&mk).unwrap();
        mac.update(&head);
        let mut remaining = ct_len;
        let mut buf = vec![0u8; 1 << 16];
        while remaining > 0 {
            let n = (buf.len() as u64).min(remaining) as usize;
            f1.read_exact(&mut buf[..n])?;
            mac.update(&buf[..n]);
            remaining -= n as u64;
        }
        let mut tag = [0u8; 32];
        f1.read_exact(&mut tag)?;
        mac.verify_slice(&tag)
            .map_err(|_| anyhow!("wrong password, or the file has been tampered with"))?;
    }

    // Pass 2: decrypt (MAC proven) + decompress.
    let mut f2 = File::open(archive)?;
    f2.seek(SeekFrom::Start(44))?;
    let cipher = Cipher::from_id(cipher_id).ok_or_else(|| anyhow!("unknown cipher id {cipher_id}"))?;
    let dr = DecReader { inner: f2, cipher: make_keystream(cipher, &ek, &iv), remaining: ct_len };
    Ok(if comp == 1 {
        Box::new(XzDecoder::new(dr))
    } else {
        Box::new(dr)
    })
}

// ------------------------- other formats (no crypto) -----------------------
fn compress_tarxz(inputs: &[PathBuf], out: &Path, level: u32, pb: &indicatif::ProgressBar) -> Result<u64> {
    let file = BufWriter::new(File::create(out)?);
    let xz = xz_writer(file, level)?;
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
                    let mut src = File::open(path)?;
                    io::copy(&mut src, &mut zw)?;
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

pub fn compress(inputs: &[PathBuf], out: &Path, level: u32, password: Option<&str>,
                keyfile: Option<&Path>, cipher: Cipher, format: Format) -> Result<(u64, u64)> {
    let original = total_size(inputs);
    let pb = bar(original);
    let kf = read_keyfile(keyfile)?;
    let size = match format {
        Format::Zed => compress_zed(inputs, out, level, password, kf.as_deref(), cipher, &pb)?,
        Format::TarXz => compress_tarxz(inputs, out, level, &pb)?,
        Format::Zip => compress_zip(inputs, out, level, &pb)?,
    };
    pb.finish_and_clear();
    Ok((original, size))
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

fn bar(total: u64) -> indicatif::ProgressBar {
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

// --------------------------------- selftest --------------------------------
pub fn self_test() -> Result<()> {
    crypto::vectors_ok().map_err(|e| anyhow!(e))?;
    println!("[selftest] cipher RFC vectors: OK (Rabbit RFC4503, ChaCha20 RFC8439)");

    let dir = std::env::temp_dir().join(format!("zed_selftest_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let payload = dir.join("payload");
    fs::create_dir_all(&payload)?;
    fs::write(payload.join("zeros.bin"), vec![0u8; 2_000_000])?;
    fs::write(payload.join("text.txt"), "hello world\n".repeat(10_000))?;
    let mut rnd = vec![0u8; 50_000];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut rnd);
    fs::write(payload.join("random.bin"), &rnd)?;

    let inputs = vec![payload.clone()];
    for (label, pw, cipher) in [
        ("plain", None, Cipher::Rabbit),
        ("rabbit", Some("correct horse battery staple"), Cipher::Rabbit),
        ("chacha20", Some("correct horse battery staple"), Cipher::ChaCha20),
        ("aes256", Some("correct horse battery staple"), Cipher::Aes256Ctr),
    ] {
        let arc = dir.join(format!("out_{label}.zed"));
        let (orig, size) = compress(&inputs, &arc, 6, pw, None, cipher, Format::Zed)?;
        let rest = dir.join(format!("restored_{label}"));
        extract(&arc, &rest, pw, None)?;
        for rel in ["payload/zeros.bin", "payload/text.txt", "payload/random.bin"] {
            let a = fs::read(payload.parent().unwrap().join(rel))?;
            let b = fs::read(rest.join(rel))?;
            if a != b {
                bail!("[{label}] roundtrip mismatch: {rel}");
            }
        }
        println!("[selftest] roundtrip {label}: OK  {} -> {}", human(orig as f64), human(size as f64));
    }

    // wrong password rejected
    let enc = dir.join("out_rabbit.zed");
    if extract(&enc, &dir.join("wrong"), Some("nope"), None).is_ok() {
        bail!("wrong password was NOT rejected");
    }
    println!("[selftest] wrong-password rejection: OK");

    // tamper detection: flip one ciphertext byte
    let mut data = fs::read(&enc)?;
    let i = 8 + 36 + 5;
    data[i] ^= 1;
    let tampered = dir.join("tampered.zed");
    fs::write(&tampered, &data)?;
    if extract(&tampered, &dir.join("tamp"), Some("correct horse battery staple"), None).is_ok() {
        bail!("tampering was NOT detected");
    }
    println!("[selftest] tamper detection: OK");

    // list + verify
    let items = list(&enc, Some("correct horse battery staple"), None)?;
    let n = verify(&enc, Some("correct horse battery staple"), None)?;
    println!("[selftest] list/verify: OK ({} files listed, {} verified)", items.len(), n);

    let _ = fs::remove_dir_all(&dir);
    println!("[selftest] ALL PASS");
    Ok(())
}
