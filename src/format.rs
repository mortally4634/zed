//! The `.zed` container: solid tar -> optional LZMA -> optional encryption.
//!   [0:4]  magic "ZED1"
//!   [4]    version (2)
//!   [5]    comp     0 = store, 1 = lzma
//!   [6]    cipher   0 = none, 1 = rabbit, 2 = chacha20, 3 = aes256-ctr
//!   [7]    reserved
//!   if encrypted: [8:12] kdf_iters(BE u32) [12:28] salt [28:44] iv
//!   then ciphertext, and the final 32 bytes are the HMAC-SHA256 tag,
//!   verified before anything is decrypted (encrypt-then-MAC).
//!
//! Also holds `xz_writer`, shared with the plain `.tar.xz` path in `archive`.

use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use xz2::read::XzDecoder;
use xz2::write::XzEncoder;

use crate::archive::{add_inputs, Format};
use crate::crypto::{derive_keys, make_keystream, Cipher, Keystream};
use crate::filters::Filter;

pub(crate) type HmacSha256 = Hmac<Sha256>;
pub(crate) const ITERS: u32 = 200_000;

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

/// Build an LZMA/xz encoder: preset 9 | EXTREME at the top level, an optional
/// BCJ pre-filter, and multithreaded block encoding when `threads > 1`.
pub(crate) fn xz_writer<W: Write>(w: W, level: u32, filter: Filter, threads: u32)
    -> Result<XzEncoder<W>>
{
    let preset = if level >= 9 { 9 | 0x8000_0000 } else { level };
    let opts = xz2::stream::LzmaOptions::new_preset(preset)
        .map_err(|e| anyhow!("xz options failed: {e}"))?;
    let mut filters = xz2::stream::Filters::new();
    filter.apply(&mut filters); // optional BCJ pre-filter (Auto already resolved)
    filters.lzma2(&opts); // compression filter must come last in the chain
    let stream = if threads > 1 {
        let mut mb = xz2::stream::MtStreamBuilder::new();
        mb.threads(threads).filters(filters).check(xz2::stream::Check::Crc64);
        mb.encoder().map_err(|e| anyhow!("xz mt init failed: {e}"))?
    } else {
        xz2::stream::Stream::new_stream_encoder(&filters, xz2::stream::Check::Crc64)
            .map_err(|e| anyhow!("xz init failed: {e}"))?
    };
    Ok(XzEncoder::new_stream(w, stream))
}

// ------------------------------- .zed write --------------------------------
#[allow(clippy::too_many_arguments)]
pub(crate) fn compress_zed(inputs: &[std::path::PathBuf], out: &Path, level: u32,
                           password: Option<&str>, keyfile: Option<&[u8]>, cipher: Cipher,
                           filter: Filter, threads: u32, pb: &indicatif::ProgressBar) -> Result<u64> {
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
        let xz = xz_writer(sink, level, filter, threads)?;
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

/// Build the decrypted + decompressed tar byte stream for a .zed, verifying the
/// MAC first for encrypted archives.
pub(crate) fn zed_tar_stream(archive: &Path, password: Option<&str>, keyfile: Option<&[u8]>)
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
