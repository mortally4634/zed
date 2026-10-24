//! ZedCompress core library.
//!
//! Module map:
//!   rabbit   - Rabbit stream cipher (RFC 4503)
//!   crypto   - cipher selection, KDF, keystream trait, RFC self-check
//!   filters  - BCJ pre-filters + executable sniffing
//!   format   - the `.zed` container (tar -> LZMA -> encrypt-then-MAC) + xz_writer
//!   archive  - format dispatch, the public compress/extract/list/verify API
//!   recovery - Reed-Solomon recovery records (protect / repair)
//!   bench    - compression preset benchmark

mod archive;
mod bench;
mod crypto;
mod filters;
mod format;
mod rabbit;
mod recovery;

use anyhow::{bail, Result};
use std::fs;

pub use archive::{compress, extract, human, list, total_size, verify, Format};
pub use bench::{bench, BenchRow};
pub use crypto::Cipher;
pub use filters::Filter;
pub use format::is_encrypted;
pub use recovery::{protect, repair};

// --------------------------------- selftest --------------------------------
pub fn self_test() -> Result<()> {
    crypto::vectors_ok().map_err(anyhow::Error::msg)?;
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
        let (orig, size, _) = compress(&inputs, &arc, 6, pw, None, cipher, Filter::Auto, 1, Format::Zed)?;
        let rest = dir.join(format!("restored_{label}"));
        extract(&arc, &rest, pw, None)?;
        for rel in ["payload/zeros.bin", "payload/text.txt", "payload/random.bin"] {
            if fs::read(payload.parent().unwrap().join(rel))? != fs::read(rest.join(rel))? {
                bail!("[{label}] roundtrip mismatch: {rel}");
            }
        }
        println!("[selftest] roundtrip {label}: OK  {} -> {}", human(orig as f64), human(size as f64));
    }

    // Multithreaded roundtrip must match single-threaded content.
    let mt = dir.join("out_mt.zed");
    compress(&inputs, &mt, 6, None, None, Cipher::Rabbit, Filter::None, 4, Format::Zed)?;
    extract(&mt, &dir.join("restored_mt"), None, None)?;
    if fs::read(payload.join("text.txt"))? != fs::read(dir.join("restored_mt/payload/text.txt"))? {
        bail!("multithreaded roundtrip mismatch");
    }
    println!("[selftest] multithreaded (4 threads) roundtrip: OK");

    // BCJ filter: an executable-like payload must auto-select x86 and roundtrip.
    let exe_dir = dir.join("exe");
    fs::create_dir_all(&exe_dir)?;
    let mut fake_exe = b"MZ".to_vec();
    fake_exe.extend((0..200_000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8));
    fs::write(exe_dir.join("app.exe"), &fake_exe)?;
    let farc = dir.join("filtered.zed");
    let (_, _, used) = compress(&[exe_dir.clone()], &farc, 6, None, None, Cipher::Rabbit, Filter::Auto, 1, Format::Zed)?;
    if used != Filter::X86 {
        bail!("auto filter did not select x86 for an executable (got {used:?})");
    }
    extract(&farc, &dir.join("exe_out"), None, None)?;
    if fs::read(dir.join("exe_out/exe/app.exe"))? != fake_exe {
        bail!("BCJ-filtered roundtrip mismatch");
    }
    println!("[selftest] BCJ filter (auto->x86) roundtrip: OK");

    // wrong password rejected
    let enc = dir.join("out_rabbit.zed");
    if extract(&enc, &dir.join("wrong"), Some("nope"), None).is_ok() {
        bail!("wrong password was NOT rejected");
    }
    println!("[selftest] wrong-password rejection: OK");

    // tamper detection: flip one ciphertext byte
    let mut data = fs::read(&enc)?;
    data[8 + 36 + 5] ^= 1;
    let tampered = dir.join("tampered.zed");
    fs::write(&tampered, &data)?;
    if extract(&tampered, &dir.join("tamp"), Some("correct horse battery staple"), None).is_ok() {
        bail!("tampering was NOT detected");
    }
    println!("[selftest] tamper detection: OK");

    // recovery records: protect, corrupt a block, repair, re-verify
    let prot = dir.join("out_plain.zed");
    let (_sidecar, pct) = protect(&prot, 20)?;
    let mut d = fs::read(&prot)?;
    let mid = d.len() / 2;
    for b in d.iter_mut().skip(mid).take(3000) {
        *b ^= 0xFF; // simulate a damaged sector
    }
    fs::write(&prot, &d)?;
    if verify(&prot, None, None).is_ok() {
        // may or may not error depending on where damage lands; force the issue
    }
    let repaired = repair(&prot)?;
    let n = verify(&prot, None, None)?;
    println!("[selftest] recovery ({pct}% parity): corrupted, repaired {repaired} shard(s), re-verified {n} entries: OK");

    // list + verify
    let items = list(&enc, Some("correct horse battery staple"), None)?;
    let v = verify(&enc, Some("correct horse battery staple"), None)?;
    println!("[selftest] list/verify: OK ({} files listed, {v} verified)", items.len());

    let _ = fs::remove_dir_all(&dir);
    println!("[selftest] ALL PASS");
    Ok(())
}
