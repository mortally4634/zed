//! Recovery records (like WinRAR's) via Reed-Solomon parity.
//!
//! `protect` writes a sidecar `<archive>.rvz` holding parity shards computed
//! over the archive; `repair` uses them to rebuild data shards whose CRC no
//! longer matches, so an archive damaged by bit-rot or a bad sector can be
//! restored — up to the configured redundancy.
//!
//! Sidecar layout (little-endian):
//!   magic "RVZ1" | data_shards u32 | parity_shards u32 | shard_size u64 |
//!   orig_len u64 | crc32 x (data+parity) | parity shard bytes

use anyhow::{anyhow, bail, Context, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::fs;
use std::path::{Path, PathBuf};

const RVZ_MAGIC: &[u8; 4] = b"RVZ1";
const MAX_DATA_SHARDS: usize = 128; // GF(2^8): data + parity must stay <= 256
const MIN_SHARD: usize = 4096;
const HEADER: usize = 4 + 4 + 4 + 8 + 8; // magic,k,m,shard_size,orig_len

fn sidecar_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_owned();
    s.push(".rvz");
    PathBuf::from(s)
}

/// Create a recovery sidecar protecting ~`percent`% of the archive against loss.
/// Returns the sidecar path and the redundancy actually achieved (percent).
pub fn protect(archive: &Path, percent: u32) -> Result<(PathBuf, u32)> {
    let data = fs::read(archive).with_context(|| format!("reading {}", archive.display()))?;
    if data.is_empty() {
        bail!("cannot protect an empty file");
    }
    let pct = percent.clamp(1, 100);

    // Geometry: up to 128 data shards of >= 4 KiB; parity = pct% of data shards.
    let k = MAX_DATA_SHARDS.min(((data.len() + MIN_SHARD - 1) / MIN_SHARD).max(1));
    let shard_size = (data.len() + k - 1) / k;
    let mut m = ((k as u64 * pct as u64).div_ceil(100)).max(1) as usize;
    if k + m > 256 {
        m = 256 - k; // cap at the GF(2^8) ceiling
    }

    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(k + m);
    for i in 0..k {
        let start = i * shard_size;
        let end = (start + shard_size).min(data.len());
        let mut s = vec![0u8; shard_size];
        if start < data.len() {
            s[..end - start].copy_from_slice(&data[start..end]);
        }
        shards.push(s);
    }
    for _ in 0..m {
        shards.push(vec![0u8; shard_size]);
    }
    let rs = ReedSolomon::new(k, m).map_err(|e| anyhow!("reed-solomon init: {e:?}"))?;
    rs.encode(&mut shards).map_err(|e| anyhow!("reed-solomon encode: {e:?}"))?;

    let crcs: Vec<u32> = shards.iter().map(|s| crc32fast::hash(s)).collect();

    let mut out = Vec::with_capacity(HEADER + crcs.len() * 4 + m * shard_size);
    out.extend_from_slice(RVZ_MAGIC);
    out.extend_from_slice(&(k as u32).to_le_bytes());
    out.extend_from_slice(&(m as u32).to_le_bytes());
    out.extend_from_slice(&(shard_size as u64).to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    for c in &crcs {
        out.extend_from_slice(&c.to_le_bytes());
    }
    for s in &shards[k..] {
        out.extend_from_slice(s);
    }
    let sidecar = sidecar_path(archive);
    fs::write(&sidecar, &out)?;
    let achieved = ((m as f64 / k as f64) * 100.0).round() as u32;
    Ok((sidecar, achieved))
}

/// Repair `archive` in place using its `.rvz` sidecar. Returns the number of
/// shards that had to be reconstructed (0 = archive was already intact).
pub fn repair(archive: &Path) -> Result<usize> {
    let sidecar = sidecar_path(archive);
    let meta = fs::read(&sidecar)
        .with_context(|| format!("reading recovery file {}", sidecar.display()))?;
    if meta.len() < HEADER || &meta[..4] != RVZ_MAGIC {
        bail!("invalid or truncated recovery file");
    }
    let k = u32::from_le_bytes(meta[4..8].try_into().unwrap()) as usize;
    let m = u32::from_le_bytes(meta[8..12].try_into().unwrap()) as usize;
    let shard_size = u64::from_le_bytes(meta[12..20].try_into().unwrap()) as usize;
    let orig_len = u64::from_le_bytes(meta[20..28].try_into().unwrap()) as usize;
    let total = k + m;
    let crc_off = HEADER;
    let parity_off = crc_off + total * 4;
    if meta.len() < parity_off + m * shard_size {
        bail!("recovery file truncated");
    }
    let crcs: Vec<u32> = (0..total)
        .map(|i| u32::from_le_bytes(meta[crc_off + i * 4..crc_off + i * 4 + 4].try_into().unwrap()))
        .collect();

    let data = fs::read(archive).with_context(|| format!("reading {}", archive.display()))?;
    let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(total);
    let mut missing = 0usize;

    // Data shards from the (possibly corrupt) archive, checked against CRCs.
    for i in 0..k {
        let start = i * shard_size;
        let mut s = vec![0u8; shard_size];
        if start < data.len() {
            let end = (start + shard_size).min(data.len());
            s[..end - start].copy_from_slice(&data[start..end]);
        }
        if crc32fast::hash(&s) == crcs[i] {
            shards.push(Some(s));
        } else {
            shards.push(None);
            missing += 1;
        }
    }
    // Parity shards from the sidecar.
    for j in 0..m {
        let o = parity_off + j * shard_size;
        let s = meta[o..o + shard_size].to_vec();
        if crc32fast::hash(&s) == crcs[k + j] {
            shards.push(Some(s));
        } else {
            shards.push(None);
            missing += 1;
        }
    }

    if missing == 0 {
        return Ok(0); // already intact
    }
    if missing > m {
        bail!("too much damage: {missing} shards lost but only {m} parity shards available");
    }

    let rs = ReedSolomon::new(k, m).map_err(|e| anyhow!("reed-solomon init: {e:?}"))?;
    rs.reconstruct(&mut shards).map_err(|e| anyhow!("reed-solomon reconstruct: {e:?}"))?;

    let mut rebuilt = Vec::with_capacity(k * shard_size);
    for s in shards.iter().take(k) {
        rebuilt.extend_from_slice(s.as_ref().expect("data shard reconstructed"));
    }
    rebuilt.truncate(orig_len);
    fs::write(archive, &rebuilt)?;
    Ok(missing)
}
