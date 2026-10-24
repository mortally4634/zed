//! Ciphers and key derivation for the .zed format.
//!
//! All three ciphers run as a keystream under encrypt-then-MAC (HMAC-SHA256);
//! keys come from a password (and optional keyfile) via PBKDF2-HMAC-SHA256.
//! Rabbit is hand-written (no mainstream crate) and verified against RFC 4503;
//! ChaCha20 and AES-256-CTR come from the audited RustCrypto crates.

use cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    Rabbit,
    ChaCha20,
    Aes256Ctr,
}

impl Cipher {
    pub fn id(self) -> u8 {
        match self {
            Cipher::Rabbit => 1,
            Cipher::ChaCha20 => 2,
            Cipher::Aes256Ctr => 3,
        }
    }
    pub fn from_id(id: u8) -> Option<Cipher> {
        match id {
            1 => Some(Cipher::Rabbit),
            2 => Some(Cipher::ChaCha20),
            3 => Some(Cipher::Aes256Ctr),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Cipher::Rabbit => "rabbit",
            Cipher::ChaCha20 => "chacha20",
            Cipher::Aes256Ctr => "aes256-ctr",
        }
    }
    pub fn parse(s: &str) -> Option<Cipher> {
        match s.to_ascii_lowercase().as_str() {
            "rabbit" => Some(Cipher::Rabbit),
            "chacha20" | "chacha" => Some(Cipher::ChaCha20),
            "aes" | "aes256" | "aes256-ctr" | "aes-256-ctr" => Some(Cipher::Aes256Ctr),
            _ => None,
        }
    }
}

/// Anything that can XOR a buffer with its keystream, maintaining state across
/// calls so it can be driven over a stream in arbitrary chunk sizes.
pub trait Keystream {
    fn xor(&mut self, buf: &mut [u8]);
}

/// Adapter so any RustCrypto `StreamCipher` satisfies `Keystream`.
struct CrateCipher<C: StreamCipher>(C);
impl<C: StreamCipher> Keystream for CrateCipher<C> {
    fn xor(&mut self, buf: &mut [u8]) {
        self.0.apply_keystream(buf);
    }
}

pub fn make_keystream(c: Cipher, enc_key: &[u8; 32], iv: &[u8; 16]) -> Box<dyn Keystream> {
    match c {
        Cipher::Rabbit => {
            let mut k = [0u8; 16];
            k.copy_from_slice(&enc_key[..16]);
            let mut i = [0u8; 8];
            i.copy_from_slice(&iv[..8]);
            Box::new(Rabbit::new(&k, Some(&i)))
        }
        Cipher::ChaCha20 => {
            let key = chacha20::Key::from_slice(enc_key);
            let nonce = chacha20::Nonce::from_slice(&iv[..12]);
            Box::new(CrateCipher(chacha20::ChaCha20::new(key, nonce)))
        }
        Cipher::Aes256Ctr => {
            type AesCtr = ctr::Ctr128BE<aes::Aes256>;
            let c = AesCtr::new_from_slices(enc_key, iv).expect("valid aes key/iv length");
            Box::new(CrateCipher(c))
        }
    }
}

/// PBKDF2-HMAC-SHA256 -> (enc_key, mac_key). An optional keyfile is folded in
/// by appending its SHA-256 to the password material (so both are required).
pub fn derive_keys(password: &str, keyfile: Option<&[u8]>, salt: &[u8], iters: u32)
    -> ([u8; 32], [u8; 32])
{
    let mut material = password.as_bytes().to_vec();
    if let Some(kf) = keyfile {
        material.extend_from_slice(&Sha256::digest(kf));
    }
    let mut dk = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha256>(&material, salt, iters, &mut dk);
    material.zeroize();
    let mut ek = [0u8; 32];
    let mut mk = [0u8; 32];
    ek.copy_from_slice(&dk[..32]);
    mk.copy_from_slice(&dk[32..]);
    dk.zeroize();
    (ek, mk)
}

// ------------------------------- Rabbit ------------------------------------
// Ported from the RFC-4503-verified reference. ponytail: keystream is produced
// per 16-byte block and buffered; per-byte XOR is the ceiling, switch to
// block-wise XOR if throughput ever matters.
const RABBIT_A: [u32; 8] = [
    0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
    0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3,
];

pub struct Rabbit {
    x: [u32; 8],
    c: [u32; 8],
    b: u32,
    kbuf: [u8; 16],
    pos: usize,
}

impl Rabbit {
    fn next_state(&mut self) {
        let mut carry = self.b as u64;
        for i in 0..8 {
            let t = self.c[i] as u64 + RABBIT_A[i] as u64 + carry;
            self.c[i] = t as u32;
            carry = t >> 32;
        }
        self.b = (carry & 1) as u32;
        let mut g = [0u32; 8];
        for i in 0..8 {
            let u = self.x[i].wrapping_add(self.c[i]);
            let sq = (u as u64).wrapping_mul(u as u64);
            g[i] = (sq ^ (sq >> 32)) as u32;
        }
        self.x[0] = g[0].wrapping_add(g[7].rotate_left(16)).wrapping_add(g[6].rotate_left(16));
        self.x[1] = g[1].wrapping_add(g[0].rotate_left(8)).wrapping_add(g[7]);
        self.x[2] = g[2].wrapping_add(g[1].rotate_left(16)).wrapping_add(g[0].rotate_left(16));
        self.x[3] = g[3].wrapping_add(g[2].rotate_left(8)).wrapping_add(g[1]);
        self.x[4] = g[4].wrapping_add(g[3].rotate_left(16)).wrapping_add(g[2].rotate_left(16));
        self.x[5] = g[5].wrapping_add(g[4].rotate_left(8)).wrapping_add(g[3]);
        self.x[6] = g[6].wrapping_add(g[5].rotate_left(16)).wrapping_add(g[4].rotate_left(16));
        self.x[7] = g[7].wrapping_add(g[6].rotate_left(8)).wrapping_add(g[5]);
    }

    pub fn new(key: &[u8; 16], iv: Option<&[u8; 8]>) -> Self {
        let mut k = [0u16; 8];
        for i in 0..8 {
            k[i] = ((key[14 - 2 * i] as u16) << 8) | key[15 - 2 * i] as u16; // k0 = K[15..0]
        }
        let mut x = [0u32; 8];
        let mut c = [0u32; 8];
        for j in 0..8 {
            if j % 2 == 0 {
                x[j] = ((k[(j + 1) % 8] as u32) << 16) | k[j] as u32;
                c[j] = ((k[(j + 4) % 8] as u32) << 16) | k[(j + 5) % 8] as u32;
            } else {
                x[j] = ((k[(j + 5) % 8] as u32) << 16) | k[(j + 4) % 8] as u32;
                c[j] = ((k[j] as u32) << 16) | k[(j + 1) % 8] as u32;
            }
        }
        let mut r = Rabbit { x, c, b: 0, kbuf: [0; 16], pos: 16 };
        for _ in 0..4 {
            r.next_state();
        }
        for j in 0..8 {
            r.c[j] ^= r.x[(j + 4) % 8];
        }
        if let Some(iv) = iv {
            let i0 = ((iv[4] as u32) << 24) | ((iv[5] as u32) << 16) | ((iv[6] as u32) << 8) | iv[7] as u32;
            let i2 = ((iv[0] as u32) << 24) | ((iv[1] as u32) << 16) | ((iv[2] as u32) << 8) | iv[3] as u32;
            let i1 = (i2 & 0xFFFF_0000) | (i0 >> 16);
            let i3 = ((i2 & 0xFFFF) << 16) | (i0 & 0xFFFF);
            let ivs = [i0, i1, i2, i3, i0, i1, i2, i3];
            for j in 0..8 {
                r.c[j] ^= ivs[j];
            }
            for _ in 0..4 {
                r.next_state();
            }
        }
        r
    }

    fn block(&mut self) -> [u8; 16] {
        self.next_state();
        let x = &self.x;
        let s0 = x[0] ^ (x[5] >> 16) ^ (x[3] << 16);
        let s1 = x[2] ^ (x[7] >> 16) ^ (x[5] << 16);
        let s2 = x[4] ^ (x[1] >> 16) ^ (x[7] << 16);
        let s3 = x[6] ^ (x[3] >> 16) ^ (x[1] << 16);
        let mut o = [0u8; 16];
        for (w, word) in [s3, s2, s1, s0].iter().enumerate() {
            o[w * 4..w * 4 + 4].copy_from_slice(&word.to_be_bytes()); // RFC 4503 OS2IP
        }
        o
    }
}

impl Keystream for Rabbit {
    fn xor(&mut self, buf: &mut [u8]) {
        for d in buf.iter_mut() {
            if self.pos == 16 {
                self.kbuf = self.block();
                self.pos = 0;
            }
            *d ^= self.kbuf[self.pos];
            self.pos += 1;
        }
    }
}

// ------------------------------ self-check ---------------------------------
/// Verify both hand-relevant ciphers against their RFC vectors.
pub fn vectors_ok() -> Result<(), String> {
    // Rabbit RFC 4503 (zero key, no IV), first keystream block.
    let mut r = Rabbit::new(&[0u8; 16], None);
    let mut blk = [0u8; 16];
    r.xor(&mut blk); // XOR into zeros == raw keystream
    if blk != hexu("b15754f036a5d6ecf56b45261c4af702") {
        return Err("Rabbit RFC4503 no-IV vector failed".into());
    }
    // Rabbit RFC 4503 (zero key, zero IV).
    let mut r = Rabbit::new(&[0u8; 16], Some(&[0u8; 8]));
    let mut blk = [0u8; 16];
    r.xor(&mut blk);
    if blk != hexu("c6a7275ef85495d87ccd5d376705b7ed") {
        return Err("Rabbit RFC4503 IV vector failed".into());
    }
    // ChaCha20 RFC 8439 block function (key 00..1f, counter 1, nonce ..09..4a..).
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = i as u8;
    }
    let nonce = hexu8_12("000000090000004a00000000");
    use cipher::{KeyIvInit, StreamCipherSeek};
    let mut cc = chacha20::ChaCha20::new(chacha20::Key::from_slice(&key),
                                         chacha20::Nonce::from_slice(&nonce));
    cc.seek(64u32); // counter block 1 starts at byte 64
    let mut ks = [0u8; 16];
    cc.apply_keystream(&mut ks);
    if ks != hexu("10f1e7e4d13b5915500fdd1fa32071c4") {
        return Err("ChaCha20 RFC8439 vector failed".into());
    }
    Ok(())
}

fn hexu(s: &str) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    o
}
fn hexu8_12(s: &str) -> [u8; 12] {
    let mut o = [0u8; 12];
    for i in 0..12 {
        o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc_vectors() {
        vectors_ok().unwrap();
    }
}
