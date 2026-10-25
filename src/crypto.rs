//! Ciphers and key derivation for the .zed format.
//!
//! All three ciphers run as a keystream under encrypt-then-MAC (HMAC-SHA256);
//! keys come from a password (and optional keyfile) via PBKDF2-HMAC-SHA256.
//! Rabbit (see [`crate::rabbit`]) is hand-written and verified against RFC 4503;
//! ChaCha20 and AES-256-CTR come from the audited RustCrypto crates.

use crate::rabbit::Rabbit;
use cipher::{KeyIvInit, StreamCipher};
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
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&iv[..12]);
            Box::new(crate::chacha::ChaCha20::new(enc_key, &nonce, 0))
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
        material.extend_from_slice(&crate::sha::sha256(kf));
    }
    let mut dk = [0u8; 64];
    crate::sha::pbkdf2_sha256(&material, salt, iters, &mut dk);
    material.zeroize();
    let mut ek = [0u8; 32];
    let mut mk = [0u8; 32];
    ek.copy_from_slice(&dk[..32]);
    mk.copy_from_slice(&dk[32..]);
    dk.zeroize();
    (ek, mk)
}

// ------------------------------ self-check ---------------------------------
/// Verify the ciphers against their RFC vectors.
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
    // Rabbit RFC 4503 (non-zero key, no IV) - independent KAT for the asm kernel.
    let key2 = [0x91, 0x28, 0x13, 0x29, 0x2E, 0x3D, 0x36, 0xFE,
                0x3B, 0xFC, 0x62, 0xF1, 0xDC, 0x51, 0xC3, 0xAC];
    let mut r = Rabbit::new(&key2, None);
    let mut blk = [0u8; 16];
    r.xor(&mut blk);
    if blk != hexu("3d2df3c83ef627a1e97fc38487e2519c") {
        return Err("Rabbit RFC4503 key2 vector failed".into());
    }
    // Rabbit RFC 4503 (zero key, non-zero IV).
    let mut r = Rabbit::new(&[0u8; 16], Some(&[0xC3, 0x73, 0xF5, 0x75, 0xC1, 0x26, 0x7E, 0x59]));
    let mut blk = [0u8; 16];
    r.xor(&mut blk);
    if blk != hexu("1fcd4eb9580012e2e0dccc9222017d6d") {
        return Err("Rabbit RFC4503 IV2 vector failed".into());
    }
    // ChaCha20 RFC 8439 block function (key 00..1f, counter 1, nonce ..09..4a..),
    // via the hand-written assembly block.
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = i as u8;
    }
    let nonce = hexu8_12("000000090000004a00000000");
    let blk = crate::chacha::block(&key, &nonce, 1);
    if blk[..16] != hexu("10f1e7e4d13b5915500fdd1fa32071c4") {
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
