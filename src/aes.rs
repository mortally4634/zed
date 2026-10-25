//! AES-256-CTR with an AES-NI assembly backend (`src/native/aes_ctr.S`).
//!
//! The key schedule is computed here in Rust (straightforward, easy to verify);
//! the AES-NI round loop runs in assembly. Callers use this only when the CPU
//! has AES-NI (checked in `crypto::make_keystream`); otherwise the `aes`/`ctr`
//! crates are used. The test below proves the asm path is byte-identical to the
//! audited crate.

use crate::crypto::Keystream;

extern "C" {
    fn zed_aes256_keystream(rk: *const u8, ctr: *mut u8, out: *mut u8, nblocks: usize);
}

// AES S-box (FIPS-197).
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (0x1b & (((x >> 7) & 1).wrapping_neg()))
}

/// Expand a 256-bit key to the 240-byte (15-round-key) schedule (FIPS-197).
fn expand_key(key: &[u8; 32]) -> [u8; 240] {
    let mut w = [0u8; 240];
    w[..32].copy_from_slice(key);
    let mut rc: u8 = 1;
    let mut i = 8usize; // word index
    while i < 60 {
        let mut t = [w[(i - 1) * 4], w[(i - 1) * 4 + 1], w[(i - 1) * 4 + 2], w[(i - 1) * 4 + 3]];
        if i % 8 == 0 {
            t.rotate_left(1); // RotWord
            for b in t.iter_mut() {
                *b = SBOX[*b as usize]; // SubWord
            }
            t[0] ^= rc;
            rc = xtime(rc);
        } else if i % 8 == 4 {
            for b in t.iter_mut() {
                *b = SBOX[*b as usize];
            }
        }
        for j in 0..4 {
            w[i * 4 + j] = w[(i - 8) * 4 + j] ^ t[j]; // AES-256: Nk = 8
        }
        i += 1;
    }
    w
}

pub struct Aes256Ctr {
    rk: [u8; 240],
    ctr: [u8; 16],
    kbuf: [u8; 16],
    pos: usize,
    scratch: Vec<u8>,
}

impl Aes256Ctr {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Aes256Ctr { rk: expand_key(key), ctr: *iv, kbuf: [0; 16], pos: 16, scratch: Vec::new() }
    }

    fn next_block(&mut self) {
        // SAFETY: rk is 240 bytes, ctr/kbuf are 16; the asm reads/writes exactly those.
        unsafe { zed_aes256_keystream(self.rk.as_ptr(), self.ctr.as_mut_ptr(), self.kbuf.as_mut_ptr(), 1) }
        self.pos = 0;
    }

    fn fill_keystream(&mut self, out: &mut [u8]) {
        for o in out.iter_mut() {
            if self.pos == 16 {
                self.next_block();
            }
            *o = self.kbuf[self.pos];
            self.pos += 1;
        }
    }
}

impl Keystream for Aes256Ctr {
    fn xor(&mut self, buf: &mut [u8]) {
        let n = buf.len();
        let mut ks = std::mem::take(&mut self.scratch);
        if ks.len() < n {
            ks.resize(n, 0);
        }
        self.fill_keystream(&mut ks[..n]);
        crate::native::xor_inplace(buf, &ks[..n]);
        self.scratch = ks;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes256_block_fips197() {
        if !std::arch::is_x86_feature_detected!("aes") {
            return;
        }
        // FIPS-197 C.3 AES-256: key 000102..1f, in 00112233..eeff -> out 8ea2b7ca...
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let plain: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        // keystream of a CTR with iv=plaintext == AES256_enc(plaintext)
        let mut ks = [0u8; 16];
        Aes256Ctr::new(&key, &plain).fill_keystream(&mut ks);
        let expect: [u8; 16] = [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                                0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89];
        assert_eq!(ks, expect, "AES-256 single block != FIPS-197 vector");
    }

    #[test]
    fn aes256ctr_matches_audited_crate() {
        if !std::arch::is_x86_feature_detected!("aes") {
            return; // AES-NI absent; the crate fallback path is what runs
        }
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        for i in 0..32 {
            key[i] = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        for i in 0..16 {
            iv[i] = (i as u8).wrapping_mul(3);
        }
        let data: Vec<u8> = (0..1000u32).map(|i| (i.wrapping_mul(2654435761) >> 20) as u8).collect();

        // our AES-NI asm path
        let mut a = data.clone();
        Aes256Ctr::new(&key, &iv).xor(&mut a);

        // the audited RustCrypto crate
        use ctr::cipher::{KeyIvInit, StreamCipher};
        let mut b = data.clone();
        let mut c = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&key, &iv).unwrap();
        c.apply_keystream(&mut b);

        assert_eq!(a, b, "AES-NI asm output differs from the audited crate");
    }
}
