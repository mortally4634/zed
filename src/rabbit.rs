//! Rabbit stream cipher (RFC 4503), hand-written because no mainstream Rust
//! crate provides it. Verified against the RFC test vectors in `crypto::vectors_ok`.
//!
//! ponytail: keystream is produced per 16-byte block and buffered; per-byte XOR
//! is the ceiling — switch to block-wise XOR if throughput ever matters.

use crate::crypto::Keystream;

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
