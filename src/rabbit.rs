//! Rabbit stream cipher (RFC 4503).
//!
//! The hot kernel — `next_state` (counter system + g-function + state update) —
//! is hand-written x86-64 assembly in `src/native/rabbit.S`. Key/IV setup and
//! the cheap extraction step stay in Rust. Verified against RFC 4503 known
//! answers (multiple keys and IVs) in `crypto::vectors_ok`.

use crate::crypto::Keystream;

/// Shared cipher state; `#[repr(C)]` so the assembly and Rust agree on the
/// byte layout (x[8] @ +0, c[8] @ +32, b @ +64).
#[repr(C)]
struct RabbitState {
    x: [u32; 8],
    c: [u32; 8],
    b: u32,
}

extern "C" {
    /// Advance the state one step. Implemented in `src/native/rabbit.S`.
    fn zed_rabbit_next(state: *mut RabbitState);
}

pub struct Rabbit {
    st: RabbitState,
    kbuf: [u8; 16],
    pos: usize,
    scratch: Vec<u8>, // reused keystream buffer, grown on demand
}

impl Rabbit {
    #[inline]
    fn next_state(&mut self) {
        // SAFETY: the asm reads/writes exactly the 68-byte RabbitState it is
        // given; `&mut self.st` is a valid, uniquely-borrowed pointer to it.
        unsafe { zed_rabbit_next(&mut self.st) }
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
        let mut r = Rabbit { st: RabbitState { x, c, b: 0 }, kbuf: [0; 16], pos: 16, scratch: Vec::new() };
        for _ in 0..4 {
            r.next_state();
        }
        for j in 0..8 {
            r.st.c[j] ^= r.st.x[(j + 4) % 8];
        }
        if let Some(iv) = iv {
            let i0 = ((iv[4] as u32) << 24) | ((iv[5] as u32) << 16) | ((iv[6] as u32) << 8) | iv[7] as u32;
            let i2 = ((iv[0] as u32) << 24) | ((iv[1] as u32) << 16) | ((iv[2] as u32) << 8) | iv[3] as u32;
            let i1 = (i2 & 0xFFFF_0000) | (i0 >> 16);
            let i3 = ((i2 & 0xFFFF) << 16) | (i0 & 0xFFFF);
            let ivs = [i0, i1, i2, i3, i0, i1, i2, i3];
            for j in 0..8 {
                r.st.c[j] ^= ivs[j];
            }
            for _ in 0..4 {
                r.next_state();
            }
        }
        r
    }

    /// Advance one step (asm) and extract a 16-byte keystream block (Rust).
    fn block(&mut self) -> [u8; 16] {
        self.next_state();
        let x = &self.st.x;
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

    /// Fill `out` with the next `out.len()` keystream bytes, continuing state.
    fn fill_keystream(&mut self, out: &mut [u8]) {
        for o in out.iter_mut() {
            if self.pos == 16 {
                self.kbuf = self.block();
                self.pos = 0;
            }
            *o = self.kbuf[self.pos];
            self.pos += 1;
        }
    }
}

impl Keystream for Rabbit {
    fn xor(&mut self, buf: &mut [u8]) {
        // Generate the matching keystream into a reused scratch buffer, then
        // apply it with the native XOR (AVX2 if available, else SSE2 asm).
        let n = buf.len();
        let mut ks = std::mem::take(&mut self.scratch); // reuse prior allocation
        if ks.len() < n {
            ks.resize(n, 0);
        }
        self.fill_keystream(&mut ks[..n]);
        crate::native::xor_inplace(buf, &ks[..n]);
        self.scratch = ks; // keep the buffer for the next call
    }
}
