//! ChaCha20 keystream (RFC 8439) over the hand-written assembly block function
//! (`src/native/chacha.S`). Replaces the `chacha20` crate.

use crate::crypto::Keystream;

extern "C" {
    fn zed_chacha20_block(key: *const u8, nonce: *const u8, counter: u32, out: *mut u8);
}

/// Compute one raw ChaCha20 block (used by tests / the RFC self-check).
pub(crate) fn block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut out = [0u8; 64];
    // SAFETY: key is 32 bytes, nonce 12, out 64 — exactly what the asm reads/writes.
    unsafe { zed_chacha20_block(key.as_ptr(), nonce.as_ptr(), counter, out.as_mut_ptr()) }
    out
}

pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    kbuf: [u8; 64],
    pos: usize,
    scratch: Vec<u8>,
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        ChaCha20 { key: *key, nonce: *nonce, counter, kbuf: [0; 64], pos: 64, scratch: Vec::new() }
    }

    fn next_block(&mut self) {
        self.kbuf = block(&self.key, &self.nonce, self.counter);
        self.counter = self.counter.wrapping_add(1);
        self.pos = 0;
    }

    fn fill_keystream(&mut self, out: &mut [u8]) {
        for o in out.iter_mut() {
            if self.pos == 64 {
                self.next_block();
            }
            *o = self.kbuf[self.pos];
            self.pos += 1;
        }
    }
}

impl Keystream for ChaCha20 {
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
    fn rfc8439_block() {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let nonce = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let out = block(&key, &nonce, 1);
        let expect: [u8; 16] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
            0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        ];
        assert_eq!(&out[..16], &expect);
    }
}
