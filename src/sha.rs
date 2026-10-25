//! SHA-256, HMAC-SHA256 and PBKDF2-HMAC-SHA256 built on the hand-written
//! assembly compression core (`src/native/sha256.S`). Replaces the RustCrypto
//! sha2/hmac/pbkdf2 crates. Verified against NIST (SHA), RFC 4231 (HMAC) and a
//! known PBKDF2-SHA256 vector in the tests below.

extern "C" {
    /// One SHA-256 block compression (scalar asm): state[8] from a 64-byte block.
    fn zed_sha256_block(state: *mut u32, block: *const u8);
    /// Same, using the SHA-NI extension (only valid when the CPU has "sha").
    fn zed_sha256_block_shani(state: *mut u32, block: *const u8);
}

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buflen: usize,
    total: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 { state: H0, buf: [0; 64], buflen: 0, total: 0 }
    }

    fn compress(&mut self) {
        // SAFETY: state is 8 u32, buf is exactly 64 bytes, as the asm expects.
        // SHA-NI backend when the CPU supports it, else the scalar asm.
        unsafe {
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            if std::arch::is_x86_feature_detected!("sha") {
                zed_sha256_block_shani(self.state.as_mut_ptr(), self.buf.as_ptr());
                return;
            }
            zed_sha256_block(self.state.as_mut_ptr(), self.buf.as_ptr());
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buflen > 0 {
            let take = (64 - self.buflen).min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                self.compress();
                self.buflen = 0;
            }
        }
        while data.len() >= 64 {
            self.buf.copy_from_slice(&data[..64]);
            self.compress();
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bits = self.total.wrapping_mul(8);
        let mut i = self.buflen;
        self.buf[i] = 0x80;
        i += 1;
        if i > 56 {
            while i < 64 {
                self.buf[i] = 0;
                i += 1;
            }
            self.compress();
            i = 0;
        }
        while i < 56 {
            self.buf[i] = 0;
            i += 1;
        }
        self.buf[56..64].copy_from_slice(&bits.to_be_bytes());
        self.compress();
        let mut out = [0u8; 32];
        for j in 0..8 {
            out[j * 4..j * 4 + 4].copy_from_slice(&self.state[j].to_be_bytes());
        }
        out
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(data);
    s.finalize()
}

/// Streaming HMAC-SHA256 (so the archive MAC can run over the ciphertext in
/// chunks). encrypt-then-MAC uses this; PBKDF2 uses the one-shot below.
pub struct HmacSha256 {
    inner: Sha256,
    opad: [u8; 64],
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&sha256(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];
        for i in 0..64 {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        HmacSha256 { inner, opad }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    pub fn finalize(self) -> [u8; 32] {
        let ih = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.opad);
        outer.update(&ih);
        outer.finalize()
    }
}

fn hmac_oneshot(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut h = HmacSha256::new(key);
    h.update(msg);
    h.finalize()
}

pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iters: u32, out: &mut [u8]) {
    let hlen = 32;
    let nblocks = out.len().div_ceil(hlen);
    for block in 1..=nblocks as u32 {
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&block.to_be_bytes());
        let mut u = hmac_oneshot(password, &msg);
        let mut t = u;
        for _ in 1..iters {
            u = hmac_oneshot(password, &u);
            for i in 0..32 {
                t[i] ^= u[i];
            }
        }
        let off = (block as usize - 1) * hlen;
        let n = hlen.min(out.len() - off);
        out[off..off + n].copy_from_slice(&t[..n]);
    }
}

/// Constant-time byte-slice equality (for MAC tag comparison).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
    }

    #[test]
    fn sha256_nist_vectors() {
        assert_eq!(sha256(b"abc").to_vec(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        assert_eq!(sha256(b"").to_vec(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        // multi-block (896 bits) NIST vector
        assert_eq!(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_vec(),
            hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    }

    #[test]
    fn hmac_rfc4231_case2() {
        let m = hmac_oneshot(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(m.to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    }

    #[test]
    fn pbkdf2_sha256_vector() {
        let mut out = [0u8; 20];
        pbkdf2_sha256(b"password", b"salt", 1, &mut out);
        assert_eq!(out.to_vec(), hex("120fb6cffcf8b32c43e7225256c4f837a86548c9"));
    }

    #[test]
    fn shani_matches_scalar_asm() {
        if !std::arch::is_x86_feature_detected!("sha") {
            return; // no SHA-NI; the scalar asm is the only path
        }
        // Compress identical random blocks with both backends from identical
        // start states; they must agree bit-for-bit over many trials.
        let mut seed = 0x12345678u32;
        let mut rng = || {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            (seed >> 24) as u8
        };
        for _ in 0..64 {
            let mut st0 = [0u32; 8];
            for s in st0.iter_mut() {
                *s = u32::from_le_bytes([rng(), rng(), rng(), rng()]);
            }
            let mut block = [0u8; 64];
            for b in block.iter_mut() {
                *b = rng();
            }
            let mut a = st0;
            let mut b = st0;
            unsafe {
                zed_sha256_block_shani(a.as_mut_ptr(), block.as_ptr());
                zed_sha256_block(b.as_mut_ptr(), block.as_ptr());
            }
            assert_eq!(a, b, "SHA-NI block differs from scalar asm");
        }
    }
}
