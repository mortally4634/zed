//! FFI to the hand-written native routines: CRC32 in C (`crc32.c`) and a
//! SIMD XOR in x86-64 assembly (`xor.S`), both linked in via `build.rs`.

extern "C" {
    fn zed_crc32(crc: u32, data: *const u8, len: usize) -> u32;
    fn zed_xor(dst: *mut u8, src: *const u8, len: usize);
}

/// IEEE CRC-32 (zip/gzip polynomial), computed in C.
pub fn crc32(data: &[u8]) -> u32 {
    // SAFETY: ptr+len come from a live slice; the C function only reads len bytes.
    unsafe { zed_crc32(0, data.as_ptr(), data.len()) }
}

/// `dst[i] ^= src[i]` over the overlapping length, via SSE2 assembly.
pub fn xor_inplace(dst: &mut [u8], src: &[u8]) {
    let n = dst.len().min(src.len());
    if n == 0 {
        return;
    }
    // SAFETY: both pointers are valid for `n` bytes (n = min of the two lens);
    // the asm reads n bytes of src and read-modify-writes n bytes of dst.
    unsafe { zed_xor(dst.as_mut_ptr(), src.as_ptr(), n) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926); // canonical CRC-32 check value
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn xor_is_reversible_and_correct() {
        let key: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
        let mut data: Vec<u8> = (0..300u32).map(|i| (i * 3 + 1) as u8).collect();
        let orig = data.clone();
        xor_inplace(&mut data, &key);
        // matches a plain scalar XOR
        let scalar: Vec<u8> = orig.iter().zip(&key).map(|(a, b)| a ^ b).collect();
        assert_eq!(data, scalar);
        xor_inplace(&mut data, &key); // XOR twice -> original
        assert_eq!(data, orig);
    }
}
