//! Compiles the hand-written native routines into a static lib linked into the
//! crate: `crc32.c` (C) and `xor.S` (x86-64 SSE2 assembly, Win64 ABI).

fn main() {
    for f in ["crc32.c", "crc32.S", "xor.S", "rabbit.S", "sha256.S", "chacha.S",
              "aes_ctr.S", "xor_avx2.cpp"] {
        println!("cargo:rerun-if-changed=src/native/{f}");
    }
    // C + assembly in one static lib.
    cc::Build::new()
        .file("src/native/crc32.c")
        .file("src/native/crc32.S")
        .file("src/native/xor.S")
        .file("src/native/rabbit.S")
        .file("src/native/sha256.S")
        .file("src/native/chacha.S")
        .file("src/native/aes_ctr.S")
        .compile("zednative");
    // C++ (AVX2) in its own lib so it builds with the C++ compiler.
    cc::Build::new()
        .cpp(true)
        .file("src/native/xor_avx2.cpp")
        .compile("zedxx");
}
