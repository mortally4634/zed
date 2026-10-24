//! Compiles the hand-written native routines into a static lib linked into the
//! crate: `crc32.c` (C) and `xor.S` (x86-64 SSE2 assembly, Win64 ABI).

fn main() {
    println!("cargo:rerun-if-changed=src/native/crc32.c");
    println!("cargo:rerun-if-changed=src/native/xor.S");
    println!("cargo:rerun-if-changed=src/native/rabbit.S");
    cc::Build::new()
        .file("src/native/crc32.c")
        .file("src/native/xor.S")
        .file("src/native/rabbit.S")
        .compile("zednative");
}
