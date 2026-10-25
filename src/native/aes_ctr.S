// void zed_aes256_keystream(const uint8_t rk[240], uint8_t ctr[16],
//                           uint8_t* out, size_t nblocks)
//   AES-256-CTR keystream via AES-NI: encrypts ctr, ctr+1, ... into `out`
//   (nblocks * 16 bytes) and advances `ctr` as a big-endian 128-bit counter
//   (matching RustCrypto's Ctr128BE, for byte-identical fallback behavior).
//   The 15 round keys (rk) are expanded in Rust (src/aes.rs).
//
// x86-64, Win64 ABI: rk=RCX, ctr=RDX, out=R8, nblocks=R9. Caller guarantees
// the CPU has AES-NI (checked via is_x86_feature_detected! in Rust). Volatile
// registers / XMM only.

    .intel_syntax noprefix
    .text
    .globl zed_aes256_keystream
zed_aes256_keystream:
    xor     rax, rax                 // block index
.Lblk:
    cmp     rax, r9
    jae     .Ldone
    // Round keys are loaded with movdqu (unaligned): AES-NI/SSE memory operands
    // would require 16-byte alignment, which the rk buffer does not guarantee.
    movdqu  xmm0, [rdx]              // counter block
    movdqu  xmm1, [rcx+0]
    pxor    xmm0, xmm1               // AddRoundKey rk0
    movdqu  xmm1, [rcx+16]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+32]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+48]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+64]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+80]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+96]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+112]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+128]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+144]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+160]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+176]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+192]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+208]
    aesenc  xmm0, xmm1
    movdqu  xmm1, [rcx+224]
    aesenclast xmm0, xmm1            // round 14
    movdqu  [r8], xmm0               // write keystream block
    add     r8, 16
    // increment ctr as a big-endian 128-bit integer
    mov     r10, [rdx+8]
    bswap   r10
    add     r10, 1
    mov     r11, [rdx]
    bswap   r11
    adc     r11, 0
    bswap   r10
    mov     [rdx+8], r10
    bswap   r11
    mov     [rdx], r11
    inc     rax
    jmp     .Lblk
.Ldone:
    ret
