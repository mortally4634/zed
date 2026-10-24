// void zed_sha256_block(uint32_t state[8], const uint8_t block[64])
//   SHA-256 compression of one 512-bit block (FIPS 180-4). Streaming, padding
//   and length handling are done in Rust (src/sha.rs); this is the hot core
//   (PBKDF2 drives it hundreds of thousands of times per key derivation).
//
// x86-64, Win64 ABI (windows-gnu): state in RCX, block in RDX. RBX is saved
// (holds the state pointer so RCX is free as a temp); everything else uses
// volatile registers. a..h and the message schedule W[0..63] live on the stack.

    .intel_syntax noprefix
    .text
    .globl zed_sha256_block
zed_sha256_block:
    push    rbx
    mov     rbx, rcx                // rbx = state*
    sub     rsp, 288                // [rsp+0..256) = W[64], [rsp+256..288) = a..h

    // W[0..15] = big-endian words of the input block
    xor     r11, r11
.Lld:
    mov     eax, [rdx + r11*4]
    bswap   eax
    mov     [rsp + r11*4], eax
    inc     r11
    cmp     r11, 16
    jb      .Lld

    // W[16..63] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
.Lex:
    mov     eax, [rsp + r11*4 - 60] // W[t-15]
    mov     ecx, eax
    ror     ecx, 7
    mov     edx, eax
    ror     edx, 18
    xor     ecx, edx
    shr     eax, 3
    xor     ecx, eax                // sigma0 in ecx
    mov     eax, [rsp + r11*4 - 8]  // W[t-2]
    mov     edx, eax
    ror     edx, 17
    mov     r8d, eax
    ror     r8d, 19
    xor     edx, r8d
    shr     eax, 10
    xor     edx, eax                // sigma1 in edx
    mov     eax, [rsp + r11*4 - 64] // W[t-16]
    add     eax, ecx
    add     eax, edx
    mov     r8d, [rsp + r11*4 - 28] // W[t-7]
    add     eax, r8d
    mov     [rsp + r11*4], eax
    inc     r11
    cmp     r11, 64
    jb      .Lex

    // a..h = state[0..7]
    mov     eax, [rbx+0]
    mov     [rsp+256], eax
    mov     eax, [rbx+4]
    mov     [rsp+260], eax
    mov     eax, [rbx+8]
    mov     [rsp+264], eax
    mov     eax, [rbx+12]
    mov     [rsp+268], eax
    mov     eax, [rbx+16]
    mov     [rsp+272], eax
    mov     eax, [rbx+20]
    mov     [rsp+276], eax
    mov     eax, [rbx+24]
    mov     [rsp+280], eax
    mov     eax, [rbx+28]
    mov     [rsp+284], eax

    lea     r10, [rip + zed_sha256_k]
    xor     r11, r11
.Lround:
    // T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
    mov     eax, [rsp+272]          // e
    mov     ecx, eax
    ror     ecx, 6
    mov     edx, eax
    ror     edx, 11
    xor     ecx, edx
    mov     edx, eax
    ror     edx, 25
    xor     ecx, edx                // Sigma1(e)
    mov     edx, [rsp+276]          // f
    and     edx, eax                // e & f
    mov     r9d, eax
    not     r9d
    mov     r8d, [rsp+280]          // g
    and     r9d, r8d                // ~e & g
    xor     edx, r9d                // Ch(e,f,g)
    mov     r8d, [rsp+284]          // h
    add     r8d, ecx
    add     r8d, edx
    mov     eax, [r10 + r11*4]      // K[t]
    add     r8d, eax
    mov     eax, [rsp + r11*4]      // W[t]
    add     r8d, eax                // r8d = T1

    // T2 = Sigma0(a) + Maj(a,b,c)
    mov     eax, [rsp+256]          // a
    mov     ecx, eax
    ror     ecx, 2
    mov     edx, eax
    ror     edx, 13
    xor     ecx, edx
    mov     edx, eax
    ror     edx, 22
    xor     ecx, edx                // Sigma0(a)
    mov     edx, [rsp+260]          // b
    mov     r9d, eax
    and     r9d, edx                // a & b
    mov     edx, [rsp+264]          // c
    and     eax, edx                // a & c
    xor     r9d, eax
    mov     eax, [rsp+260]          // b
    and     eax, edx                // b & c
    xor     r9d, eax                // Maj(a,b,c)
    add     r9d, ecx                // r9d = T2

    // rotate: h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2
    mov     eax, [rsp+280]
    mov     [rsp+284], eax
    mov     eax, [rsp+276]
    mov     [rsp+280], eax
    mov     eax, [rsp+272]
    mov     [rsp+276], eax
    mov     eax, [rsp+268]
    add     eax, r8d
    mov     [rsp+272], eax
    mov     eax, [rsp+264]
    mov     [rsp+268], eax
    mov     eax, [rsp+260]
    mov     [rsp+264], eax
    mov     eax, [rsp+256]
    mov     [rsp+260], eax
    mov     eax, r8d
    add     eax, r9d
    mov     [rsp+256], eax

    inc     r11
    cmp     r11, 64
    jb      .Lround

    // state[i] += a..h
    mov     eax, [rsp+256]
    add     [rbx+0], eax
    mov     eax, [rsp+260]
    add     [rbx+4], eax
    mov     eax, [rsp+264]
    add     [rbx+8], eax
    mov     eax, [rsp+268]
    add     [rbx+12], eax
    mov     eax, [rsp+272]
    add     [rbx+16], eax
    mov     eax, [rsp+276]
    add     [rbx+20], eax
    mov     eax, [rsp+280]
    add     [rbx+24], eax
    mov     eax, [rsp+284]
    add     [rbx+28], eax

    add     rsp, 288
    pop     rbx
    ret

    .p2align 2
zed_sha256_k:
    .long 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .long 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .long 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .long 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .long 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .long 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .long 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .long 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .long 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .long 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .long 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .long 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .long 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .long 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .long 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .long 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
