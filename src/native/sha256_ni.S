// void zed_sha256_block_shani(uint32_t state[8], const uint8_t block[64])
//   SHA-256 compression of one block using the SHA-NI extension (sha256rnds2 /
//   sha256msg1 / sha256msg2). Called only when the CPU reports the "sha"
//   feature (checked in Rust); otherwise the scalar sha256.S backend is used.
//
// x86-64, Win64 ABI: state=RCX, block=RDX. xmm0 holds MSG (the implicit operand
// of sha256rnds2). STATE0=xmm1, STATE1=xmm2, MSG0..3 = xmm3/4/5/6, TMP=xmm7,
// byte-swap MASK=xmm8. xmm6/7/8 are nonvolatile and saved; xmm3/4/5 are volatile
// and live across the block (the function makes no calls). Round constants and
// the mask are loaded with movdqu (no alignment requirement).

    .intel_syntax noprefix
    .text

// generic scheduled quad for rounds >= 16: current message reg, previous reg,
// next reg (gets the msg2 schedule), and the K offset.
    .macro SCHED cur, prev, next, koff
    movdqa  xmm0, \cur
    movdqu  xmm7, [r10 + \koff]
    paddd   xmm0, xmm7
    sha256rnds2 xmm2, xmm1
    movdqa  xmm7, \cur
    palignr xmm7, \prev, 4
    paddd   \next, xmm7
    sha256msg2 \next, \cur
    pshufd  xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 \prev, \cur
    .endm

    .globl zed_sha256_block_shani
zed_sha256_block_shani:
    sub     rsp, 80
    movdqu  [rsp+0],  xmm6
    movdqu  [rsp+16], xmm7
    movdqu  [rsp+32], xmm8

    lea     r10, [rip + shani_k]
    movdqu  xmm8, [rip + shani_mask]

    // load state -> STATE0 = ABEF (xmm1), STATE1 = CDGH (xmm2)
    movdqu  xmm2, [rcx]            // DCBA
    movdqu  xmm1, [rcx+16]         // HGFE
    pshufd  xmm2, xmm2, 0xB1       // CDAB
    pshufd  xmm1, xmm1, 0x1B       // EFGH
    movdqa  xmm0, xmm2
    palignr xmm0, xmm1, 8          // ABEF
    pblendw xmm1, xmm2, 0xF0       // CDGH
    movdqa  xmm2, xmm1             // STATE1 = CDGH
    movdqa  xmm1, xmm0             // STATE0 = ABEF

    movdqu  [rsp+48], xmm1         // ABEF_SAVE
    movdqu  [rsp+64], xmm2         // CDGH_SAVE

    // rounds 0-3
    movdqu  xmm0, [rdx+0]
    pshufb  xmm0, xmm8
    movdqa  xmm3, xmm0             // MSG0
    movdqu  xmm7, [r10+0]
    paddd   xmm0, xmm7
    sha256rnds2 xmm2, xmm1
    pshufd  xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2

    // rounds 4-7
    movdqu  xmm0, [rdx+16]
    pshufb  xmm0, xmm8
    movdqa  xmm4, xmm0             // MSG1
    movdqu  xmm7, [r10+16]
    paddd   xmm0, xmm7
    sha256rnds2 xmm2, xmm1
    pshufd  xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm3, xmm4

    // rounds 8-11
    movdqu  xmm0, [rdx+32]
    pshufb  xmm0, xmm8
    movdqa  xmm5, xmm0             // MSG2
    movdqu  xmm7, [r10+32]
    paddd   xmm0, xmm7
    sha256rnds2 xmm2, xmm1
    pshufd  xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm4, xmm5

    // rounds 12-15
    movdqu  xmm0, [rdx+48]
    pshufb  xmm0, xmm8
    movdqa  xmm6, xmm0             // MSG3
    movdqu  xmm7, [r10+48]
    paddd   xmm0, xmm7
    sha256rnds2 xmm2, xmm1
    movdqa  xmm7, xmm6
    palignr xmm7, xmm5, 4
    paddd   xmm3, xmm7
    sha256msg2 xmm3, xmm6
    pshufd  xmm0, xmm0, 0x0E
    sha256rnds2 xmm1, xmm2
    sha256msg1 xmm5, xmm6

    // rounds 16-63 (MSG registers cycle MSG0..MSG3)
    SCHED xmm3, xmm6, xmm4, 64     // 16-19: cur MSG0 prev MSG3 next MSG1
    SCHED xmm4, xmm3, xmm5, 80     // 20-23
    SCHED xmm5, xmm4, xmm6, 96     // 24-27
    SCHED xmm6, xmm5, xmm3, 112    // 28-31
    SCHED xmm3, xmm6, xmm4, 128    // 32-35
    SCHED xmm4, xmm3, xmm5, 144    // 36-39
    SCHED xmm5, xmm4, xmm6, 160    // 40-43
    SCHED xmm6, xmm5, xmm3, 176    // 44-47
    SCHED xmm3, xmm6, xmm4, 192    // 48-51
    SCHED xmm4, xmm3, xmm5, 208    // 52-55
    SCHED xmm5, xmm4, xmm6, 224    // 56-59
    SCHED xmm6, xmm5, xmm3, 240    // 60-63

    // add saved state
    movdqu  xmm7, [rsp+48]
    paddd   xmm1, xmm7             // STATE0 += ABEF_SAVE
    movdqu  xmm7, [rsp+64]
    paddd   xmm2, xmm7             // STATE1 += CDGH_SAVE

    // unpack STATE0(ABEF)/STATE1(CDGH) back to state[0..7]
    pshufd  xmm7, xmm1, 0x1B       // TMP = shuffle(STATE0,0x1B)
    pshufd  xmm2, xmm2, 0xB1       // STATE1 = shuffle(CDGH,0xB1)
    movdqa  xmm1, xmm7
    pblendw xmm1, xmm2, 0xF0       // DCBA
    palignr xmm2, xmm7, 8          // HGFE
    movdqu  [rcx], xmm1
    movdqu  [rcx+16], xmm2

    movdqu  xmm6, [rsp+0]
    movdqu  xmm7, [rsp+16]
    movdqu  xmm8, [rsp+32]
    add     rsp, 80
    ret

    .p2align 4
shani_k:
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
    .p2align 4
shani_mask:
    .byte 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
    .byte 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
