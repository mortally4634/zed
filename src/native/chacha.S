// void zed_chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
//                         uint32_t counter, uint8_t out[64])
//   ChaCha20 block function (RFC 8439): 20 rounds, out = working + initial.
//
// x86-64, Win64 ABI: key in RCX, nonce in RDX, counter in R8D, out in R9.
// State and working array live on the stack (WORK at rsp+0, STATE at rsp+64).
// Volatile registers only (EAX/ECX/EDX temps, R10D round counter, R9 = out).

    .intel_syntax noprefix
    .text

// One ChaCha quarter-round on working words at the given 4 indices.
    .macro QR i, j, k, l
    mov     eax, [rsp + \i*4]
    add     eax, [rsp + \j*4]
    mov     [rsp + \i*4], eax          // a += b
    mov     edx, [rsp + \l*4]
    xor     edx, eax
    rol     edx, 16
    mov     [rsp + \l*4], edx          // d = rol(d ^ a, 16)
    mov     ecx, [rsp + \k*4]
    add     ecx, edx
    mov     [rsp + \k*4], ecx          // c += d
    mov     eax, [rsp + \j*4]
    xor     eax, ecx
    rol     eax, 12
    mov     [rsp + \j*4], eax          // b = rol(b ^ c, 12)
    mov     eax, [rsp + \i*4]
    add     eax, [rsp + \j*4]
    mov     [rsp + \i*4], eax          // a += b
    mov     edx, [rsp + \l*4]
    xor     edx, eax
    rol     edx, 8
    mov     [rsp + \l*4], edx          // d = rol(d ^ a, 8)
    mov     ecx, [rsp + \k*4]
    add     ecx, edx
    mov     [rsp + \k*4], ecx          // c += d
    mov     eax, [rsp + \j*4]
    xor     eax, ecx
    rol     eax, 7
    mov     [rsp + \j*4], eax          // b = rol(b ^ c, 7)
    .endm

    .globl zed_chacha20_block
zed_chacha20_block:
    sub     rsp, 128                   // WORK [rsp+0..64), STATE [rsp+64..128)

    // initial state: constants | key | counter | nonce
    mov     dword ptr [rsp+64+0],  0x61707865
    mov     dword ptr [rsp+64+4],  0x3320646e
    mov     dword ptr [rsp+64+8],  0x79622d32
    mov     dword ptr [rsp+64+12], 0x6b206574
    mov     eax, [rcx+0]
    mov     [rsp+64+16], eax
    mov     eax, [rcx+4]
    mov     [rsp+64+20], eax
    mov     eax, [rcx+8]
    mov     [rsp+64+24], eax
    mov     eax, [rcx+12]
    mov     [rsp+64+28], eax
    mov     eax, [rcx+16]
    mov     [rsp+64+32], eax
    mov     eax, [rcx+20]
    mov     [rsp+64+36], eax
    mov     eax, [rcx+24]
    mov     [rsp+64+40], eax
    mov     eax, [rcx+28]
    mov     [rsp+64+44], eax
    mov     [rsp+64+48], r8d           // counter
    mov     eax, [rdx+0]
    mov     [rsp+64+52], eax
    mov     eax, [rdx+4]
    mov     [rsp+64+56], eax
    mov     eax, [rdx+8]
    mov     [rsp+64+60], eax

    // WORK = STATE
    xor     r11, r11
.Lcp:
    mov     eax, [rsp+64 + r11*4]
    mov     [rsp + r11*4], eax
    inc     r11
    cmp     r11, 16
    jb      .Lcp

    // 10 double-rounds (column then diagonal quarter-rounds)
    mov     r10d, 10
.Ldr:
    QR 0, 4, 8, 12
    QR 1, 5, 9, 13
    QR 2, 6, 10, 14
    QR 3, 7, 11, 15
    QR 0, 5, 10, 15
    QR 1, 6, 11, 12
    QR 2, 7, 8, 13
    QR 3, 4, 9, 14
    dec     r10d
    jnz     .Ldr

    // out[i] = WORK[i] + STATE[i], little-endian
    xor     r11, r11
.Lout:
    mov     eax, [rsp + r11*4]
    add     eax, [rsp+64 + r11*4]
    mov     [r9 + r11*4], eax
    inc     r11
    cmp     r11, 16
    jb      .Lout

    add     rsp, 128
    ret
