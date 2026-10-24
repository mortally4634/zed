// void zed_rabbit_next(RabbitState* state)
//   Advances the Rabbit (RFC 4503) state one step: counter system update,
//   g-function (x+c squared, folded), and the non-linear state update.
//   Extraction stays in Rust. This is the hot keystream-generation kernel.
//
// RabbitState layout (#[repr(C)], 4-byte fields):
//   x[0..8] at +0 .. +28, c[0..8] at +32 .. +60, b at +64
//
// x86-64, Win64 ABI (windows-gnu): state ptr in RCX. Uses only volatile
// registers (RAX, RDX, R8, R9, R11) plus 32 bytes of stack scratch for g[8];
// makes no calls, so no alignment or save/restore is required.

    .intel_syntax noprefix
    .text
    .globl zed_rabbit_next
zed_rabbit_next:
    sub     rsp, 32                 // scratch: g[0..8] at [rsp+0 .. rsp+28]

    // ---- counter system: c[i] += A[i] + carry (64-bit), carry = overflow ----
    mov     r8d, [rcx+64]           // carry = b (0 or 1)

    mov     eax, [rcx+32]
    mov     r11d, 0x4D34D34D
    add     rax, r11
    add     rax, r8
    mov     [rcx+32], eax
    shr     rax, 32
    mov     r8, rax

    mov     eax, [rcx+36]
    mov     r11d, 0xD34D34D3
    add     rax, r11
    add     rax, r8
    mov     [rcx+36], eax
    shr     rax, 32
    mov     r8, rax

    mov     eax, [rcx+40]
    mov     r11d, 0x34D34D34
    add     rax, r11
    add     rax, r8
    mov     [rcx+40], eax
    shr     rax, 32
    mov     r8, rax

    mov     eax, [rcx+44]
    mov     r11d, 0x4D34D34D
    add     rax, r11
    add     rax, r8
    mov     [rcx+44], eax
    shr     rax, 32
    mov     r8, rax

    mov     eax, [rcx+48]
    mov     r11d, 0xD34D34D3
    add     rax, r11
    add     rax, r8
    mov     [rcx+48], eax
    shr     rax, 32
    mov     r8, rax

    mov     eax, [rcx+52]
    mov     r11d, 0x34D34D34
    add     rax, r11
    add     rax, r8
    mov     [rcx+52], eax
    shr     rax, 32
    mov     r8, rax

    mov     eax, [rcx+56]
    mov     r11d, 0x4D34D34D
    add     rax, r11
    add     rax, r8
    mov     [rcx+56], eax
    shr     rax, 32
    mov     r8, rax

    mov     eax, [rcx+60]
    mov     r11d, 0xD34D34D3
    add     rax, r11
    add     rax, r8
    mov     [rcx+60], eax
    shr     rax, 32
    mov     r8, rax

    and     r8d, 1
    mov     [rcx+64], r8d           // b = final carry & 1

    // ---- g[i] = low(u*u) XOR high(u*u),  u = x[i] + c[i] (mod 2^32) ----
    mov     eax, [rcx+0]
    add     eax, [rcx+32]
    mul     eax
    xor     eax, edx
    mov     [rsp+0], eax
    mov     eax, [rcx+4]
    add     eax, [rcx+36]
    mul     eax
    xor     eax, edx
    mov     [rsp+4], eax
    mov     eax, [rcx+8]
    add     eax, [rcx+40]
    mul     eax
    xor     eax, edx
    mov     [rsp+8], eax
    mov     eax, [rcx+12]
    add     eax, [rcx+44]
    mul     eax
    xor     eax, edx
    mov     [rsp+12], eax
    mov     eax, [rcx+16]
    add     eax, [rcx+48]
    mul     eax
    xor     eax, edx
    mov     [rsp+16], eax
    mov     eax, [rcx+20]
    add     eax, [rcx+52]
    mul     eax
    xor     eax, edx
    mov     [rsp+20], eax
    mov     eax, [rcx+24]
    add     eax, [rcx+56]
    mul     eax
    xor     eax, edx
    mov     [rsp+24], eax
    mov     eax, [rcx+28]
    add     eax, [rcx+60]
    mul     eax
    xor     eax, edx
    mov     [rsp+28], eax

    // ---- state update (all adds are mod 2^32; rol = rotate-left) ----
    // x0 = g0 + rotl(g7,16) + rotl(g6,16)
    mov     eax, [rsp+28]
    rol     eax, 16
    mov     r9d, [rsp+24]
    rol     r9d, 16
    add     eax, r9d
    add     eax, [rsp+0]
    mov     [rcx+0], eax
    // x1 = g1 + rotl(g0,8) + g7
    mov     eax, [rsp+0]
    rol     eax, 8
    add     eax, [rsp+28]
    add     eax, [rsp+4]
    mov     [rcx+4], eax
    // x2 = g2 + rotl(g1,16) + rotl(g0,16)
    mov     eax, [rsp+4]
    rol     eax, 16
    mov     r9d, [rsp+0]
    rol     r9d, 16
    add     eax, r9d
    add     eax, [rsp+8]
    mov     [rcx+8], eax
    // x3 = g3 + rotl(g2,8) + g1
    mov     eax, [rsp+8]
    rol     eax, 8
    add     eax, [rsp+4]
    add     eax, [rsp+12]
    mov     [rcx+12], eax
    // x4 = g4 + rotl(g3,16) + rotl(g2,16)
    mov     eax, [rsp+12]
    rol     eax, 16
    mov     r9d, [rsp+8]
    rol     r9d, 16
    add     eax, r9d
    add     eax, [rsp+16]
    mov     [rcx+16], eax
    // x5 = g5 + rotl(g4,8) + g3
    mov     eax, [rsp+16]
    rol     eax, 8
    add     eax, [rsp+12]
    add     eax, [rsp+20]
    mov     [rcx+20], eax
    // x6 = g6 + rotl(g5,16) + rotl(g4,16)
    mov     eax, [rsp+20]
    rol     eax, 16
    mov     r9d, [rsp+16]
    rol     r9d, 16
    add     eax, r9d
    add     eax, [rsp+24]
    mov     [rcx+24], eax
    // x7 = g7 + rotl(g6,8) + g5
    mov     eax, [rsp+24]
    rol     eax, 8
    add     eax, [rsp+20]
    add     eax, [rsp+28]
    mov     [rcx+28], eax

    add     rsp, 32
    ret
