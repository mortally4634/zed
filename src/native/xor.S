// void zed_xor(uint8_t* dst, const uint8_t* src, size_t len)
//   dst[i] ^= src[i]  for i in 0..len
//
// x86-64, Win64 ABI (windows-gnu target): args in RCX, RDX, R8.
// Uses only volatile registers (RAX, R9, XMM0, XMM1) so nothing must be saved.
// SSE2 (movdqu/pxor) is baseline on all x86-64, so there is no CPU-feature risk;
// 16 bytes per iteration with a scalar tail for the remainder.

    .intel_syntax noprefix
    .text
    .globl zed_xor
zed_xor:
    xor     rax, rax               // i = 0
.Lblock:
    mov     r9, r8
    sub     r9, rax                // remaining = len - i
    cmp     r9, 16
    jb      .Ltail                 // < 16 bytes left -> scalar tail
    movdqu  xmm0, [rcx + rax]      // dst chunk
    movdqu  xmm1, [rdx + rax]      // src chunk
    pxor    xmm0, xmm1
    movdqu  [rcx + rax], xmm0
    add     rax, 16
    jmp     .Lblock
.Ltail:
    cmp     rax, r8
    jae     .Ldone
    movzx   r9d, byte ptr [rdx + rax]
    xor     byte ptr [rcx + rax], r9b
    inc     rax
    jmp     .Ltail
.Ldone:
    ret
