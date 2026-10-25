// uint32_t zed_crc32(uint32_t crc, const uint8_t* data, size_t len)
//   Table-driven IEEE CRC-32 hot loop. The 256-entry table (zed_crc32_table)
//   is owned and filled by C (crc32.c); this is just the per-byte update.
//
// x86-64, Win64 ABI: crc in ECX, data in RDX, len in R8; result in EAX.
// Volatile registers only.

    .intel_syntax noprefix
    .text
    .globl zed_crc32
zed_crc32:
    not     ecx                        // crc = ~crc
    lea     r10, [rip + zed_crc32_table]
    xor     rax, rax                   // i = 0
.Lcrc:
    cmp     rax, r8
    jae     .Lcrc_done
    movzx   r9d, byte ptr [rdx + rax]  // data[i]
    xor     r9d, ecx
    and     r9d, 0xFF                  // (crc ^ data[i]) & 0xFF
    mov     r9d, [r10 + r9*4]          // table[...]
    shr     ecx, 8
    xor     ecx, r9d                   // crc = table[...] ^ (crc >> 8)
    inc     rax
    jmp     .Lcrc
.Lcrc_done:
    not     ecx
    mov     eax, ecx
    ret
