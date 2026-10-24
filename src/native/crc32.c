/* IEEE CRC-32 (same polynomial as zip/gzip/PNG), table-based.
 *
 * Used by the recovery module to checksum Reed-Solomon shards. The table is
 * built on the stack each call, so the function is pure and thread-safe (the
 * build is tiny next to hashing a >= 4 KiB shard).
 *
 * zed_crc32(0, data, len) matches a standard CRC32: crc32("123456789") =
 * 0xCBF43926, verified in the Rust test and the runtime self-test.
 */
#include <stddef.h>
#include <stdint.h>

uint32_t zed_crc32(uint32_t crc, const uint8_t *data, size_t len) {
    uint32_t table[256];
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        table[i] = c;
    }
    crc = ~crc;
    for (size_t i = 0; i < len; i++)
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}
