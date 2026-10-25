/* IEEE CRC-32 lookup table (same polynomial as zip/gzip/PNG).
 *
 * C owns and builds the table; the hot per-byte loop lives in crc32.S (asm).
 * `zed_crc32_init` is called once from Rust before the first checksum, so the
 * table is ready without relying on static-constructor ordering.
 */
#include <stdint.h>

uint32_t zed_crc32_table[256];

void zed_crc32_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        zed_crc32_table[i] = c;
    }
}
