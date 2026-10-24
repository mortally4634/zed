// AVX2 buffer XOR: dst[i] ^= src[i], 32 bytes per iteration.
//
// Only this function is compiled for AVX2 (via the target attribute), so the
// rest of the binary stays baseline. Rust calls it ONLY after a runtime
// `is_x86_feature_detected!("avx2")` check; on CPUs without AVX2 the SSE2
// assembly (`xor.S`) is used instead. This is the widest tier of the XOR path.

#include <immintrin.h>
#include <cstddef>
#include <cstdint>

extern "C" __attribute__((target("avx2")))
void zed_xor_avx2(uint8_t* dst, const uint8_t* src, size_t n) {
    size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(dst + i));
        __m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src + i));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst + i), _mm256_xor_si256(a, b));
    }
    for (; i < n; ++i) {
        dst[i] ^= src[i]; // scalar tail for the last < 32 bytes
    }
}
