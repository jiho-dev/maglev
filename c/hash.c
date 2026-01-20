#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <smmintrin.h>

#include "hash.h"
#include "util.h"

//////////////////////////////

/* The CRC32 polynomial used by the SSE4.2 hardware instruction (CRC-32C, Castagnoli) */
#define CRC32C_POLY 0x82f63b78

///////////////////////////////////////////
// no table version
uint32_t sw_crc32c_byte(uint32_t crc, uint8_t data) {
    crc ^= data;
    for (int i = 0; i < 8; ++i) {
        if (crc & 1) {
            crc = (crc >> 1) ^ CRC32C_POLY;
        } else {
            crc >>= 1;
        }
    }
    return crc;
}

uint32_t sw_crc32c_u32(uint32_t crc, uint32_t value) {
    crc = sw_crc32c_byte(crc, (value >> 0) & 0xFF);
    crc = sw_crc32c_byte(crc, (value >> 8) & 0xFF);
    crc = sw_crc32c_byte(crc, (value >> 16) & 0xFF);
    crc = sw_crc32c_byte(crc, (value >> 24) & 0xFF);
    return crc;
}

uint32_t sw_crc32c_u64(uint32_t crc, uint64_t value) {
    crc = sw_crc32c_byte(crc, (value >> 0) & 0xFF);
    crc = sw_crc32c_byte(crc, (value >> 8) & 0xFF);
    crc = sw_crc32c_byte(crc, (value >> 16) & 0xFF);
    crc = sw_crc32c_byte(crc, (value >> 24) & 0xFF);
    crc = sw_crc32c_byte(crc, (value >> 32) & 0xFF);
    crc = sw_crc32c_byte(crc, (value >> 40) & 0xFF);
    crc = sw_crc32c_byte(crc, (value >> 48) & 0xFF);
    crc = sw_crc32c_byte(crc, (value >> 56) & 0xFF);

    return crc;
}

uint32_t hash_add1(uint32_t hash, uint32_t data)
{
    return sw_crc32c_u32(hash, data);
}

uint32_t hash_finish1(uint64_t hash, uint64_t final)
{
    /* The finishing multiplier 0x805204f3 has been experimentally
     * derived to pass the testsuite hash tests. */
    hash = sw_crc32c_u64(hash, final) * 0x805204f3;
    return hash ^ (uint32_t)hash >> 16; /* Increase entropy in LSBs. */
}

uint32_t hash_bytes1(const void *p_, size_t n, uint32_t basis)
{
    const uint8_t *p = p_;
    size_t orig_n = n;
    uint32_t hash;

    hash = basis;
    while (n >= 4) {
        hash = hash_add1(hash, get_unaligned_u32(ALIGNED_CAST(const uint32_t *, p)));
        n -= 4;
        p += 4;
    }

    if (n) {
        uint32_t tmp = 0;
        memcpy(&tmp, p, n);
        hash = hash_add1(hash, tmp);
    }

    return hash_finish1(hash, orig_n);
}

/////////////////////////////////////
// with table
/* Precomputed table for byte-by-byte CRC calculation */
uint32_t crc32c_table[256];

void swtab_init_crc32c() {
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (uint32_t j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ CRC32C_POLY;
            } else {
                crc >>= 1;
            }
        }
        crc32c_table[i] = crc;
    }
}

uint32_t swtab_crc32c_u32(uint32_t crc, uint32_t v) {
    uint8_t b1 = (v >> 0) & 0xff;
    uint8_t b2 = (v >> 8) & 0xff;
    uint8_t b3 = (v >> 16) & 0xff;
    uint8_t b4 = (v >> 24) & 0xff;

    crc = (crc >> 8) ^ crc32c_table[(crc ^ b1) & 0xff];
    crc = (crc >> 8) ^ crc32c_table[(crc ^ b2) & 0xff];
    crc = (crc >> 8) ^ crc32c_table[(crc ^ b3) & 0xff];
    crc = (crc >> 8) ^ crc32c_table[(crc ^ b4) & 0xff];

    return crc;
}

uint64_t swtab_crc32c_u64(uint64_t crc, uint64_t value) {
    uint32_t current_crc = (uint32_t)crc;

    for (int i = 0; i < 8; ++i) {
        uint8_t byte = (value >> (i * 8)) & 0xFF;
        current_crc = (current_crc >> 8) ^ crc32c_table[(current_crc ^ byte) & 0xFF];
    }

    return (uint64_t)current_crc;
}

uint32_t hash_add2(uint32_t hash, uint32_t data)
{
    return swtab_crc32c_u32(hash, data);
}

uint32_t hash_finish2(uint64_t hash, uint64_t final)
{
    /* The finishing multiplier 0x805204f3 has been experimentally
     * derived to pass the testsuite hash tests. */
    hash = swtab_crc32c_u64(hash, final) * 0x805204f3;
    return hash ^ (uint32_t)hash >> 16; /* Increase entropy in LSBs. */
}

uint32_t hash_bytes2(const void *p_, size_t n, uint32_t basis)
{
    const uint8_t *p = p_;
    size_t orig_n = n;
    uint32_t hash;

    hash = basis;
    while (n >= 4) {
        hash = hash_add2(hash, get_unaligned_u32(ALIGNED_CAST(const uint32_t *, p)));
        n -= 4;
        p += 4;
    }

    if (n) {
        uint32_t tmp = 0;
        memcpy(&tmp, p, n);
        hash = hash_add2(hash, tmp);
    }

    return hash_finish2(hash, orig_n);
}

///////////////////////////////////////
// with table reflected
uint32_t crc32c_table_ref[256];

void init_table_ref() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (-(crc & 1) & CRC32C_POLY);
        }
        crc32c_table_ref[i] = crc;
    }
}

uint32_t crc32c_ref(uint32_t crc, const unsigned char *buf, size_t len) {
    crc = ~crc;
    for (size_t i = 0; i < len; i++) {
        crc = crc32c_table_ref[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

////////////////////////
// with sse4.2 reflected

uint32_t crc32c_hw_ref(uint32_t crc, const unsigned char *buf, size_t len) {
    //uint32_t crc = 0xFFFFFFFF; // 초기값 (Reflected)
    crc = ~crc;
    size_t i = 0;

    for (; i + 4 <= len; i += 4) {
        uint32_t data;
        memcpy(&data, &buf[i], sizeof(uint32_t));
        crc = _mm_crc32_u32(crc, data);
    }

    for (; i < len; i++) {
        crc = _mm_crc32_u8(crc, buf[i]);
    }

    //return crc ^ 0xFFFFFFFF; // 최종 XOR
    return ~crc;
}

/////////////////////////////////////////
/// _mm_crc32_u32는 crc32c reflected 구현체와 다르다.


uint32_t hash_add(uint32_t hash, uint32_t data)
{
    // CRC32C와 다르다. _mm_crc32_u32: non-inverted
    return _mm_crc32_u32(hash, data);
}

// unsigned __int64 _mm_crc32_u64(unsigned __int64 crc, unsigned __int64 data)
uint32_t hash_finish(uint64_t hash, uint64_t final)
{
    /* The finishing multiplier 0x805204f3 has been experimentally
     * derived to pass the testsuite hash tests. */
    hash = _mm_crc32_u64(hash, final) * 0x805204f3;
    return hash ^ (uint32_t)hash >> 16; /* Increase entropy in LSBs. */
}

uint32_t hash_bytes(const void *p_, size_t n, uint32_t basis)
{
    const uint8_t *p = p_;
    size_t orig_n = n;
    uint32_t hash;

    hash = basis;
    while (n >= 4) {
        hash = hash_add(hash, get_unaligned_u32(ALIGNED_CAST(const uint32_t *, p)));
        n -= 4;
        p += 4;
    }

    if (n) {
        uint32_t tmp = 0;

        memcpy(&tmp, p, n);
        hash = hash_add(hash, tmp);
    }

    return hash_finish(hash, orig_n);
}

