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

uint32_t crc32c_byte(uint32_t crc, uint8_t data) {
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

uint32_t software_mm_crc32_u32(uint32_t crc, uint32_t value) {
    crc = crc32c_byte(crc, (value >> 0) & 0xFF);
    crc = crc32c_byte(crc, (value >> 8) & 0xFF);
    crc = crc32c_byte(crc, (value >> 16) & 0xFF);
    crc = crc32c_byte(crc, (value >> 24) & 0xFF);
    return crc;
}

uint32_t software_mm_crc32_u64(uint32_t crc, uint64_t value) {
    crc = crc32c_byte(crc, (value >> 0) & 0xFF);
    crc = crc32c_byte(crc, (value >> 8) & 0xFF);
    crc = crc32c_byte(crc, (value >> 16) & 0xFF);
    crc = crc32c_byte(crc, (value >> 24) & 0xFF);
    crc = crc32c_byte(crc, (value >> 32) & 0xFF);
    crc = crc32c_byte(crc, (value >> 40) & 0xFF);
    crc = crc32c_byte(crc, (value >> 48) & 0xFF);
    crc = crc32c_byte(crc, (value >> 56) & 0xFF);

    return crc;
}

/* Precomputed table for byte-by-byte CRC calculation */
uint32_t crc32c_table[256];

void init_crc32c_table() {
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

uint32_t software_mm_crc32_u32_table(uint32_t crc, uint32_t v) {
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

uint64_t software_mm_crc32_u64_table(uint64_t crc, uint64_t value) {
    uint32_t current_crc = (uint32_t)crc;

    for (int i = 0; i < 8; ++i) {
        uint8_t byte = (value >> (i * 8)) & 0xFF;
        current_crc = (current_crc >> 8) ^ crc32c_table[(current_crc ^ byte) & 0xFF];
    }

    return (uint64_t)current_crc;
}


////////////////////////////

uint32_t hash_add1(uint32_t hash, uint32_t data)
{
    return software_mm_crc32_u32(hash, data);
}

uint32_t hash_finish1(uint64_t hash, uint64_t final)
{
    /* The finishing multiplier 0x805204f3 has been experimentally
     * derived to pass the testsuite hash tests. */
    hash = software_mm_crc32_u64(hash, final) * 0x805204f3;
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

////////////////////////////

uint32_t hash_add2(uint32_t hash, uint32_t data)
{
    return software_mm_crc32_u32_table(hash, data);
}

uint32_t hash_finish2(uint64_t hash, uint64_t final)
{
    /* The finishing multiplier 0x805204f3 has been experimentally
     * derived to pass the testsuite hash tests. */
    hash = software_mm_crc32_u64_table(hash, final) * 0x805204f3;
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


/////////////////////////////////////////
/// ovs 

uint32_t hash_add(uint32_t hash, uint32_t data)
{
    return _mm_crc32_u32(hash, data);
}

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

