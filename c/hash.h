#ifndef __HASH_H__
#define __HASH_H__

#include <stddef.h>

void init_crc32c_table();
uint32_t hash_add(uint32_t hash, uint32_t data);
uint32_t hash_finish(uint64_t hash, uint64_t final);
uint32_t hash_bytes(const void *p_, size_t n, uint32_t basis);
uint32_t hash_add1(uint32_t hash, uint32_t data);
uint32_t hash_finish1(uint64_t hash, uint64_t final);
uint32_t hash_bytes1(const void *p_, size_t n, uint32_t basis);
uint32_t hash_add2(uint32_t hash, uint32_t data);
uint32_t hash_finish2(uint64_t hash, uint64_t final);
uint32_t hash_bytes2(const void *p_, size_t n, uint32_t basis);


#endif
