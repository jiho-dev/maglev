#ifndef __TEST_VECTOR_H_
#define __TEST_VECTOR_H_

#include "list.h"

struct tv_entry {
    struct ovs_list node;

    uint32_t sip;
    uint16_t sport;
    uint32_t dip;
    uint16_t dport;
    uint8_t  protocol;
    uint32_t hash;
    uint32_t bkt_id;
};

typedef struct test_vector_s {
    uint32_t maglev_hash_table_size_index;
	uint32_t maglev_id;
	uint32_t num_buckets;
	uint32_t bucket_weight;
	char	 *maglev_hash2;

    struct ovs_list tv_list;
    uint32_t num_tv_entries;
    uint32_t mismatched;

} test_vector_t;

test_vector_t* load_test_vector(char *test_vect_file);
int free_test_vector(test_vector_t *tv);

#endif
