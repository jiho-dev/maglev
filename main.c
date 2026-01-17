#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <smmintrin.h>

#include "list.h"
#include "hash.h"
#include "group.h"
#include "log.h"

typedef unsigned int uint32, uint32_t, ovs_be32, u32;
typedef unsigned short uint16, uint16_t, ovs_be16, u16;

struct {
    union {
        ovs_be32 ipv4_addr;
        struct in6_addr ipv6_addr;
    } tunnel;

    union {
        ovs_be32 ipv4_addr;
        struct in6_addr ipv6_addr;
    } pkt;

    ovs_be16 tp_port;
} hash_val;

//////////////////////////////

int hash_single_byte() {
    uint32_t expected_hash=0xa89a73bf;
    const unsigned char message = 6;
    size_t len = 1;
    uint32_t crc=0;

    crc = 0;
    crc = hash_bytes(&message, len, crc);
    VLOG_DEBUG("SSE 4.2   : 0x%x, 0x%x(0x%x)", message, crc, expected_hash);

    init_crc32c_table();

    crc = 0;
    crc = hash_bytes1(&message, len, crc); 
    VLOG_DEBUG("Software1 : 0x%x, 0x%x(0x%x)", message, crc, expected_hash);

    crc = 0;
    crc = hash_bytes2(&message, len, crc); 
    VLOG_DEBUG("Software2 : 0x%x, 0x%x(0x%x)", message, crc, expected_hash);

    return 0;
}

uint32_t hash_multiple_bytes() {
    memset(&hash_val, 0, sizeof hash_val);

    uint32_t expected_hash=0x60795727;
    uint32_t hash = 0;
    uint16_t port = 0;
    uint8_t protocol = 6; // tcp

    // src/dst ip
    uint32_t ip = 0;
    ip = 0xc34214ac;
    hash_val.pkt.ipv4_addr ^= ip;

    // src/dst ip
    ip =0x509314ac;
    hash_val.pkt.ipv4_addr ^= ip;

    // protocol
    hash = hash_bytes1(&protocol, sizeof(protocol), hash); 

    // port
    port = 0xe0ea;
    hash_val.tp_port ^= port;

    port = 0x5000;
    hash_val.tp_port ^= port;

    // finallize hash
    hash = hash_bytes1(&hash_val, sizeof(hash_val), hash);

    VLOG_DEBUG("Multiple bytes: 0x%x(0x%x)", hash, expected_hash);

    return hash;
}

void hash_test() {
    hash_single_byte();
    hash_multiple_bytes();
}

void maglev_test() {
    VLOG_INFO("Start maglev test ");

    struct group_dpif group;
    struct ofputil_bucket bkt1, bkt2, bkt3, bkt4, bkt5, bkt6;

    memset(&group, 0, sizeof(group));
    memset(&bkt1, 0, sizeof(bkt1));
    memset(&bkt2, 0, sizeof(bkt2));
    memset(&bkt3, 0, sizeof(bkt3));
    memset(&bkt4, 0, sizeof(bkt4));
    memset(&bkt5, 0, sizeof(bkt5));
    memset(&bkt6, 0, sizeof(bkt6));

    ovs_list_init(&group.up.buckets);
    ovs_list_init(&bkt1.list_node);

    bkt1.weight = 50;
    bkt1.bucket_id = 1;

    bkt2.weight = 50;
    bkt2.bucket_id = 2;

    bkt3.weight = 50;
    bkt3.bucket_id = 3;

    bkt4.weight = 50;
    bkt4.bucket_id = 4;

    bkt5.weight = 50;
    bkt5.bucket_id = 5;

    bkt6.weight = 50;
    bkt6.bucket_id = 6;

    group.hash_alg = 5;  // table size: 0 ~ 10
    group.hash_basis = 0;
    group.up.group_id = 100;

    ovs_list_push_back(&group.up.buckets, &bkt1.list_node);
    ovs_list_push_back(&group.up.buckets, &bkt2.list_node);
    ovs_list_push_back(&group.up.buckets, &bkt3.list_node);
    ovs_list_push_back(&group.up.buckets, &bkt4.list_node);
    ovs_list_push_back(&group.up.buckets, &bkt5.list_node);
    ovs_list_push_back(&group.up.buckets, &bkt6.list_node);

    mh_construct(&group);

    uint32_t hash_data;
    hash_data = hash_multiple_bytes();

    struct ofputil_bucket *selected_bkt;
    uint32_t expected_bkt_id = 5;
    selected_bkt = mh_lookup(&group, hash_data);

    VLOG_INFO("Selected bucket: bkt_id=%d, expected=%d", selected_bkt->bucket_id, expected_bkt_id);

    mh_destruct(&group);

    VLOG_INFO("End maglev test ");

}

int main() {
    VLOG_INFO("Start maglev simulater ");

    hash_test();
    maglev_test();

    VLOG_INFO("End maglev simulater ");
}
