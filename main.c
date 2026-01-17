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

struct hash_val {
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

struct hash_data {
    struct ovs_list node;

    uint32_t sip;
    uint16_t sport;
    uint32_t dip;
    uint16_t dport;
    uint8_t protocol;
    uint32_t hash;
    uint32_t bkt_id;
};

///////////////////////////

int read_hash_value(struct ovs_list *in_hash_list);

//////////////////////////////

int hash_single_byte() {
    uint32_t expected_hash=0xa89a73bf;
    const unsigned char message = 6;
    size_t len = 1;
    uint32_t crc=0;

    crc = 0;
    crc = hash_bytes(&message, len, crc);
    VLOG_INFO("SSE 4.2   : 0x%x, 0x%x expect=0x%x", message, crc, expected_hash);

    init_crc32c_table();

    crc = 0;
    crc = hash_bytes1(&message, len, crc); 
    VLOG_INFO("Software1 : 0x%x, 0x%x expect=0x%x", message, crc, expected_hash);

    crc = 0;
    crc = hash_bytes2(&message, len, crc); 
    VLOG_INFO("Software2 : 0x%x, 0x%x expect=0x%x", message, crc, expected_hash);

    return 0;
}

uint32_t hash_multiple_bytes() {
#if 0
2026-01-17T07:40:32.743Z|00835|bridge|WARN|could not open network device vgw-pkt-out (No such device)
2026-01-17T07:40:37.653Z|00029|ofproto_dpif_xlate(handler1)|INFO|MH-SEL: ipv4 src/dst mf.id=141, val=0xc25814ac
2026-01-17T07:40:37.653Z|00030|ofproto_dpif_xlate(handler1)|INFO|MH-SEL: ipv4 src/dst mf.id=142, val=0x1aea14ac
2026-01-17T07:40:37.653Z|00031|ofproto_dpif_xlate(handler1)|INFO|MH-SEL: ext mf.id=146, val=0x6 len=1
2026-01-17T07:40:37.653Z|00032|ofproto_dpif_xlate(handler1)|INFO|MH-SEL: src/dst port mf.id=157, val=0x3ace
2026-01-17T07:40:37.653Z|00033|ofproto_dpif_xlate(handler1)|INFO|MH-SEL: src/dst port mf.id=158, val=0x5000
2026-01-17T07:40:37.653Z|00034|ofproto_dpif_xlate(handler1)|INFO|MH-SEL: before selecte bucket: 172.20.88.194:52794->172.20.234.26:80(6), hash.ip=0xd8b20000, hash.port=0x6ace, hash=0xa89a73bf, id=49394
2026-01-17T07:40:37.653Z|00035|ofproto_dpif_xlate(handler1)|INFO|MH-SEL: selected bucket: 172.20.88.194:52794->172.20.234.26:80(6), packet=0x7f95953c9a10, hash=0x5271e49c, id=49394:1
2026-01-17T07:40:37.740Z|00836|bridge|WARN|could not open network device vgw-pkt-out (No such device)
2026-01-17T07:40:38.108Z|00837|bridge|WARN|could not open network device vgw-pkt-out (No such device)
#endif

    struct hash_val hval;

    memset(&hval, 0, sizeof hval);

    uint32_t expected_hash=0x5271e49c;
    uint32_t exp_port = 0xa89a73bf;
    uint32_t hash = 0;
    uint16_t port = 0;
    uint8_t protocol = 6; // tcp

    // src/dst ip
    uint32_t ip = 0;
    ip = 0xc25814ac;
    hval.pkt.ipv4_addr ^= ip;

    // src/dst ip
    ip = 0x1aea14ac;
    hval.pkt.ipv4_addr ^= ip;

    // protocol
    hash = hash_bytes1(&protocol, sizeof(protocol), hash); 
    VLOG_INFO("Port Hash: 0x%x, except=0x%x", hash, exp_port);

    // port
    port = 0x3ace;
    hval.tp_port ^= port;

    port = 0x5000;
    hval.tp_port ^= port;

    // finallize hash
    hash = hash_bytes1(&hval, sizeof(hval), hash);


    //VLOG_DEBUG("In: ip=0x%x, port=0x%x", hval.pkt.ipv4_addr, hval.tp_port);
    VLOG_INFO("Multiple bytes Hash: 0x%x, expect=0x%x", hash, expected_hash);

    return hash;
}

uint32_t get_hash(struct hash_data *in) {
    struct hash_val hval;

    memset(&hval, 0, sizeof hval);

    uint32_t hash = 0;
    uint16_t port = 0;
    uint8_t protocol = in->protocol;

    // ip
    hval.pkt.ipv4_addr ^= in->sip;
    hval.pkt.ipv4_addr ^= in->dip;

    // protocol
    hash = hash_bytes1(&protocol, sizeof protocol, hash); 

    // port
    hval.tp_port ^= in->sport;
    hval.tp_port ^= in->dport;

    // finallize hash
    hash = hash_bytes1(&hval, sizeof(hval), hash);

    return hash;
}

void hash_test() {
    VLOG_INFO("Start verifying hash function");
    hash_single_byte();
    hash_multiple_bytes();
}

int add_bucket(struct group_dpif *group, int bkt_cnt, int weight) {
    int i;
    struct ofputil_bucket *bkt;

    for (i=0; i<bkt_cnt; i++) {
        bkt = calloc(sizeof(struct ofputil_bucket), 1);

        bkt->weight = weight;
        bkt->bucket_id = i + 1;

        VLOG_INFO("add bucket: %p", bkt);
        ovs_list_init(&bkt->list_node);
        ovs_list_push_back(&group->up.buckets, &bkt->list_node);
    }
}

void free_bucket(struct group_dpif *group) {
    struct ofputil_bucket *bkt, *next;
    LIST_FOR_EACH_SAFE(bkt, next, list_node, &group->up.buckets) {
        ovs_list_remove(&bkt->list_node);

        VLOG_INFO("free bucket: %p", bkt);
        free(bkt);
    }
}

void maglev_test() {
    VLOG_INFO("Start verifying Maglev");

    struct group_dpif group;

    memset(&group, 0, sizeof(group));
    ovs_list_init(&group.up.buckets);

    group.hash_alg = 5;  // table size: 0 ~ 10
    group.hash_basis = 0;
    group.up.group_id = 100;

    // add 3 buckets
    int nbkts = 3;
    int weight = 10;
    add_bucket(&group, nbkts, weight);

    mh_construct(&group);

    struct ovs_list in_hash_list;
    ovs_list_init(&in_hash_list);
    
    // load hashes to be verified
    read_hash_value(&in_hash_list);

    struct hash_data *hdata;
    uint32_t node_hash;
    uint32_t idx=1;
    uint32_t mismatched=0;

    // verify them
    VLOG_INFO("Verify Maglev Hash result");

    struct ofputil_bucket *bkt;
    LIST_FOR_EACH (hdata, node, &in_hash_list) {
        node_hash = get_hash(hdata);
        bkt = mh_lookup(&group, node_hash);
        if (bkt->bucket_id != hdata->bkt_id) {
            VLOG_INFO("%d: compare: bkt_id=%d:%d hash=0x%x:0x%x", idx, 
                      bkt->bucket_id, hdata->bkt_id,
                      node_hash, hdata->hash);

            mismatched ++;
        }

        idx ++;
    }

    VLOG_INFO("Verification Result: Total=%d, Mismatched=%d", idx, mismatched);

    mh_destruct(&group);
    free_bucket(&group);

    VLOG_INFO("End maglev test ");
}

int read_hash_value(struct ovs_list *in_hash_list) {
    FILE *fp;
    char buffer[1024];
    char *fname = "./hash_value.txt";

    VLOG_INFO("Load hash entries");

    fp = fopen(fname, "r");
    if (fp == NULL) {
        VLOG_ERROR("failed to open file: %s", fname);
        return 1;
    }

    char *token;
    char *delimiters = " ";
    int line_count = 1;

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (buffer[0] == '#') {
            continue;
        }

        line_count ++;

        struct hash_data *in_hash = calloc(1, sizeof(struct hash_data));
        in_hash->protocol = 6; // tcp

        token = strtok(buffer, delimiters);
        int idx=0;
        char *endptr;
        while (token != NULL) {
            switch (idx) {
            case 0:
                in_hash->sip = ip2int(token);
                break;
            case 1:
                in_hash->sport =  atoi(token);
                in_hash->sport = htons(in_hash->sport);
                break;
            case 2:
                in_hash->dip = ip2int(token);
                break;
            case 3:
                in_hash->dport = atoi(token);
                in_hash->dport = htons(in_hash->dport);
                break;
            case 4:
                in_hash->hash = strtol(token, &endptr, 16);
                break;
            case 5:
                in_hash->bkt_id =  atoi(token);
                break;
            }

            idx++;
            token = strtok(NULL, delimiters);
        }

        ovs_list_init(&in_hash->node);
        ovs_list_push_back(in_hash_list, &in_hash->node);

#if 0
        VLOG_DEBUG("Hash node: 0x%x:0x%x->0x%x:0x%x 0x%x %d", 
                   in_hash->sip,
                   in_hash->sport,
                   in_hash->dip,
                   in_hash->dport,
                   in_hash->hash,
                   in_hash->bkt_id);
#endif

    }

    VLOG_INFO("Hash nodes to be verified: %d", line_count);

    fclose(fp);

    return 0;
}


int main() {
    VLOG_INFO("Start maglev simulater ");

    hash_test();
    maglev_test();

    VLOG_INFO("End maglev simulater ");

    return 0;
}
