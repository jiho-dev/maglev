#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <smmintrin.h>
#include <unistd.h>

#include "list.h"
#include "hash.h"
#include "jhash.h"
#include "group.h"
#include "log.h"
#include "maglev_hash.h"
#include "test_vector.h"


//////////////////////////////
//
int verify_crc32() {
    VLOG_INFO("Start verifying CRC32C function");

    uint32_t expected=0xc4451272;
    uint32_t hash_data = 6;
    size_t len = 4;
    uint32_t crc=0;

    //////////////////
    // non-inverted version
    crc = hash_add(0, hash_data);
    VLOG_INFO("SSE4.2 CRC: 0x%x, 0x%x expect=0x%x", hash_data, crc, expected);

    swtab_init_crc32c();
    crc = 0;
    crc = hash_add1(0, hash_data);
    VLOG_INFO("SW1 CRC   : 0x%x, 0x%x expect=0x%x", hash_data, crc, expected);

    crc = 0;
    crc = hash_add2(0, hash_data);
    VLOG_INFO("SW2 CRC   : 0x%x, 0x%x expect=0x%x", hash_data, crc, expected);

    ////////////////////////////////////////
    // standard reflected verion
    // CRC32C with reflected is not the same with hash_byte above
    // this is the original CRC32C implementaion.
    // https://www.sunshine2k.de/coding/javascript/crc/crc_js.html
   
    init_table_ref();
    crc = 0;
    expected = 0x12FD1978;
    hash_data = 0x06060606; // byteorder free
    crc = crc32c_ref(crc, (char*)&hash_data, 4);
    VLOG_INFO("SW3 CRC   : 0x%x, 0x%x expect=0x%x", hash_data, crc, expected);

    crc = 0;
    expected = 0x12FD1978;
    hash_data = 0x06060606; // byteorder free
    crc = crc32c_hw_ref(crc, (char*)&hash_data, 4);
    VLOG_INFO("SW4 CRC   : 0x%x, 0x%x expect=0x%x", hash_data, crc, expected);

    return 0;
}

int verify_hash_byte() {
    VLOG_INFO("Start verifying Hash Byte");

    uint32_t expected_hash=0xa89a73bf;
    const unsigned char message = 6;
    size_t len = 1;
    uint32_t hash, hash_data;

    hash = 0;
    hash = hash_bytes(&message, len, hash);
    VLOG_INFO("SSE4.2    : 0x%x, 0x%x expect=0x%x", message, hash, expected_hash);

    swtab_init_crc32c();

    hash = 0;
    hash = hash_bytes1(&message, len, hash); 
    VLOG_INFO("Software1 : 0x%x, 0x%x expect=0x%x", message, hash, expected_hash);

    hash = 0;
    hash = hash_bytes2(&message, len, hash); 
    VLOG_INFO("Software2 : 0x%x, 0x%x expect=0x%x", message, hash, expected_hash);

    return 0;
}

uint32_t verify_hash_bytes() {
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

    VLOG_INFO("Start verifying Hash Bytes");

    uint32_t expected_hash=0x5271e49c;
    uint32_t exp_port = 0xa89a73bf;
    uint32_t hash = 0;
    uint16_t port = 0;
    uint8_t protocol = 6; // tcp
                          //
    struct hash_val hval;
    memset(&hval, 0, sizeof hval);

    // src/dst ip
    uint32_t ip = 0;
    ip = 0xc25814ac;
    hval.pkt.ipv4_addr ^= ip;

    // src/dst ip
    ip = 0x1aea14ac;
    hval.pkt.ipv4_addr ^= ip;

    // protocol
    hash = hash_bytes(&protocol, sizeof(protocol), hash); 
    VLOG_INFO("Port Hash: 0x%x, except=0x%x", hash, exp_port);

    // port
    port = 0x3ace;
    hval.tp_port ^= port;

    port = 0x5000;
    hval.tp_port ^= port;

    // finallize hash
    hash = hash_bytes(&hval, sizeof(hval), hash);

    VLOG_INFO("Multiple bytes Hash: 0x%x, expect=0x%x, len=%d", hash, expected_hash, sizeof(hval));

    return hash;
}

uint32_t verify_murmur_hash_4bytes() {
    VLOG_INFO("Start verifying mhash 4 Bytes");

    uint32_t expected_hash=0xf4c0ec39;
    uint32_t hash = 0;
    uint8_t buf[4];

    buf[0]=0;
    buf[1]=1;
    buf[2]=2;
    buf[3]=3;

    hash = murmurhash((char*)buf, sizeof(buf), 0);
    VLOG_INFO("Multiple bytes mhash: 0x%x, expect=0x%x, len=%d", hash, expected_hash, sizeof(buf));

    return hash;
}

uint32_t verify_murmur_hash_bytes() {
    VLOG_INFO("Start verifying murmur hash Bytes");

    uint32_t expected_hash=0x805eab91;
    uint32_t hash = 0;
    uint16_t port = 0;

    struct hash_val hval;
    memset(&hval, 0, sizeof hval);

    // src/dst ip
    uint32_t ip = 0;
    ip = 0xc25814ac;
    hval.pkt.ipv4_addr ^= ip;

    // src/dst ip
    ip = 0x1aea14ac;
    hval.pkt.ipv4_addr ^= ip;

    // port
    port = 0x3ace;
    hval.tp_port ^= port;

    port = 0x5000;
    hval.tp_port ^= port;

#if 0
    uint8_t *p = (uint8_t*)&hval;
    for (int i=0; i<sizeof(hval); i++) {
        if (i > 0 && i%4 == 0) {
            printf("\n");
        }
        printf("%d ",  p[i]);
    }
    printf("\n");
#endif

    hash = murmurhash((char*)&hval, sizeof(hval), 0);
    VLOG_INFO("Multiple bytes mhash: 0x%x, expect=0x%x, len=%d", hash, expected_hash, sizeof(hval));

    return hash;
}

uint32_t verify_jhash_4bytes() {
    VLOG_INFO("Start verifying mhash 4 Bytes");

    uint32_t expected_hash=0xe4cf1d42;
    uint32_t hash = 0;
    uint8_t buf[4];

    buf[0]=0;
    buf[1]=1;
    buf[2]=2;
    buf[3]=3;

    hash = jhash_bytes((char*)buf, sizeof(buf), 0);
    VLOG_INFO("Multiple bytes jhash: 0x%x, expect=0x%x, len=%d", hash, expected_hash, sizeof(buf));

    return hash;
}

uint32_t verify_jhash_bytes() {
    VLOG_INFO("Start verifying jhash Bytes");

    uint32_t expected_hash=0x3adcbda7;
    uint32_t hash = 0;
    uint16_t port = 0;

    struct hash_val hval;
    memset(&hval, 0, sizeof hval);

    // src/dst ip
    uint32_t ip = 0;
    ip = 0xc25814ac;
    hval.pkt.ipv4_addr ^= ip;

    // src/dst ip
    ip = 0x1aea14ac;
    hval.pkt.ipv4_addr ^= ip;

    // port
    port = 0x3ace;
    hval.tp_port ^= port;

    port = 0x5000;
    hval.tp_port ^= port;

#if 0
    uint8_t *p = (uint8_t*)&hval;
    for (int i=0; i<sizeof(hval); i++) {
        if (i > 0 && i%4 == 0) {
            printf("\n");
        }
        printf("0x%x ",  p[i]);
    }
    printf("\n");
#endif

    hash = jhash_bytes((char*)&hval, sizeof(hval), 0);
    VLOG_INFO("Multiple bytes jhash: 0x%x, expect=0x%x, len=%d", hash, expected_hash, sizeof(hval));

    return hash;
}


uint32_t get_hash(struct tv_entry *in) {
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

int add_bucket(struct group_dpif *group, int bkt_cnt, int weight) {
    int i;
    struct ofputil_bucket *bkt;

    for (i=0; i<bkt_cnt; i++) {
        bkt = calloc(1, sizeof(struct ofputil_bucket));

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

void maglev_verify(test_vector_t *tv) {
    VLOG_INFO("Start verifying Maglev: GroupId=%d, hash_tab_idx=%d, num_bkts=%d, bkt_weight=%d, num_tv=%d", 
              tv->maglev_id,
              tv->maglev_hash_table_size_index,
              tv->num_buckets,
              tv->bucket_weight,
              tv->num_tv_entries);

    struct group_dpif group;

    memset(&group, 0, sizeof(group));
    ovs_list_init(&group.up.buckets);

    // set group info
    group.hash_alg = tv->maglev_hash_table_size_index;  // table size: 0 ~ 10
    group.hash_basis = 0;
    group.up.group_id = tv->maglev_id;

    // add buckets
    int nbkts = tv->num_buckets;
    int weight = tv->bucket_weight;
    add_bucket(&group, nbkts, weight);

    mh_construct(&group);
    
    struct tv_entry *entry;
    uint32_t calc_hash;
    uint32_t idx=1;

    // verify them
    VLOG_INFO("Verify Maglev Hash result");

    struct ofputil_bucket *bkt;
    LIST_FOR_EACH (entry, node, &tv->tv_list) {
        calc_hash = get_hash(entry);

        bkt = mh_lookup(&group, calc_hash);
        if (bkt->bucket_id != entry->bkt_id) {
            VLOG_INFO("%d: mismatched: bkt_id=%d:%d hash=0x%x:0x%x", idx, 
                      bkt->bucket_id, entry->bkt_id,
                      calc_hash, entry->hash);

            tv->mismatched ++;
        }

        idx ++;
    }

    VLOG_INFO("Verification Result: Total=%d, Mismatched=%d", idx, tv->mismatched);

    mh_destruct(&group);
    free_bucket(&group);

    VLOG_INFO("End maglev test ");
}

void print_usage(char *pgname) {
    printf("usage: %s [-h] [-v] [-n name]\n", pgname);
    printf("options:\n");
    printf("  -h       : print this help  \n");
    printf("  -f [name]: test vector file name. \n");
}


int main(int argc, char *argv[]) {
    int opt;
    char *test_vect_file = NULL;

    while ((opt = getopt(argc, argv, "hf:")) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'f':
                test_vect_file = optarg;
                break;
            case '?':
                print_usage(argv[0]);
                return 1;
        }
    }

    if (test_vect_file == NULL) {
        VLOG_WARN("test vector file name required");
        return 1;
    }

    VLOG_INFO("Start maglev simulater ");

    verify_crc32();
    verify_hash_byte();
    verify_hash_bytes();
    verify_jhash_4bytes();
    verify_jhash_bytes();
    verify_murmur_hash_4bytes();
    verify_murmur_hash_bytes();

    // verify test vector
    // load test vectors to be verified
    test_vector_t *tv = load_test_vector(test_vect_file);
    if (tv == NULL) {
        return 1;
    }

    maglev_verify(tv);

    free_test_vector(tv);

    VLOG_INFO("End maglev simulater ");

    return 0;
}
