/* Maglev Hashing scheduling module
 *
 * Authors for IPVS: Inju Song <inju.song@navercorp.com>
 * Modified for OpenvSwitch: Jiho Jung <jiho.jung88@gmail.com>
 *
 */

/* The mh algorithm is to assign a preference list of all the lookup
 * table positions to each destination and populate the table with
 * the most-preferred position of destinations. Then it is to select
 * destination with the hash key of source IP address through looking
 * up a the lookup table.
 *
 * The algorithm is detailed in:
 * [3.4 Consistent Hasing] 
 * https://www.usenix.org/system/files/conference/nsdi16/nsdi16-paper-eisenbud.pdf
 *
 */

/*
 * modified for OpenvSwitch Group Function
 */

//#define _MH_DEBUG 1

#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>

#include "log.h"
#include "list.h"
#include "jhash.h"
#include "hash.h"
#include "maglev_hash_utils.h"
#include "maglev_hash.h"
#include "group.h"

//VLOG_DEFINE_THIS_MODULE(maglev_hash);

#define CONFIG_MH_TAB_INDEX 5 /* 4093 */

static void mh_reset_state(struct maglev_state *s);
static int mh_get_dest_count(struct maglev_hash_service *svc);

///////////////////////////////////////////


void * xcalloc(size_t count, size_t size)
{
    void *p = count && size ? calloc(count, size) : malloc(1);
    return p;
}

static inline uint32_t mh_hash1(uint8_t *data, uint32_t len)
{
    return hash_bytes(data, len, 0);
}

static inline uint32_t mh_hash2(uint8_t *data, uint32_t len)
{
    return jhash_bytes(data, len, 0);
}

static inline uint32_t mh_get_table_size(uint32_t idx) {
    /* [0]     : for debugging
     * [1 ~ 10]: valid
     */

    static uint32_t mh_primes[] = {11, 251, 509, 1021, 2039, 4093, 8191, 16381, 32749, 65521, 131071};

    uint32_t len = sizeof(mh_primes) / sizeof(mh_primes[0]);

    if (idx > len) {
        idx = CONFIG_MH_TAB_INDEX;
    }

    return mh_primes[idx];
}

/* Helper function to determine if server is unavailable */
static inline uint32_t is_unavailable(struct maglev_dest *dest)
{
    //return dest->weight <= 0 || dest->flags & MH_DEST_FLAG_DISABLE;

    /* 0 weight is the draining */
    return dest->flags & MH_DEST_FLAG_DISABLE;
}

static struct maglev_dest* mh_get_lookup_dest(struct maglev_state *s, unsigned int hash_data)
{
    unsigned int hash = hash_data % s->lookup_size;
    return s->lookup[hash].dest;
}

static int mh_permutate(struct maglev_state *s, struct maglev_hash_service *svc)
{
    struct maglev_dest_setup *ds;
    struct maglev_dest *dest;
    int lw;
    uint32_t hash_data = 0;

    /* If gcd is smaller then 1, number of dests or
     * all last_weight of dests are zero. So, skip
     * permutation for the dests.
     */
    if (s->gcd < 1)
        return 0;

    /* Set dest_setup for the dests permutation */
    ds = &s->dest_setup[0];

    LIST_FOR_EACH (dest, n_list, &svc->destinations) {
        hash_data = dest->dest_id;

        ds->offset = mh_hash2((uint8_t*)&hash_data, sizeof(hash_data)) % svc->table_size;
        ds->skip = mh_hash1((uint8_t*)&hash_data, sizeof(hash_data)) % (svc->table_size - 1) + 1;
        ds->perm = ds->offset;

        lw = dest->last_weight;
        ds->turns = ((lw / s->gcd) >> s->rshift) ? : (lw != 0);

        ds++;
    }

    return 0;
}

static int mh_populate(struct maglev_state *s, struct maglev_hash_service *svc)
{
    int n, c, dt_count;
    unsigned long *table;
    struct ovs_list *p;
    struct maglev_dest_setup *ds;
    struct maglev_dest *new_dest;

    /* If gcd is smaller then 1, number of dests or
     * all last_weight of dests are zero. So, skip
     * the population for the dests and reset lookup table.
     */
    if (s->gcd < 1) {
        mh_reset_state(s);
        return 0;
    }

    table =  xcalloc(BITS_TO_LONGS(svc->table_size), sizeof(unsigned long));
    if (!table)
        return -ENOMEM;

    p = &svc->destinations;
    n = 0;
    dt_count = 0;
    while (n < svc->table_size) {
        if (p == &svc->destinations)
            p = p->next;

        ds = &s->dest_setup[0];
        while (p != &svc->destinations) {
            /* Ignore added server with zero weight */
            if (ds->turns < 1) {
                p = p->next;
                ds++;
                continue;
            }

            c = ds->perm;
            /* find the available slot */
            while (test_bit(c, table)) {
                /* Add skip, mod table_size */
                ds->perm += ds->skip;

                if (ds->perm >= svc->table_size)
                    ds->perm -= svc->table_size;

                c = ds->perm;
            }

            set_bit(c, table);

            new_dest = CONTAINER_OF(p, struct maglev_dest, n_list);
            s->lookup[c].dest =  new_dest;

            if (++n == svc->table_size)
                goto out;

            if (++dt_count >= ds->turns) {
                dt_count = 0;
                p = p->next;
                ds++;
            }
        }
    }

out:
    free(table);
    return 0;
}

/* Get maglev_dest associated with supplied parameters. */
static struct maglev_dest* mh_lookup_dest(struct maglev_state *s,  uint32_t hash_data)
{
    if (!s) {
        return NULL;
    }

    struct maglev_dest *dest = mh_get_lookup_dest(s, hash_data);

    return (!dest || is_unavailable(dest)) ? NULL : dest;
}

/* As mh_lookup_dest, but with fallback if selected server is unavailable */
static inline struct maglev_dest *mh_lookup_dest_fallback(struct maglev_state *s, uint32_t hash_data)
{
    unsigned int offset, roffset;
    unsigned int hash;
    struct maglev_dest *dest;

    if (!s) {
        return NULL;
    }

    /* First try the dest it's supposed to go to */
    dest = mh_get_lookup_dest(s, hash_data);
    if (!dest)
        return NULL;

    if (!is_unavailable(dest))
        return dest;

    VLOG_INFO("selected unavailable server(id=%u:%u), reselecting", dest->gid, dest->dest_id);

    /* If the original dest is unavailable, loop around the table
     * starting from ihash to find a new dest
     */
    for (offset = 0; offset < s->lookup_size; offset++) {
        /* XXX: FIXME from ipvs code */
        roffset = offset + hash_data;
        hash = mh_hash1((uint8_t*)&roffset, sizeof(roffset));
        dest = mh_get_lookup_dest(s, hash);
        if (!dest)
            break;

        if (!is_unavailable(dest))
            return dest;

        VLOG_INFO("selected unavailable server(id=%u:%u) (offset %u), reselecting", dest->gid, dest->dest_id, roffset);
    }

    return NULL;
}

/* Assign all the hash buckets of the specified table with the service. */
static int mh_build_lookup_table(struct maglev_state *s, struct maglev_hash_service *svc)
{
    int ret=0;
    int num_dests = mh_get_dest_count(svc);

    if (num_dests > svc->table_size)
        return -EINVAL;

    if (num_dests >= 1) {
        s->dest_setup = xcalloc(num_dests, sizeof(struct maglev_dest_setup));
        if (!s->dest_setup)
            return -ENOMEM;
    }

    mh_permutate(s, svc);
    ret = mh_populate(s, svc);

    if (s->dest_setup) {
        free(s->dest_setup);
        s->dest_setup = NULL;
    }

    return ret;
}

static int mh_gcd_weight(struct maglev_hash_service *svc)
{
    struct maglev_dest *dest;
    int weight;
    int g = 0;

    LIST_FOR_EACH(dest, n_list, &svc->destinations) {
        weight = dest->last_weight;
        if (weight > 0) {
            if (g > 0)
                g = gcd(weight, g);
            else
                g = weight;
        }
    }

    return g;
}

/* To avoid assigning huge weight for the MH table,
 * calculate shift value with gcd.
 */
static int mh_shift_weight(struct maglev_hash_service *svc, int gcd)
{
    struct maglev_dest *dest;
    int new_weight, weight = 0;
    int mw, shift;

    /* If gcd is smaller then 1, number of dests or
     * all last_weight of dests are zero. So, return
     * shift value as zero.
     */
    if (gcd < 1)
        return 0;

    LIST_FOR_EACH(dest, n_list, &svc->destinations) {
        new_weight = dest->last_weight;
        if (new_weight > weight)
            weight = new_weight;
    }

    /* Because gcd is greater than zero,
     * the maximum weight and gcd are always greater than zero
     */
    mw = weight / gcd;

    int tab_bits = bitlen(svc->table_size)/2;

    /* shift = occupied bits of weight/gcd - MH highest bits */
    shift = fls(mw) - tab_bits;
    return (shift >= 0) ? shift : 0;
}

static struct maglev_state* mh_alloc_state(uint32_t table_size)
{
    struct maglev_state *s;

    /* Allocate the MH table for this service */
    s = xcalloc(1, sizeof(struct maglev_state));
    if (!s)
        return NULL;

    s->lookup = xcalloc(table_size, sizeof(struct maglev_lookup));
    if (!s->lookup) {
        free(s);
        return NULL;
    }

    s->lookup_size = table_size;

    /* refcnt starts 1 */
    //ovs_refcount_init(&s->refcnt);
    s->refcnt = 1;

    VLOG_INFO("Alloc Maglev State: state=%p, lookup_size=%u", s, table_size);

    return s;
}

static void mh_init_state(struct maglev_state *s, struct maglev_hash_service *svc)
{
    s->gcd = mh_gcd_weight(svc);
    s->rshift = mh_shift_weight(svc, s->gcd);
}

/* Reset all the hash buckets of the specified table. */
static void mh_reset_state(struct maglev_state *s)
{
    int i;

    if (!s || !s->lookup) {
        return;
    }

    for (i = 0; i < s->lookup_size; i++) {
        s->lookup[i].dest = NULL;
    }
}

static void mh_free_state(struct maglev_state *s)
{
    if (!s)
        return;

    VLOG_INFO("Free Maglev State: state=%p, lookup_size=%u", s, s->lookup_size);

    /* refcnt starts 1 */
    if (ovs_refcount_read(&s->refcnt) > 1) {
        VLOG_WARN("WARNING: Maglev State under referenced: refcnt=%d", ovs_refcount_read(&s->refcnt));
    }

    mh_reset_state(s);

    if (s->lookup) {
        free(s->lookup);
        s->lookup = NULL;
    }

    free(s);
}

static void mh_ref_state(struct maglev_state *s)
{
    ovs_refcount_ref(&s->refcnt);
}

static void mh_unref_state(struct maglev_state *s)
{
    /* ovs_refcount_unref returns the previous value */
    /* 2 means the last reference because refcnt starts 1 */ 
    if (ovs_refcount_unref(&s->refcnt) == 2) {
        // now refcnt is 1
        mh_free_state(s);
    }
}

static void mh_attach_state(struct maglev_state *s, struct maglev_hash_service *svc)
{
    struct maglev_state *old = svc->mh_state;
    if (old) {
        mh_unref_state(old);
    }

    if (s) {
        mh_ref_state(s);
    }

    svc->mh_state = s;
}

static struct maglev_state* mh_hold_state(struct maglev_hash_service *svc)
{
    if (svc == NULL || svc->mh_state == NULL) {
        return NULL;
    }

    mh_ref_state(svc->mh_state);
    return svc->mh_state;
}

static void mh_release_state(struct maglev_state *s)
{
    if (s) {
        mh_unref_state(s);
    }
}

static void mh_free_dest(struct maglev_hash_service *svc) 
{
    struct maglev_dest *dest, *next;
    LIST_FOR_EACH_SAFE(dest, next, n_list, &svc->destinations) {
        ovs_list_remove(&dest->n_list);

        VLOG_INFO("free dest: %u:%u:%u:%p", dest->gid, dest->dest_id, dest->weight, dest);
        free(dest);
    }
}

static struct maglev_dest* mh_get_dest(uint32_t id, struct maglev_hash_service *svc) 
{
    struct maglev_dest *dest;

    LIST_FOR_EACH (dest, n_list, &svc->destinations) {
        if (dest->dest_id == id) {
            return dest;
        }
    }

    return NULL;
}

static void mh_set_dest_weight(struct maglev_dest* dest, uint32_t weight)
{
    dest->weight = weight;
    dest->last_weight = weight;
}

static int mh_get_dest_count(struct maglev_hash_service *svc)
{
    int cnt=0;
    struct maglev_dest *dest;

    LIST_FOR_EACH (dest, n_list, &svc->destinations) {
        cnt ++;
    }

    return cnt;
}

static struct maglev_hash_service* mh_alloc_service(uint32_t table_size) 
{
    struct maglev_hash_service* svc;

    svc = xcalloc(1, sizeof(struct maglev_hash_service));
    if (!svc) {
        VLOG_INFO("failed to alloc memory for Maglev Hash SVC (%lu bytes)", sizeof(struct maglev_hash_service));
        return NULL;
    }

    ovs_list_init(&svc->destinations);
    svc->table_size = table_size;

    /* refcnt starts 1 */
    //ovs_refcount_init(&svc->refcnt);
    //atomic_count_init(&svc->version, 1);
    
    svc->refcnt = 1;

    VLOG_INFO("Alloc Maglev Hash SVC: svc=%p, table_size=%u", svc, table_size);
    return svc;
}

static void mh_free_service(struct maglev_hash_service* svc)
{
    VLOG_INFO("Free Maglev Hash SVC: svc=%p, table_size=%u", svc, svc->table_size);

    mh_attach_state(NULL, svc);
    mh_free_dest(svc);

    free(svc);
}

static int mh_add_dest(uint32_t gid, uint32_t id, uint16_t weight, void *data, struct maglev_hash_service *svc)
{
    int ret = 0;
    struct maglev_dest* dest = mh_get_dest(id, svc);

    if (dest != NULL) {
        //atomic_count_set(&dest->version, atomic_count_get(&svc->version));

        if ((uint16_t)dest->weight != weight) {
            VLOG_INFO("changed weight: id=%u:%u, weight: %u -> %u", 
                      dest->gid, dest->dest_id, dest->weight, weight);

            mh_set_dest_weight(dest, weight);
            ret = 1;
        }

        if (dest->data != data) {
            dest->data = data;
        }

        return ret;
    }

    dest = xcalloc(1, sizeof(struct maglev_dest));
    if (dest == NULL) {
        VLOG_INFO("failed to alloc memory for dest: size=%lu, id=%u:%u, weight=%u", 
                 sizeof(struct maglev_dest), gid, id, weight);

        return -ENOMEM;
    }

    ovs_list_init(&dest->n_list);
    //atomic_count_set(&dest->version, atomic_count_get(&svc->version));

    dest->weight = weight;
    dest->last_weight = weight;
    dest->gid = gid;
    dest->dest_id = id;
    dest->data = data;

    VLOG_INFO("add dest: %u:%u:%u:%p", dest->gid, dest->dest_id, dest->weight, dest);

    ovs_list_push_back(&svc->destinations, &dest->n_list);

    return 1;
}

static int mh_build_hash_table(struct maglev_hash_service *svc)
{
    int ret;
    struct maglev_state *s, *old;
    int num_dests = mh_get_dest_count(svc);

    VLOG_INFO("Building Maglev Hash Lookup Table: svc=%p, flags=0x%x, table_size=%u, dest cnt=%d", 
              svc,
              svc->flags,
              svc->table_size, 
              num_dests);

    old = mh_hold_state(svc);
    if (old) {
        s = old;
    } else {
        /* Allocate the MH table for this service */
        s =  mh_alloc_state(svc->table_size);
        if (!s)
            return -ENOMEM;

        VLOG_INFO("Maglev Lookup Table (memory=%lu bytes) allocated for current service",
                  sizeof(struct maglev_lookup) * svc->table_size);
    }

    mh_init_state(s, svc);

    /* Assign the lookup table with current dests */
    ret = mh_build_lookup_table(s, svc);
    if (ret < 0) {
        VLOG_INFO("failed to build lookup table: err=%d", ret);

        if (old == NULL) {
            mh_free_state(s);
        }

        return ret;
    }

    if (old == s) {
        mh_release_state(s);
    } else {
        /* No more failures, attach state */
        /* the old one would be released if exists */
        mh_attach_state(s, svc);
    }

    return 0;
}

static int mh_dump_lookup_table(struct maglev_hash_service *svc) 
{
    struct dump_cnt {
        struct maglev_dest *dest;
        uint32_t cnt;
    };

    struct maglev_state *s = mh_hold_state(svc);
    if (!s)
        return 0;

    int num_dests = mh_get_dest_count(svc);
    struct maglev_dest *dest;
    int i,k;
    struct dump_cnt *dcnt = xcalloc(num_dests, sizeof(struct dump_cnt));

    i=0;
    LIST_FOR_EACH (dest, n_list, &svc->destinations) {
        dcnt[i].dest = dest;
        dcnt[i].cnt = 0;
        i ++;
    }

    struct maglev_lookup *lookup = svc->mh_state->lookup;
    for (i=0; i<svc->table_size; i++) {
        dest = lookup[i].dest;
        if (dest == NULL) {
            continue;
        }

        for (k=0; k<num_dests; k++) { 
            if (dest == dcnt[k].dest) {
                dcnt[k].cnt ++;
            }
        }

        //VLOG_DBG("Maglev Look(%d): dest=%u:%u:%u:%p", i, dest->gid, dest->dest_id, dest->weight, dest);
    }

    for (i=0; i<num_dests; i++) {
        VLOG_INFO("Maglev Dest(%d): id=%u:%u:%u:%p, occupying lookup entry cnt=%u", 
                  i, 
                  dcnt[i].dest->gid, dcnt[i].dest->dest_id, dcnt[i].dest->weight, dcnt[i].dest, dcnt[i].cnt);
    }

    if (s)
        mh_release_state(s);

    free(dcnt);

    return 0;
}

static void mh_build(struct group_dpif *group)
{
    struct maglev_hash_service* mh_svc;
    struct ofputil_bucket *bucket;
    uint32_t tab_size=0;

    if (group->mh_svc) {
        mh_free_service(group->mh_svc);
    }

    group->mh_svc = NULL;

    tab_size = mh_get_table_size((uint32_t)group->hash_alg);
    mh_svc = mh_alloc_service(tab_size);
    if (mh_svc == NULL) {
        VLOG_INFO("failed to alloc a new Maglev Hash SVC: group=%u(%p)", group->up.group_id, group);
        return;
    }

    mh_svc->flags = group->hash_basis;

    VLOG_INFO("Start building a new Maglev Hash SVC: group=%u(%p), mh_svc=%p, flags=0x%x, table_size=%u(%u)", 
              group->up.group_id, group, mh_svc, mh_svc->flags, tab_size, group->hash_alg);

    LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
        mh_add_dest(group->up.group_id, bucket->bucket_id, bucket->weight, bucket, mh_svc);
    }

    int ret;
    ret = mh_build_hash_table(mh_svc);
    if (ret != 0) {
        VLOG_INFO("failed to build Maglev Hash Lookup Table: group=%u(%p), mh_svc=%p, ret=%d", 
                 group->up.group_id, group, mh_svc, ret);
        mh_free_service(mh_svc);
    }

    if (mh_svc) {
        mh_dump_lookup_table(mh_svc);
    }

    // XXX: use refcnt
    group->mh_svc = mh_svc;
}


/* Maglev Hashing lookup */
static struct maglev_dest* mh_lookup_(struct maglev_hash_service *svc, uint32_t hash_data)
{
    struct maglev_dest *dest = NULL;
    struct maglev_state *s;

    if (svc == NULL)
        return NULL;

    s = mh_hold_state(svc);
    if (!s)
        return NULL;

    if (svc->flags & MH_FLAG_FALLBACK)
        dest = mh_lookup_dest_fallback(s, hash_data);
    else
        dest = mh_lookup_dest(s, hash_data);

    mh_release_state(s);

#if 0
    if (!dest) {
        VLOG_INFO("Lookup Dest is unavailable: hash_data=%u", hash_data);
    } 
#endif

    return dest;
}

/////////////////////////////

void mh_construct(struct group_dpif *new_group)
{
    VLOG_INFO("Construct Maglev Hash: new group=%u(%p), tab_size_idx=%u",
              new_group->up.group_id, new_group, (uint32_t)new_group->hash_alg);

    mh_build(new_group);
}

void mh_destruct(struct group_dpif *group)
{
    if (group == NULL || group->mh_svc == NULL)
        return;

    struct maglev_hash_service *svc = group->mh_svc;

    VLOG_INFO("Destruct Maglev Hash: group=%u(%p), mh_svc=%p, method=%d", 
              group->up.group_id, group, svc, group->selection_method);

    mh_free_service(group->mh_svc);
    group->mh_svc = NULL;
}

struct ofputil_bucket* mh_lookup(struct group_dpif *group, uint32_t hash_data)
{
    if (group == NULL || group->mh_svc == NULL) {
        return NULL;
    }

    struct maglev_dest *dest = mh_lookup_(group->mh_svc, hash_data);
    if (dest == NULL) {
        return NULL;
    }

    return (struct ofputil_bucket *)dest->data;
}
