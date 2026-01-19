#ifndef __GROUP__
#define __GROUP__ 

#include "list.h"
#include "maglev_hash.h"

struct ofputil_bucket {
    struct ovs_list list_node;

    uint16_t weight;            /* Relative weight, for "select" groups. */

#if 0
    ofp_port_t watch_port;      /* Port whose state affects whether this bucket
                                 * is live. Only required for fast failover
                                 * groups. */
    uint32_t watch_group;       /* Group whose state affects whether this
                                 * bucket is live. Only required for fast
                                 * failover groups. */
#endif

    uint32_t bucket_id;         /* Bucket Id used to identify bucket*/
    //struct ofpact *ofpacts;     /* Series of "struct ofpact"s. */
    //size_t ofpacts_len;         /* Length of ofpacts, in bytes. */

    //struct bucket_counter stats;
};

struct ofgroup {
#if 0
    struct cmap_node cmap_node; /* In ofproto's "groups" cmap. */

    /* Group versioning. */
    struct versions versions;

    /* Number of references.
     *
     * This is needed to keep track of references to the group in the xlate
     * module.
     *
     * If the main thread removes the group from an ofproto, we need to
     * guarantee that the group remains accessible to users of
     * xlate_group_actions and the xlate_cache, as the xlate_cache will not be
     * cleaned up until the corresponding datapath flows are revalidated. */
    struct ovs_refcount ref_count;

    /* No lock is needed to protect the fields below since they are not
     * modified after construction. */
    struct ofproto * const ofproto;  /* The ofproto that contains this group. */
#endif
    uint32_t group_id;
    struct ovs_list buckets;    /* Contains "struct ofputil_bucket"s. */
    uint32_t n_buckets;
#if 0
    const enum ofp11_group_type type; /* One of OFPGT_*. */
    bool being_deleted;               /* Group removal has begun. */

    const long long int created;      /* Creation time. */
    const long long int modified;     /* Time of last modification. */

    const struct ovs_list buckets;    /* Contains "struct ofputil_bucket"s. */
    const uint32_t n_buckets;

    struct ofputil_group_props props;

    struct rule_collection rules OVS_GUARDED;   /* Referring rules. */
#endif
};


struct group_dpif {
	struct ofgroup up;

	//enum group_selection_method selection_method;
	//enum ovs_hash_alg hash_alg;       /* dp_hash algorithm to be applied. */
	int selection_method;
	int hash_alg;						/* dp_hash algorithm to be applied. */
	uint32_t hash_basis;                /* Basis for dp_hash. */
	uint32_t hash_mask;                 /* Used to mask dp_hash (2^N - 1).*/
	struct ofputil_bucket **hash_map;   /* Map hash values to buckets. */
	struct maglev_hash_service* mh_svc;
};


#endif
