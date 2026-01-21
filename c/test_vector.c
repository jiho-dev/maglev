#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "test_vector.h"

test_vector_t* load_test_vector(char *test_vect_file) 
{
    FILE *fp;
    char buffer[1024];
    char *fname = test_vect_file;
    test_vector_t *tv = calloc(1, sizeof(test_vector_t));

    VLOG_INFO("Load hash entries from %s", fname);

    ovs_list_init(&tv->tv_list);

    fp = fopen(fname, "r");
    if (fp == NULL) {
        VLOG_ERROR("failed to open file: %s", fname);
        return NULL;
    }

    char *token;
    char *delimiters = " :";
    char *b;
    int begin_hash = 0;

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        b = trim(buffer);
        if (strlen(buffer) < 1) {
            continue;
        } else if (buffer[0] == '#') {
            continue;
        } 

        if (begin_hash == 0) {
            // continue
            token = strtok(b, delimiters);
            if (strcmp("maglev_hash_table_size_index" , token) == 0) {
                token = strtok(NULL, delimiters);
                tv->maglev_hash_table_size_index = atoi(token);
                continue;
            } else if (strcmp("maglev_id" , token) == 0) {
                token = strtok(NULL, delimiters);
                tv->maglev_id = atoi(token);
                continue;
            } else if (strcmp("maglev_hash2" , token) == 0) {
                token = strtok(NULL, delimiters);
                tv->maglev_hash2 = strdup(token);
                continue;
            } else if (strcmp("num_buckets" , token) == 0) {
                token = strtok(NULL, delimiters);
                tv->num_buckets = atoi(token);
                continue;
            } else if (strcmp("bucket_weight" , token) == 0) {
                token = strtok(NULL, delimiters);
                tv->bucket_weight = atoi(token);
                continue;
            } else if (token[0] < '0' || '9' < token[0]) {
                // not IP string
                VLOG_INFO("Unknown data: %s", b);
                continue;
            } else {
                begin_hash = 1;
            }
        } else {
            token = strtok(b, delimiters);
        }

        struct tv_entry *entry = calloc(1, sizeof(struct tv_entry));
        entry->protocol = 6; // tcp

        int idx=0;
        char *endptr;
        while (token != NULL) {
            switch (idx) {
            case 0:
                entry->sip = ip2int(token);
                break;
            case 1:
                entry->sport =  atoi(token);
                entry->sport = htons(entry->sport);
                break;
            case 2:
                entry->dip = ip2int(token);
                break;
            case 3:
                entry->dport = atoi(token);
                entry->dport = htons(entry->dport);
                break;
            case 4:
                entry->protocol = atoi(token);
                break;
            case 5:
                entry->hash = strtol(token, &endptr, 16);
                break;
            case 6:
                entry->bkt_id =  atoi(token);
                break;
            }

            idx++;
            token = strtok(NULL, delimiters);
        }

        ovs_list_init(&entry->node);
        ovs_list_push_back(&tv->tv_list, &entry->node);
        tv->num_tv_entries ++;

#if 0
        VLOG_DEBUG("Hash node(%d): 0x%x:0x%x->0x%x:0x%x %d 0x%x %d", 
                   tv->num_tv_entries,
                   entry->sip,
                   entry->sport,
                   entry->dip,
                   entry->dport,
                   entry->protocol,
                   entry->hash,
                   entry->bkt_id);
#endif

    }

    VLOG_INFO("Hash nodes to be verified: %d", tv->num_tv_entries);

    fclose(fp);

    return tv;
}

int free_test_vector(test_vector_t *tv) 
{
    struct tv_entry *h, *next;

    LIST_FOR_EACH_SAFE(h, next, node, &tv->tv_list) {
        ovs_list_remove(&h->node);

        //VLOG_INFO("free input data: %p", h);
        free(h);
    }

    return 0;
}

