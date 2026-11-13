#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <stdio.h>

static void *scripted_lookup(void *map, const void *key);
// Compile the shipped helper, replacing only the kernel lookup primitive so
// the two attempts can be driven deterministically.
#define bpf_map_lookup_elem scripted_lookup
#include "xdp/pdr.h"

static int mode, calls;
static struct pdr_index index_value;
static struct pdr_bucket good = {.key=100,.kind=0,.info={.session_id=10}};
static struct pdr_bucket wrong_key = {.key=200,.kind=0};
static struct pdr_bucket wrong_kind = {.key=100,.kind=1};

static void *scripted_lookup(void *map, const void *key) {
    if (map != &pdr_buckets) {
        calls++;
        if (mode==3 || (mode==1 && calls==1) || (mode==2 && calls==2)) return 0;
        index_value.slot=mode==6 ? 0 : mode==7 ? 999999 : calls;
        return &index_value;
    }
    if (mode==7) return 0;
    if (mode==4 && calls==1) return &wrong_kind;
    if ((mode==0 || mode==2) && calls==1) return &wrong_key;
    return &good;
}

int main(void) {
    struct {int mode,found,calls,stale;} cases[]={
        {0,1,2,1}, // wrong key then valid
        {1,1,2,0}, // missing then valid
        {2,0,2,1}, // wrong key then missing: no Error Indication
        {3,0,2,0}, // truly absent
        {4,1,2,1}, // wrong map kind then valid
        {5,1,1,0}, // valid on first lookup
        {6,0,2,1}, // slot zero is reserved
        {7,0,2,1}, // missing slot
    };
    for (unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        mode=cases[i].mode;calls=0;int stale=0;
        struct pdr_info *p=lookup_pdr4(&pdr_map_teid_ip4,100,0,&stale);
        if (!!p!=cases[i].found || calls!=cases[i].calls || stale!=cases[i].stale || (p && p->session_id!=10)) {
            fprintf(stderr,"mode=%d found=%d calls=%d stale=%d\n",mode,!!p,calls,stale);
            return 1;
        }
    }
    return 0;
}
