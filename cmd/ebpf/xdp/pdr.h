// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/ipv6.h>

#include "xdp/sdf_filter.h"
#include "xdp/sizing.h"

enum outer_header_removal_values {
    OHR_GTP_U_UDP_IPv4 = 0,
    OHR_GTP_U_UDP_IPv6 = 1,
    OHR_UDP_IPv4 = 2,
    OHR_UDP_IPv6 = 3,
    OHR_IPv4 = 4,
    OHR_IPv6 = 5,
    OHR_GTP_U_UDP_IP = 6,
    OHR_VLAN_S_TAG = 7,
    OHR_S_TAG_C_TAG = 8,
};

// Possible optimizations:
// 0. Store SDFs in a separate map. PDR will have only id of corresponding SDF.
// 1. Combine SrcAddress.Type and DstAddress.Type into one __u8 field. Then to retrieve and put data will be used operators & and | .
// 2. Put all fields into one big structure. Sort in specific order to reduce paddings inside structure.

struct pdr {
    __u32 far_id;
    __u32 qer_id[4];
    __u8 qer_count;
    __u32 urr_id[URR_LIST_SIZE];
    __u8 outer_header_removal;
 __u8 outer_header_removal_present;
};

// TS 29.244 V20.1.0 clauses 5.2.1 and 8.2.11: one independently
// replaceable entry per PDR, ordered by increasing numeric Precedence.
#define PDR_LIST_SIZE 4
#define QFI_LIST_SIZE 8
struct pdr_entry {
    __u8 match_mode; // 0: full PDI, 1: any source, 2: Access, 3: Core
    struct pdr pdr;
    struct pdr return_pdr;
    __u8 return_nr_flag;
    __u32 pdr_id;
    __u32 precedence;
    __u64 notify;
    __u32 ue_ip4;
    __u32 ue_mask4;
    __u8 ue_ip6[16];
    __u8 ue_mask6[16];
    __u8 ue_ip4_present;
    __u8 ue_ip6_present;
    __u32 assigned_ip4;
    __u8 assigned_ip6[16];
    __u8 assigned_mask6[16];
    __u8 assigned_ip4_present;
    __u8 assigned_ip6_present;
    __u8 ue_destination;
    __u8 source_interface_present;
    __u8 source_interface;
    __u8 trace_flag;
    __u8 nr_flag;
    __u8 sdf_count;
    __u8 qfi_count;
    __u8 qfis[QFI_LIST_SIZE];
    struct sdf_filter sdf_filters[SDF_LIST_SIZE];
};

struct pdr_info {
    __u64 session_id;
    __u32 count;
    struct pdr_entry entries[PDR_LIST_SIZE];
};

// One aligned scalar is published in place using BPF_F_LOCK. Packet readers
// load slot once; they never retain a pointer into a recyclable hash element.
// Linux v5.15/v6.18 kernel/bpf/hashtab.c:htab_map_update_elem.
struct pdr_index {
    struct bpf_spin_lock lock;
    __u32 slot;
};
struct pdr_bucket {
    __u32 key;
    __u32 kind; // 0: TEID, 1: IPv4 destination (network byte order)
    struct pdr_info info;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct pdr_bucket);
    __uint(max_entries, PDR_MAP_SIZE * 4 + 1);
} pdr_buckets SEC(".maps");

/* ipv4 -> stable bucket slot */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct pdr_index);
    __uint(max_entries, PDR_MAP_SIZE);
} pdr_map_downlink_ip4 SEC(".maps");

struct ipv6_pdr_key {
    __u32 prefix_length;
    __u8 address[16];
};

/* IPv6 address/prefix -> session PDRs */
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv6_pdr_key);
    __type(value, struct pdr_info);
    __uint(max_entries, PDR_MAP_SIZE);
} pdr_map_downlink_ip6 SEC(".maps");


/* teid -> PDR */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct pdr_index);
    __uint(max_entries, PDR_MAP_SIZE);
} pdr_map_teid_ip4 SEC(".maps");

// Slot memory is never freed by the kernel. It is reused only after the
// userspace publication journal's RCU grace. A deleted hash element can still
// be recycled on Linux >=6.1: validate the bucket key and retry once.
static __always_inline struct pdr_info *lookup_pdr4(void *map, __u32 key, __u32 kind, int *stale) {
    for (int attempt=0; attempt<2; attempt++) {
        struct pdr_index *index=bpf_map_lookup_elem(map,&key);
        if (!index) continue;
        __u32 slot=*(volatile __u32 *)&index->slot;
        struct pdr_bucket *bucket=bpf_map_lookup_elem(&pdr_buckets,&slot);
        if (slot && bucket && bucket->key==key && bucket->kind==kind)
            return &bucket->info;
        *stale=1;
    }
    return 0;
}

enum far_action_mask {
    FAR_DROP = 0x01,
    FAR_FORW = 0x02,
    FAR_BUFF = 0x04,
    FAR_NOCP = 0x08,
    FAR_DUPL = 0x10,
    FAR_IPMA = 0x20,
    FAR_IPMD = 0x40,
    FAR_DFRT = 0x80,
};

enum outer_header_creation_values {
    OHC_GTP_U_UDP_IPv4 = 0x01,
    OHC_GTP_U_UDP_IPv6 = 0x02,
    OHC_UDP_IPv4 = 0x04,
    OHC_UDP_IPv6 = 0x08,
};

struct far_info {
    __u8 action;
    __u8 outer_header_creation;
    __u32 teid;
    __u32 remoteip;
    /* first octet DSCP value in the Type-of-Service, second octet shall contain the ToS/Traffic Class mask field, which shall be set to "0xFC". */
    __u16 transport_level_marking;
    __u8 destination_interface;
    __u8 destination_interface_present;
};

/* FAR ID -> FAR */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct far_info);
    __uint(max_entries, FAR_MAP_SIZE);
} far_map SEC(".maps");
