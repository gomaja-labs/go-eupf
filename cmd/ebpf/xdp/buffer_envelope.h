// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors
#pragma once

// IEEE Std 802 Local Experimental EtherType 1. The private envelope is never
// a user packet: authenticate it before parsing, padding or charging traffic.
#define BUFFER_ETHERTYPE 0x88b5
#define BUFFER_CURSOR_MAGIC 0x42554646
#define BUFFER_ENVELOPE_SIZE 30
struct buffer_cursor {
    __u32 magic,ingress;
    __u64 token;
} __attribute__((packed));
struct {
    __uint(type,BPF_MAP_TYPE_ARRAY);
    __uint(max_entries,1);
    __uint(map_flags,BPF_F_RDONLY_PROG);
    __type(key,__u32);
    __type(value,__u64);
} buffer_token SEC(".maps");
struct buffer_continuation_counters { __u64 passed,dropped; };
struct {
    __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries,1);
    __type(key,__u32);
    __type(value,struct buffer_continuation_counters);
} buffer_continuation_stat SEC(".maps");

#ifdef BUFFER_ADMISSION
static __noinline int buffer_consume_envelope(struct xdp_md *ctx) {
    void *data=(void *)(long)ctx->data,*end=(void *)(long)ctx->data_end;
    __u32 zero=0;
    struct buffer_continuation_counters *stat=bpf_map_lookup_elem(&buffer_continuation_stat,&zero);
    if (!stat) return XDP_DROP;
    if (data+BUFFER_ENVELOPE_SIZE+ETH_HLEN>end) goto invalid;
    struct buffer_cursor cursor;
    __builtin_memcpy(&cursor,data+ETH_HLEN,sizeof(cursor));
    __u64 *token=bpf_map_lookup_elem(&buffer_token,&zero);
    if (cursor.magic!=BUFFER_CURSOR_MAGIC || !token || cursor.token!=*token ||
        !cursor.ingress || cursor.ingress!=ctx->ingress_ifindex) goto invalid;
    if (bpf_xdp_adjust_head(ctx,BUFFER_ENVELOPE_SIZE)) goto invalid;
    stat->passed++;
    return XDP_PASS;
invalid:
    stat->dropped++;
    return XDP_DROP;
}
#endif
