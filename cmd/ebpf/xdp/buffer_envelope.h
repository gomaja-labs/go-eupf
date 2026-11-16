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
// Only configured generic-mode attachments can receive a private envelope.
struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,65536);
    __uint(map_flags,BPF_F_NO_PREALLOC|BPF_F_RDONLY_PROG);
    __type(key,__u32);
    __type(value,__u32);
} buffer_generic_ingress SEC(".maps");
struct buffer_continuation_counters { __u64 passed,rejected; };
struct {
    __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries,1);
    __type(key,__u32);
    __type(value,struct buffer_continuation_counters);
} buffer_continuation_stat SEC(".maps");

#ifdef BUFFER_ADMISSION
static __noinline int buffer_consume_envelope(struct xdp_md *ctx) {
    void *data=(void *)(long)ctx->data,*end=(void *)(long)ctx->data_end;
    // Ordinary Local Experimental traffic has the base unknown-EtherType
    // action, including short frames. Only our magic identifies an attempt.
    if (data+ETH_HLEN+sizeof(__u32)>end) return DEFAULT_XDP_ACTION;
    __u32 magic;
    __builtin_memcpy(&magic,data+ETH_HLEN,sizeof(magic));
    if (magic!=BUFFER_CURSOR_MAGIC) return DEFAULT_XDP_ACTION;
    __u32 zero=0,ingress=ctx->ingress_ifindex;
    struct buffer_continuation_counters *stat=bpf_map_lookup_elem(&buffer_continuation_stat,&zero);
    if (data+BUFFER_ENVELOPE_SIZE+ETH_HLEN>end) goto invalid;
    struct buffer_cursor cursor;
    __builtin_memcpy(&cursor,data+ETH_HLEN,sizeof(cursor));
    __u64 *token=bpf_map_lookup_elem(&buffer_token,&zero);
    __u32 *generic=bpf_map_lookup_elem(&buffer_generic_ingress,&ingress);
    if (!token || cursor.token!=*token || !cursor.ingress || cursor.ingress!=ingress ||
        !generic || !*generic) goto invalid;
    if (bpf_xdp_adjust_head(ctx,BUFFER_ENVELOPE_SIZE)) goto invalid;
    if (stat) stat->passed++;
    return XDP_PASS;
invalid:
    if (stat) stat->rejected++;
    return DEFAULT_XDP_ACTION;
}
#endif
