// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors
#pragma once

#ifdef BUFFER_CONTINUATION
#include <linux/pkt_cls.h>

#define BUFFER_OUTPUT_SIZE (BUFFER_FRAME_SIZE+64)
struct buffer_render_key {
    __u64 session_id,cookie,sequence;
    __u32 lane,reserved;
};
struct buffer_render_result {
    __u64 status;
    __u32 action,ifindex,ingress_ifindex,length;
    __u64 reserved;
    __u8 packet[BUFFER_OUTPUT_SIZE];
};
struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(map_flags,BPF_F_NO_PREALLOC);
    __uint(max_entries,4096);
    __type(key,struct buffer_render_key);
    __type(value,struct buffer_render_result);
} buffer_rendered SEC(".maps");
struct {
    __uint(type,BPF_MAP_TYPE_ARRAY);
    __uint(max_entries,1);
    __type(key,__u32);
    __type(value,struct buffer_render_key);
} buffer_current SEC(".maps");

// Only the serialized private renderer uses this key. Ordinary forwarding
// neither reads nor writes these maps. A result lives until packet completion.
static __always_inline struct buffer_render_result *buffer_current_result(void) {
    __u32 zero=0;
    struct buffer_render_key *key=bpf_map_lookup_elem(&buffer_current,&zero);
    return key ? bpf_map_lookup_elem(&buffer_rendered,key) : 0;
}
static __always_inline void buffer_capture_route(__u32 ifindex) {
    struct buffer_render_result *result=buffer_current_result();
    if (result) result->ifindex=ifindex;
}
static __always_inline void buffer_result_admitted(void) {
    struct buffer_render_result *result=buffer_current_result();
    if (result) { result->action=XDP_DROP;result->length=0;result->status=2; }
}

// Test-run can repeat after an interrupted syscall. The first invocation owns
// processing; later invocations read its saved result without charging again.
// TS 29.244 V20.1.0 clause 5.2.4.2: previously processed packets stay processed.
static __noinline int buffer_result_finish(struct xdp_md *ctx, int action, __u32 output) {
    struct buffer_render_result *result=buffer_current_result();
    if (!result) return XDP_ABORTED;
    result->action=action;
    if (output) result->ifindex=output;
    if (action==XDP_TX && !result->ifindex) result->ifindex=result->ingress_ifindex;
    result->length=0;
    if (action==XDP_DROP || action==XDP_ABORTED) { result->status=2;return XDP_DROP; }
    __u64 raw=(__u64)ctx->data_end-ctx->data;
    if (raw<14 || raw>BUFFER_OUTPUT_SIZE) { result->action=XDP_ABORTED;result->status=2;return XDP_DROP; }
    __u32 length=raw;
    asm volatile("" : "+r"(length));length &= 0xfff;
    if (length<14 || length>BUFFER_OUTPUT_SIZE) { result->action=XDP_ABORTED;result->status=2;return XDP_DROP; }
    if (bpf_probe_read_kernel(result->packet,length,(void *)(long)ctx->data)) result->action=XDP_ABORTED;
    else result->length=length;
    result->status=2;
    return XDP_PASS;
}
#define BUFFER_RETURN(ctx,action) return buffer_result_finish(ctx,action,0)

// A private veth carries an eight-octet cursor after Ethernet. Redirecting to
// original ingress at TC bypasses XDP and preserves kernel forwarding/ICMP,
// including TTL, MTU and neighbour handling. Linux bpf_redirect BPF_F_INGRESS.
SEC("tc/upf_buffer_kernel")
int upf_buffer_kernel_func(struct __sk_buff *skb) {
    if (bpf_skb_pull_data(skb,22)) return TC_ACT_SHOT;
    void *data=(void *)(long)skb->data;
    void *end=(void *)(long)skb->data_end;
    if (data+22>end) return TC_ACT_SHOT;
    __u32 magic,ingress;
    __builtin_memcpy(&magic,data+14,4);
    __builtin_memcpy(&ingress,data+18,4);
    if (magic!=0x42554646 || !ingress || ingress==skb->ifindex) return TC_ACT_SHOT;
    if (bpf_skb_adjust_room(skb,-8,BPF_ADJ_ROOM_MAC,0)) return TC_ACT_SHOT;
    return bpf_redirect(ingress,BPF_F_INGRESS);
}
#else
#define BUFFER_RETURN(ctx,action) return (action)
#endif
