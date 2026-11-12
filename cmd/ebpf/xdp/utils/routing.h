// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
#pragma once

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <sys/socket.h>

#include "xdp/utils/trace.h"

struct route_stat {
    __u64 fib_lookup_ip4_ok;
    __u64 fib_lookup_ip4_error_drop;
    __u64 fib_lookup_ip4_error_pass;
    __u64 fib_lookup_ip6_ok;
    __u64 fib_lookup_ip6_error_drop;
    __u64 fib_lookup_ip6_error_pass;
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct route_stat);
    __uint(max_entries, 1);
} upf_route_stat SEC(".maps");

static __always_inline enum xdp_action do_route(struct xdp_md *ctx, struct ethhdr *eth, int ifindex, __u8 (*smac)[6], __u8 (*dmac)[6]) {
    //_decr_ttl(ether_proto, l3hdr);
    __builtin_memcpy(eth->h_source, smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);

    if (ifindex == ctx->ingress_ifindex)
        return XDP_TX;
    int action = bpf_redirect(ifindex, 0);
    return action == XDP_REDIRECT ? XDP_REDIRECT : XDP_ABORTED;
}

static __always_inline enum xdp_action route_ipv4(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *ip4) {
    const __u32 key = 0;
    struct route_stat *statistic = bpf_map_lookup_elem(&upf_route_stat, &key);
    if (!statistic) {
        return XDP_ABORTED;
    }


    struct bpf_fib_lookup fib_params = {};
    fib_params.family = AF_INET;
    fib_params.tos = ip4->tos;
    fib_params.l4_protocol = ip4->protocol;
    fib_params.sport = 0;
    fib_params.dport = 0;
    fib_params.tot_len = bpf_ntohs(ip4->tot_len);
    fib_params.ipv4_src = ip4->saddr;
    fib_params.ipv4_dst = ip4->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0 /*BPF_FIB_LOOKUP_OUTPUT*/);
    switch (rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            upf_printk("upf: bpf_fib_lookup %pI4 -> %pI4: nexthop: %pI4", &ip4->saddr, &ip4->daddr, &fib_params.ipv4_dst);
            upf_printk("upf: bpf_fib_lookup2 %pI4 -> %pI4: h_vlan_TCI: %d", &ip4->saddr, &ip4->daddr, fib_params.h_vlan_TCI);
            upf_printk("upf: bpf_fib_lookup3 %pI4 -> %pI4: h_vlan_proto: %d", &ip4->saddr, &ip4->daddr, fib_params.h_vlan_proto);
            // RFC 1812 section 5.3.1: let the kernel generate Time Exceeded
            // for an exhausted packet; decrement only on successful redirect.
            if (ip4->ttl <= 1) return XDP_PASS;
            __u16 old = *(__u16 *)&ip4->ttl;
            ip4->ttl--;
            ipv4_csum_replace(&ip4->check, old, *(__u16 *)&ip4->ttl);
            statistic->fib_lookup_ip4_ok += 1;


            return do_route(ctx, eth, fib_params.ifindex, &fib_params.smac, &fib_params.dmac);

        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            upf_printk("upf: bpf_fib_lookup %pI4 -> %pI4: %d", &ip4->saddr, &ip4->daddr, rc);
            statistic->fib_lookup_ip4_error_drop += 1;
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
        default:
            upf_printk("upf: bpf_fib_lookup %pI4 -> %pI4: %d", &ip4->saddr, &ip4->daddr, rc);
            statistic->fib_lookup_ip4_error_pass += 1;
            return XDP_PASS; /* Let's kernel takes care */
    }
}

static __always_inline enum xdp_action route_ipv6(struct xdp_md *ctx, struct ethhdr *eth, struct ipv6hdr *ip6) {
    const __u32 key = 0;
    struct route_stat *statistic = bpf_map_lookup_elem(&upf_route_stat, &key);
    if (!statistic) {
        return XDP_ABORTED;
    }

    struct bpf_fib_lookup fib_params = {};
    fib_params.family = AF_INET6;
    // fib_params.tos = ip6->flow_lbl;
    fib_params.l4_protocol = ip6->nexthdr;
    fib_params.sport = 0;
    fib_params.dport = 0;
    // RFC 8200 sections 3 and 5: MTU applies to header plus payload.
    __u32 total = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
    if (total > 65535) return XDP_PASS;
    fib_params.tot_len = total;
    __builtin_memcpy(fib_params.ipv6_src, &ip6->saddr, sizeof(ip6->saddr));
    __builtin_memcpy(fib_params.ipv6_dst, &ip6->daddr, sizeof(ip6->daddr));
    fib_params.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0 /*BPF_FIB_LOOKUP_OUTPUT*/);
    switch (rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            upf_printk("upf: bpf_fib_lookup %pI6c -> %pI6c: nexthop: %pI6c", &ip6->saddr, &ip6->daddr, &fib_params.ipv6_dst);
            // RFC 8200 section 3: retain the original Hop Limit on fallback.
            if (ip6->hop_limit <= 1) return XDP_PASS;
            ip6->hop_limit--;
            statistic->fib_lookup_ip6_ok += 1;

            return do_route(ctx, eth, fib_params.ifindex, &fib_params.smac, &fib_params.dmac);
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            upf_printk("upf: bpf_fib_lookup %pI6c -> %pI6c: %d", &ip6->saddr, &ip6->daddr, rc);
            statistic->fib_lookup_ip6_error_drop += 1;
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
        default:
            upf_printk("upf: bpf_fib_lookup %pI6c -> %pI6c: %d", &ip6->saddr, &ip6->daddr, rc);
            statistic->fib_lookup_ip6_error_pass += 1;
            return XDP_PASS; /* Let's kernel takes care */
    }
}