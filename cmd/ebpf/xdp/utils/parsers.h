// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
#pragma once

#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmpv6.h>

#include "xdp/utils/packet_context.h"
#include "xdp/utils/trace.h"
#include "xdp/utils/csum.h"

#define ETH_P_IPV6_BE	0xDD86
#define ETH_P_IP_BE 	0x0008

static __always_inline __u64 bounded_wire_length(__be16 length) {
    __u64 value = bpf_ntohs(length);
    // Linux 5.15 needs an explicit unsigned bound after BPF_END.
    asm volatile("" : "+r"(value));
    return value & 0xffff;
}

static __always_inline int parse_ethernet(struct packet_context *ctx) {
    struct ethhdr *eth = (struct ethhdr *)ctx->data;
    if ((const char *)(eth + 1) > ctx->data_end)
        return -1;

    /* TODO: Add vlan support */

    ctx->data += sizeof(*eth);
    ctx->eth = eth;
    return bpf_ntohs(eth->h_proto);
}

/* 0x3FFF mask to check for fragment offset field */
#define IP_FRAGMENTED 65343

static __always_inline int parse_ip4(struct packet_context *ctx) {
    struct iphdr *ip4 = (struct iphdr *)ctx->data;
    if ((const char *)(ip4 + 1) > ctx->data_end)
        return -1;

    // RFC 791 section 3.1: IHL, total length and fragment offsets delimit L4.
    // Fragments stay intact for kernel reassembly; never classify fragment data.
    __u32 ihl = ip4->ihl * 4;
    __u32 total = bounded_wire_length(ip4->tot_len);
    if (ip4->version != 4 || ihl < sizeof(*ip4) || total < ihl ||
        (const char *)ip4 + ihl > ctx->data_end ||
        (const char *)ip4 + total > ctx->data_end ||
        (ip4->frag_off & bpf_htons(0x3fff)))
        return -1;
    ctx->ip_end = (const char *)ip4 + total;
    ctx->data += ihl;
    ctx->ip4 = ip4;
    return ip4->protocol;
}

struct ipv6_metadata {
    __u32 offset;
    __u8 protocol;
    __u8 fragmented;
    __u8 nonfirst_fragment;
    __u8 reserved;
};

// Verify the bounded walker separately from policy selection. Only scalar
// offsets and flags cross this boundary; no packet pointer escapes it.
int walk_ipv6_headers(struct xdp_md *xdp, __u32 ip_offset, struct ipv6_metadata *meta) {
    const char *end=(const void *)(long)xdp->data_end;
    char *base=(void *)(long)xdp->data;
    if (!meta || ip_offset>32767) return -1;
    __u64 bounded_offset=ip_offset;
    asm volatile("" : "+r"(bounded_offset));
    bounded_offset &= 0x7fff;
    struct ipv6hdr *ip6=(void *)(base+bounded_offset);
    if ((const char *)(ip6+1)>end) return -1;
    const char *ip_end;
    // RFC 8200 section 4, updated by RFC 9673: find the final Next Header
    // through at most eight extension headers. Incomplete/long chains are
    // unclassifiable (-2); callers drop them before selecting any PDR.
    __u64 payload_len = bounded_wire_length(ip6->payload_len);
    if (ip6->version != 6 || (const char *)(ip6 + 1) + payload_len > end)
        return -1;
    ip_end = (const char *)(ip6 + 1) + payload_len;
    meta->fragmented = 0;
    meta->nonfirst_fragment = 0;
    char *cursor = (char *)(ip6 + 1);
    __u8 next = ip6->nexthdr;
    int saw_fragment = 0;
    for (int i=0; i<8; i++) {
        if (next!=IPPROTO_HOPOPTS && next!=IPPROTO_ROUTING &&
            next!=IPPROTO_DSTOPTS && next!=IPPROTO_FRAGMENT && next!=IPPROTO_AH) {
            meta->offset=cursor-(char *)ip6;meta->protocol=next;return 0;
        }
        if (cursor+8>end || cursor+8>ip_end) return -2;
        const __u8 *header=(const void *)cursor;
        __u8 following=header[0];
        __u32 length;
        if (next==IPPROTO_FRAGMENT) {
            if (saw_fragment) return -2;
            saw_fragment=1;
            __u16 bits=bpf_ntohs(*(__be16 *)(cursor+2));
            __u16 offset=bits & 0xfff8;
            // RFC 6733 section 4.3.1: offset-one fragments are discarded.
            if (offset==8) return -2;
            meta->fragmented=(offset!=0 || (bits&1));
            meta->nonfirst_fragment=offset!=0;
            length=8;
        } else if (next==IPPROTO_AH) {
            length=((__u32)header[1]+2)*4;
        } else {
            length=((__u32)header[1]+1)*8;
        }
        if (length<8 || cursor+length>end || cursor+length>ip_end) return -2;
        cursor+=length;
        next=following;
        if (meta->nonfirst_fragment) {
            // Extension headers after the fragment header cannot be found in
            // a non-first fragment. Never guess a transport tuple from data.
            if (next==IPPROTO_HOPOPTS || next==IPPROTO_ROUTING || next==IPPROTO_DSTOPTS || next==IPPROTO_FRAGMENT || next==IPPROTO_AH) return -2;
            meta->offset=cursor-(char *)ip6;meta->protocol=next;return 0;
        }
    }
    if (next==IPPROTO_HOPOPTS || next==IPPROTO_ROUTING || next==IPPROTO_DSTOPTS || next==IPPROTO_FRAGMENT || next==IPPROTO_AH) return -2;
    meta->offset=cursor-(char *)ip6;meta->protocol=next;return 0;
}

static __always_inline int parse_ip6(struct packet_context *ctx) {
    struct ipv6hdr *ip6=(void *)ctx->data;
    if ((const char *)(ip6+1)>ctx->data_end) return -1;
    struct ipv6_metadata meta={0};
    __u64 offset=ctx->data-(char *)(long)ctx->xdp_ctx->data;
    if (offset>32767) return -1;
    int result=walk_ipv6_headers(ctx->xdp_ctx,offset,&meta);
    if (result<0) return result;
    // Bound every scalar exported by the independently verified walker.
    __u32 length=meta.offset & 0x7fff;
    if (length>16424 || length<sizeof(*ip6) || (char *)ip6+length>ctx->data_end) return -2;
    __u64 payload_len=bounded_wire_length(ip6->payload_len);
    if ((const char *)(ip6+1)+payload_len>ctx->data_end) return -1;
    ctx->ip_end=(const char *)(ip6+1)+payload_len;
    ctx->ip6=ip6;ctx->data=(char *)ip6+length;
    ctx->ip_protocol=meta.protocol;
    ctx->fragmented=meta.fragmented;
    ctx->nonfirst_fragment=meta.nonfirst_fragment;
    ctx->ports_present=0;
    return meta.protocol;
}

static __always_inline int parse_udp(struct packet_context *ctx) {
    struct udphdr *udp = (struct udphdr *)ctx->data;
    if ((const char *)(udp + 1) > ctx->data_end)
        return -1;

    // RFC 768: UDP Length includes its header and excludes Ethernet padding.
    __u32 len = bounded_wire_length(udp->len);
    if (len < sizeof(*udp) || (!ctx->fragmented && (const char *)udp + len > ctx->data_end) ||
        (ctx->ip_end && ((const char *)(udp+1)>ctx->ip_end || (!ctx->fragmented && (const char *)udp + len > ctx->ip_end))))
        return -1;
    ctx->data += sizeof(*udp);
    ctx->udp = udp;
    ctx->source_port = bpf_ntohs(udp->source);
    ctx->destination_port = bpf_ntohs(udp->dest);
    ctx->ports_present = 1;
    return bpf_ntohs(udp->dest);
}

static __always_inline int parse_tcp(struct packet_context *ctx) {
    struct tcphdr *tcp = (struct tcphdr *)ctx->data;
    if ((const char *)(tcp + 1) > ctx->data_end)
        return -1;

    __u32 len = tcp->doff * 4;
    if (len < sizeof(*tcp) || (const char *)tcp + len > ctx->data_end ||
        (ctx->ip_end && (const char *)tcp + len > ctx->ip_end))
        return -1;

    ctx->data += len;
    ctx->tcp = tcp;
    ctx->source_port = bpf_ntohs(tcp->source);
    ctx->destination_port = bpf_ntohs(tcp->dest);
    ctx->ports_present = 1;
    return bpf_ntohs(tcp->dest);
}

// RFC 6733 section 4.3.1: SCTP has source/destination ports too.
// Only the common 12-byte header is needed for classification.
static __always_inline int parse_sctp(struct packet_context *ctx) {
    const __be16 *ports = (const void *)ctx->data;
    if (ctx->data + 12 > ctx->data_end ||
        (ctx->ip_end && ctx->data + 12 > ctx->ip_end)) return -1;
    ctx->source_port = bpf_ntohs(ports[0]);
    ctx->destination_port = bpf_ntohs(ports[1]);
    ctx->ports_present = 1;
    return 0;
}

static __always_inline int parse_l4(int ip_protocol, struct packet_context *ctx)
{
    ctx->ports_present=0;
    if (ctx->nonfirst_fragment) return 0;
    switch (ip_protocol) {
        case IPPROTO_UDP:
            return parse_udp(ctx);
        case IPPROTO_TCP:
            return parse_tcp(ctx);
        case IPPROTO_SCTP:
            return parse_sctp(ctx);
        default:
            return 0;
    }
}

static __always_inline void swap_mac(struct ethhdr *eth) {
    __u8 mac[6];
    __builtin_memcpy(mac, eth->h_source, sizeof(mac));
    __builtin_memcpy(eth->h_source, eth->h_dest, sizeof(eth->h_source));
    __builtin_memcpy(eth->h_dest, mac, sizeof(eth->h_dest));
}

static __always_inline void swap_port(struct udphdr *udp) {
    __u16 tmp = udp->dest;
    udp->dest = udp->source;
    udp->source = tmp;
    /* Update UDP checksum */
    udp->check = 0;
    // cs = 0;
    // ipv4_l4_csum(udp, sizeof(*udp), &cs, iph);
    // udp->check = cs;
}

static __always_inline void swap_ip(struct iphdr *iph) {
    __u32 tmp_ip = iph->daddr;
    iph->daddr = iph->saddr;
    iph->saddr = tmp_ip;

    /* Don't need to recalc csum in case of ip swap */
    // ip->check = ipv4_csum(ip, sizeof(*ip));
}

static __always_inline void update_tos_ipv4(struct iphdr *ip, __u8 tos) {
    if(!tos)
        return;
    __u16 old = *(__u16*)ip;
    ip->tos = tos;
    ipv4_csum_replace(&ip->check, old, *(__u16*)ip);
}

static __always_inline void update_tos_ipv6(struct ipv6hdr *ip6, __u8 tos) {
    if(!tos)
        return;
    // RFC 8200 section 3: low Traffic Class nibble is above the Flow Label.
    ip6->flow_lbl[0] = (ip6->flow_lbl[0] & 0x0f) | ((tos & 0x0f) << 4);
    ip6->priority = tos >> 4;
}

static __always_inline void context_set_ip4(struct packet_context *ctx, char *data, const char *data_end, struct ethhdr *eth, struct iphdr *ip4, struct udphdr *udp, struct gtpuhdr *gtp) {
    ctx->data = data;
    ctx->data_end = data_end;
    ctx->eth = eth;
    ctx->ip4 = ip4;
    ctx->ip6 = 0;
    ctx->udp = udp;
    ctx->gtp = gtp;
}

static __always_inline void context_reset(struct packet_context *ctx, char *data, const char *data_end) {
    ctx->data = data;
    ctx->data_end = data_end;
    ctx->eth = 0;
    ctx->ip4 = 0;
    ctx->ip6 = 0;
    ctx->udp = 0;
    ctx->gtp = 0;
    ctx->tcp = 0;
    ctx->ip_end = 0;
    ctx->source_port = 0; ctx->destination_port = 0; ctx->ports_present = 0;
    ctx->locally_generated = 0;
}


static __always_inline long context_reinit(struct packet_context *ctx, char *data, const char *data_end) {
    context_reset(ctx, data, data_end);

    int ethertype = parse_ethernet(ctx);
    switch (ethertype) {
        case ETH_P_IPV6: {
            if (-1 == parse_ip6(ctx)) {
                upf_printk("upf: can't parse ip6");
                return -1;
            }
            return 0;
        }
        case ETH_P_IP: {
            if (-1 == parse_ip4(ctx)) {
                upf_printk("upf: can't parse ip4");
                return -1;
            }
            return 0;
        }

        default:
            /* do nothing with non-ip packets */
            upf_printk("upf: can't process not an ip packet: %d", ethertype);
            return -1;
    }
}
