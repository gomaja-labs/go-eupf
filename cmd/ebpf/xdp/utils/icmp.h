// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "xdp/utils/csum.h"
#include "xdp/utils/parsers.h"
#include "xdp/utils/packet_context.h"

static __always_inline void fill_icmp_header(struct icmphdr *icmp) {
    icmp->type = ICMP_TIME_EXCEEDED;
    icmp->code = ICMP_EXC_TTL;
    icmp->un.gateway = 0;
    icmp->checksum = 0;
}

// static __always_inline __u32 add_icmp_over_ip4_headers(struct packet_context *ctx, int saddr, int daddr) {
//     static const size_t icmp_encap_size = sizeof(struct iphdr) + sizeof(struct icmphdr);

//     if (!ctx->ip4)
//         return -1;

//     const __u32 ip_packet_len = bpf_ntohs(ctx->ip4->tot_len);

//     int result = bpf_xdp_adjust_head(ctx->xdp_ctx, (__s32)-icmp_encap_size);
//     if (result)
//         return -1;

//     char *data = (char *)(long)ctx->xdp_ctx->data;
//     const char *data_end = (const char *)(long)ctx->xdp_ctx->data_end;

//     struct ethhdr *orig_eth = (struct ethhdr *)(data + icmp_encap_size);
//     if ((const char *)(orig_eth + 1) > data_end)
//         return -1;

//     struct ethhdr *eth = (struct ethhdr *)data;
//     __builtin_memcpy(eth, orig_eth, sizeof(*eth));
//     eth->h_proto = bpf_htons(ETH_P_IP);

//     struct iphdr *ip = (struct iphdr *)(eth + 1);
//     if ((const char *)(ip + 1) > data_end)
//         return -1;

//     /* Add the outer IP header */
//     fill_ip_header(ip, saddr, daddr, 0, ip_packet_len + icmp_encap_size);
//     ip->protocol = IPPROTO_ICMP;
//     ip->check = ipv4_csum(ip, sizeof(*ip));

//     /* Add the ICMP header */
//     struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
//     if ((const char *)(icmp + 1) > data_end)
//         return -1;

//     fill_icmp_header(icmp);
//     const __s8 icmp_payload_size = data_end - (const char *)icmp;
//     icmp->checksum = ipv4_csum(icmp, icmp_payload_size);

//     /* Update packet pointers */
//     context_set_ip4(ctx, (char *)(long)ctx->xdp_ctx->data, (const char *)(long)ctx->xdp_ctx->data_end, eth, ip, 0, 0);
//     return 0;
// }

#define ICMPV6_ROUTER_SOLICITATION    	133
#define ICMPV6_ROUTER_ADVERTISEMENT    	134

struct icmp6hdr_ra_ {
    __u8	icmp6_type;
    __u8	icmp6_code;
    __sum16	icmp6_cksum;

    union {
        __be32	un_data32[1];
        __be16	un_data16[2];
        __u8	un_data8[4];

        struct icmpv6_nd_ra_ {
        __u8    hop_limit;
        #if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8	reserved:3,
                router_pref:2,
                home_agent:1,
                other:1,
                managed:1;

#elif defined(__BIG_ENDIAN_BITFIELD)
        __u8	managed:1,
                other:1,
                home_agent:1,
                router_pref:2,
                reserved:3;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        __be16	rt_lifetime;
        __be32	rt_reachabletime;
        __be32	rt_retranstimer;
        } u_nd_ra;
    } icmp6_dataun;
};

struct icmpv6_option_prefix {
    __u8    type;
    __u8    length;
    __u8    prefix_length;
    __u8    reserved:5,
            router_addr_flag:1,
            auto_flag:1,
            onlink_flag:1;
    __be32 valid_lifetime;
    __be32 pref_lifetime;
    __be32 _reserved;
    struct in6_addr	prefix;
};

static __always_inline __u32 prepare_icmp_echo_reply(struct packet_context *ctx, int saddr, int daddr) {
    if (!ctx->ip4)
        return -1;

    struct ethhdr *eth = ctx->eth;
    swap_mac(eth);

    const char *data_end = (const char *)(long)ctx->xdp_ctx->data_end;
    struct iphdr *ip = ctx->ip4;
    if ((const char *)(ip + 1) > data_end)
        return -1;

    swap_ip(ip);

    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
    if ((const char *)(icmp + 1) > data_end)
        return -1;

    if(icmp->type != ICMP_ECHO)
        return -1;

    __u16 old = *(__u16*)&icmp->type;
    icmp->type = ICMP_ECHOREPLY;
    icmp->code = 0;
    
    ipv4_csum_replace(&icmp->checksum, old, *(__u16*)&icmp->type);

    return 0;
}

static __noinline int valid_rs_checksum(struct ipv6hdr *ip, const char *end, __u32 len) {
    struct icmp6hdr *icmp=(void *)(ip+1);
    __u64 sum=0;
    for (int i=0; i<32; i++) {
        if (i*8>=len) break;
        void *block=(void *)icmp+i*8;
        if ((const char *)block+8>end) return 0;
        sum=bpf_csum_diff(0,0,block,8,sum);
    }
    struct ipv6_pseudo_header pseudo={};
    pseudo.fields.src_ip=ip->saddr;
    pseudo.fields.dst_ip=ip->daddr;
    pseudo.fields.length=bpf_htonl(len);
    pseudo.fields.next_header=IPPROTO_ICMPV6;
    #pragma unroll
    for (int i=0;i<20;i++) sum+=pseudo.words[i];
    return csum_fold_helper(sum) == 0;

}

// RFC 4861 section 6.1.1: validate every solicitation before generating a
// response. The bounded fast path leaves larger messages to the kernel.
static __noinline int valid_router_solicitation(struct packet_context *ctx) {
    struct ipv6hdr *ip = ctx->ip6;
    __u32 len = bpf_ntohs(ip->payload_len);
    if (len > 256) return -1;
    struct icmp6hdr *icmp = (void *)(ip+1);
    if (ip->hop_limit != 255 || len < 8 || len > 256 || (len & 7) ||
        (const char *)(icmp+1) > ctx->data_end ||
        (const char *)icmp+len > ctx->data_end || icmp->icmp6_code != 0)
        return 0;
    if (!valid_rs_checksum(ip, ctx->data_end, len)) return 0;
    int unspecified = !(ip->saddr.s6_addr32[0] | ip->saddr.s6_addr32[1] |
                        ip->saddr.s6_addr32[2] | ip->saddr.s6_addr32[3]);
    __u64 offset = 8;
    for (int i=0; i<31 && offset<len; i++) {
        asm volatile("" : "+r"(offset));
        if (offset > 254) return 0;
        __u8 *opt = (void *)icmp+offset;
        if ((const char *)opt+2 > ctx->data_end) return 0;
        __u32 span = opt[1]*8;
        if (!span || offset+span>len || (unspecified && opt[0]==1)) return 0;
        offset+=span;
    }
    return offset == len;
}

static __always_inline __u32 prepare_icmp6_ra(struct packet_context *ctx, const struct in6_addr *prefix, __u8 prefix_length) {
    if (!ctx->ip6 || prefix_length>128) return -1;
    __s32 required = sizeof(struct ethhdr)+sizeof(struct ipv6hdr)+sizeof(struct icmp6hdr_ra_)+sizeof(struct icmpv6_option_prefix);
    __s32 current = (void *)(long)ctx->xdp_ctx->data_end - (void *)(long)ctx->xdp_ctx->data;
    asm volatile("" : "+r"(current));
    if (bpf_xdp_adjust_tail(ctx->xdp_ctx, required-current)) return -1;
    char *data = (void *)(long)ctx->xdp_ctx->data;
    const char *end = (void *)(long)ctx->xdp_ctx->data_end;
    // Re-establish bounds directly: the original RS length can exceed the RA.
    struct ethhdr *eth = (void *)data;
    struct ipv6hdr *ip = (void *)(eth+1);
    struct icmp6hdr_ra_ *ra = (void *)(ip+1);
    struct icmpv6_option_prefix *opt = (void *)(ra+1);
    if ((const char *)(opt+1)>end) return -1;
    swap_mac(eth);
    // RFC 4861 sections 4.2 and 6.2.6: unicast solicitor, or all-nodes
    // multicast for the unspecified source. The advertised prefix is not a
    // destination address and must never replace the solicitor's prefix.
    ip->daddr = ip->saddr;
    if (!(ip->saddr.s6_addr32[0] | ip->saddr.s6_addr32[1] |
          ip->saddr.s6_addr32[2] | ip->saddr.s6_addr32[3])) {
        ip->daddr = (struct in6_addr){ .s6_addr={0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1} };
    }
    ip->saddr = (struct in6_addr){ .s6_addr={0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1} };
    ip->version=6;
    ip->priority=0;
    __builtin_memset(ip->flow_lbl,0,sizeof(ip->flow_lbl));
    ip->nexthdr=IPPROTO_ICMPV6;
    ip->hop_limit=255;
    ip->payload_len=bpf_htons(sizeof(*ra)+sizeof(*opt));
    __builtin_memset(ra,0,sizeof(*ra));
    ra->icmp6_type=ICMPV6_ROUTER_ADVERTISEMENT;
    ra->icmp6_dataun.u_nd_ra.hop_limit=64;
    // RFC 8319 section 4 amends RFC 4861's Router Lifetime upper bound.
    ra->icmp6_dataun.u_nd_ra.rt_lifetime=bpf_htons(64800);
    __builtin_memset(opt,0,sizeof(*opt));
    opt->type=3;opt->length=4;opt->prefix_length=prefix_length;
    opt->onlink_flag=1;opt->auto_flag=1;
    opt->valid_lifetime=bpf_htonl(0xffffffff);
    opt->pref_lifetime=bpf_htonl(0xffffffff);
    opt->prefix=*prefix;
    ra->icmp6_cksum=icmp6_csum(ip,0,ICMPV6_ROUTER_ADVERTISEMENT,ra,sizeof(*ra)+sizeof(*opt));
    ctx->data=data;ctx->data_end=end;ctx->eth=eth;ctx->ip6=ip;ctx->ip4=0;ctx->udp=0;ctx->tcp=0;ctx->gtp=0;
    ctx->ip_end=(const char *)(opt+1);
    return 0;
}
