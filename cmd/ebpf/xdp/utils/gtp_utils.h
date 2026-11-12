// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include "xdp/utils/gtpu.h"
#include "xdp/utils/packet_context.h"
#include "xdp/utils/trace.h"

// One global budget bounds reflection across spoofed peer addresses. Diagnostic
// control replies share at most 100 responses/s; Echo Responses are not policed.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} gtp_error_budget SEC(".maps");

static __always_inline int allow_gtp_error(void) {
    __u32 key=0;
    __u64 *next=bpf_map_lookup_elem(&gtp_error_budget,&key);
    if (!next) return 0;
    __u64 now=bpf_ktime_get_ns();
    __u64 before=*next;
    if (before>now) return 0;
    return __sync_val_compare_and_swap(next,before,now+10000000ULL)==before;
}

// TS 29.281 V19.2.0 clauses 5.1 and 5.2.1: validate the complete
// UDP/GTP envelope and walk length-delimited extensions before using a TEID.
static __noinline int parse_gtp(struct packet_context *ctx) {
    struct gtpuhdr *gtp = (struct gtpuhdr *)ctx->data;
    if ((const char *)(gtp + 1) > ctx->data_end || !ctx->udp || !ctx->ip4)
        return -1;
    __u32 length = bounded_wire_length(gtp->message_length);
    __u32 udp_length = bounded_wire_length(ctx->udp->len);
    if (gtp->version != 1 || !gtp->pt || udp_length != length + 16 ||
        (const char *)(gtp + 1) + length > ctx->data_end)
        return -1;
    ctx->gtp = gtp;
    const char *end = (const char *)(gtp + 1) + length;
    char *cursor = (char *)(gtp + 1);
    __u8 next = 0;
    if (gtp->e || gtp->s || gtp->pn) {
        struct gtp_hdr_ext *opt = (void *)cursor;
        if ((const char *)(opt + 1) > ctx->data_end || (const char *)(opt + 1) > end)
            return -1;
        if (gtp->e) next = opt->next_ext;
        cursor += sizeof(*opt);
    }
    // Bound work on hostile chains; longer chains use the control/error path.
    for (int i = 0; i < 16 && next; i++) {
        if (cursor + 4 > ctx->data_end || cursor + 4 > end) return -1;
        __u64 span = (__u8)*cursor * 4;
        if (!span) return -1;
        char *after = cursor + span;
        asm volatile("" : "+r"(after));
        if (after > ctx->data_end || after > end) return -1;
        if (next == GTPU_EXT_TYPE_PDU_SESSION_CONTAINER) {
            // TS 38.415 V19.1.0 figure 5.5.2.2-1: QFI is the low six bits.
            ctx->qfi = cursor[2] & 0x3f;ctx->qfi_present=1;
        } else if (next & 0x80) {
            // TS 29.281 V19.2.0 figure 5.2.1-2: bits 10 require
            // comprehension only at an endpoint; bits 11 at every node.
            ctx->unknown_extensions |= (next & 0x40) ? 2 : 1;
        } else if (next & 0x40) {
            ctx->unknown_extensions |= 4;
        }
        next = (__u8)*(after - 1);
        cursor = after;
    }
    if (next) return -1;
    ctx->gtp = gtp;
    ctx->data = cursor;
    ctx->gtp_header_length = cursor - (char *)gtp;
    ctx->tpdu_length = end - cursor;
    if (gtp->message_type == GTPU_G_PDU) {
        // Only IP PDU sessions are supported. Validate the entire T-PDU before
        // policy or accounting; optional GTP words are never subscriber bytes.
        struct packet_context inner = { .data=cursor, .data_end=ctx->data_end, .xdp_ctx=ctx->xdp_ctx };
        if (cursor + 1 > ctx->data_end || cursor + 1 > end) return -1;
        __u8 version = (__u8)*cursor >> 4;
        if (version == 4) {
            struct iphdr *ip=(void *)cursor;
            if ((const char *)(ip+1)>ctx->data_end || (const char *)(ip+1)>end) return -1;
            // Fragments use the same intact kernel slow path as outer IP.
            if (ip->frag_off & bpf_htons(0x3fff)) return -3;
            if (parse_ip4(&inner) < 0 || inner.ip_end != end) return -1;
            if (parse_l4(ip->protocol,&inner)<0) return -1;
        } else if (version == 6) {
            int protocol=parse_ip6(&inner);
            if (protocol < 0 || inner.ip_end != end) return -1;
            if (parse_l4(protocol,&inner)<0) return -1;
        } else return -1;
    }
    return gtp->message_type;
}

// TS 29.281 V19.2.0 clauses 7.2.2, 7.2.3, 7.3.1 and 8.2-8.5:
// construct mandatory control IEs independently of request data and padding.
static __noinline enum xdp_action reply_gtp_control(struct packet_context *ctx, __u8 type) {
    if (!ctx->ip4 || !ctx->udp || !ctx->gtp) return XDP_ABORTED;
    __u32 ihl=ctx->ip4->ihl*4;
    __u32 original_teid=ctx->gtp->teid;
    __u32 original_destination=ctx->ip4->daddr;
    __u16 sequence=0;
    if (type==GTPU_ECHO_RESPONSE) {
        struct gtp_hdr_ext *request_opt=(void *)(ctx->gtp+1);
        if (!ctx->gtp->s || (const char *)(request_opt+1)>ctx->data_end) return XDP_DROP;
        sequence=request_opt->sqn;
    } else if (!allow_gtp_error()) return XDP_DROP;
    __u32 size=14;
    if (type==GTPU_ERROR_INDICATION) size=24;
    else if (type==GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION) size=16;
    __s32 target=sizeof(struct ethhdr)+ihl+sizeof(struct udphdr)+size;
    __s32 current=(void *)(long)ctx->xdp_ctx->data_end-(void *)(long)ctx->xdp_ctx->data;
    asm volatile("" : "+r"(current));
    if (bpf_xdp_adjust_tail(ctx->xdp_ctx,target-current)) return XDP_ABORTED;
    char *data=(void *)(long)ctx->xdp_ctx->data;
    const char *end=(void *)(long)ctx->xdp_ctx->data_end;
    struct ethhdr *eth=(void *)data;
    struct iphdr *ip=(void *)(eth+1);
    if ((const char *)(ip+1)>end || ihl<20 || ihl>60) return XDP_ABORTED;
    struct udphdr *udp=(void *)ip+ihl;
    if ((const char *)(udp+1)>end) return XDP_ABORTED;
    struct gtpuhdr *gtp=(void *)(udp+1);
    if ((const char *)gtp+14>end) return XDP_ABORTED;
    swap_mac(eth);swap_ip(ip);swap_port(udp);
    // TS 29.281 V19.2.0 clauses 4.4.2.2, 4.4.2.4 and 4.4.2.5:
    // only Echo Response returns to the request's source port. Diagnostic
    // indications target the registered GTP-U port even for an ephemeral sender.
    if (type != GTPU_ECHO_RESPONSE) udp->dest=bpf_htons(GTP_UDP_PORT);
    ip->ttl=64;ip->tot_len=bpf_htons(ihl+sizeof(*udp)+size);
    ip->check=0;ip->check=ipv4_header_checksum(ip,end);
    udp->len=bpf_htons(sizeof(*udp)+size);
    *(__u8 *)gtp=0x32;
    gtp->message_type=type;gtp->message_length=bpf_htons(size-8);gtp->teid=0;
    struct gtp_hdr_ext *opt=(void *)(gtp+1);
    opt->sqn=sequence;opt->npdu=0;opt->next_ext=0;
    __u8 *ie=(void *)(opt+1);
    if (type==GTPU_ERROR_INDICATION) {
        if ((const char *)gtp+24>end) return XDP_ABORTED;
        ie[0]=16;
        __builtin_memcpy(ie+1,&original_teid,4);
        ie[5]=133;ie[6]=0;ie[7]=4;
        __builtin_memcpy(ie+8,&original_destination,4);
    } else if (type==GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION) {
        if ((const char *)gtp+16>end) return XDP_ABORTED;
        ie[0]=141;ie[1]=0;ie[2]=1;ie[3]=GTPU_EXT_TYPE_PDU_SESSION_CONTAINER;
    } else { ie[0]=14;ie[1]=0; }
    context_set_ip4(ctx,data,end,eth,ip,udp,gtp);
    return XDP_TX;
}

static __always_inline int guess_eth_protocol(const char *data) {
    const __u8 ip_version = (*(const __u8 *)data) >> 4;
    switch (ip_version) {
        case 6: {
            return ETH_P_IPV6_BE;
        }
        case 4: {
            return ETH_P_IP_BE;
        }
        default:
            /* do nothing with non-ip packets */
            upf_printk("upf: can't process non-IP packet: %d", ip_version);
            return -1;
    }
}

static __always_inline long remove_gtp_header(struct packet_context *ctx) {
    if (!ctx->gtp) {
        upf_printk("upf: remove_gtp_header: not a gtp packet");
        return -1;
    }

    __u64 gtp_encap_size = ctx->ip4->ihl * 4 + sizeof(struct udphdr) + ctx->gtp_header_length;
    asm volatile("" : "+r"(gtp_encap_size));
    if (gtp_encap_size < 36 || gtp_encap_size > 16400) return -1;

    char *data = (char *)(long)ctx->xdp_ctx->data;
    const char *data_end = (const char *)(long)ctx->xdp_ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((const char *)(eth + 1) > data_end) {
        upf_printk("upf: remove_gtp_header: can't parse eth");
        return -1;
    }

    data += gtp_encap_size;
    struct ethhdr *new_eth = (struct ethhdr *)data;
    if ((const char *)(new_eth + 1) > data_end) {
        upf_printk("upf: remove_gtp_header: can't set new eth");
        return -1;
    }

    data += sizeof(*new_eth);
    if (data + 1 > data_end)
        return -1;

    const int eth_proto = guess_eth_protocol(data);

    if (eth_proto == -1)
        return -1;

    __builtin_memcpy(new_eth, eth, sizeof(*new_eth));

    new_eth->h_proto = eth_proto;

    long result = bpf_xdp_adjust_head(ctx->xdp_ctx, gtp_encap_size);
    if (result)
        return result;

    /* Update packet pointers */
    data = (char *)(long)ctx->xdp_ctx->data;
    data_end = (const char *)(long)ctx->xdp_ctx->data_end;
    return context_reinit(ctx, data, data_end);
}

static __always_inline void fill_ip_header(struct iphdr *ip, int saddr, int daddr, __u8 tos, int tot_len) {
    ip->version = 4;
    ip->ihl = 5; /* No options */
    ip->tos = tos;
    ip->tot_len = bpf_htons(tot_len);
    ip->id = 0;            /* No fragmentation */
    ip->frag_off = 0x0040; /* Don't fragment; Fragment offset = 0 */
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = saddr;
    ip->daddr = daddr;
}

static __always_inline void fill_udp_header(struct udphdr *udp, int port, int len) {
    udp->source = bpf_htons(port);
    udp->dest = udp->source;
    udp->len = bpf_htons(len);
    udp->check = 0;
}

static __always_inline void fill_gtp_header(struct gtpuhdr *gtp, int extention, int teid, int len) {
    *(__u8 *)gtp = GTP_FLAGS;
    gtp->e = extention;
    gtp->message_type = GTPU_G_PDU;
    gtp->message_length = bpf_htons(len);
    gtp->teid = bpf_htonl(teid);
}

static __always_inline void fill_gtp_ext_header(struct gtp_hdr_ext *gtp_ext) {
    gtp_ext->sqn = 0;
    gtp_ext->npdu = 0;
    gtp_ext->next_ext = GTPU_EXT_TYPE_PDU_SESSION_CONTAINER;
}

static __always_inline void fill_gtp_ext_header_psc(struct gtp_hdr_ext_pdu_session_container *gtp_ext, int qfi, int pdu_type) {
    gtp_ext->length = 1;
    gtp_ext->pdu_type = pdu_type;
    gtp_ext->spare1 = 0;
    gtp_ext->spare2 = 0;
    gtp_ext->rqi = (qfi >> 6) & 1;
    gtp_ext->qfi = qfi & 0x3f;
    gtp_ext->next_ext = 0;
}

static __always_inline __u32 add_gtp_over_ip4_headers(struct packet_context *ctx, int saddr, int daddr, __u8 tos, __u8 qfi, int teid, __u8 use_gtp_ext) {

    static const size_t gtp_full_hdr_base_size = sizeof(struct gtpuhdr);
    static const size_t gtp_encap_base_size = sizeof(struct iphdr) + sizeof(struct udphdr) + gtp_full_hdr_base_size;

    static const size_t gtp_ext_hdr_size = sizeof(struct gtp_hdr_ext) + sizeof(struct gtp_hdr_ext_pdu_session_container);
    static const size_t gtp_full_hdr_ext_size = sizeof(struct gtpuhdr) + gtp_ext_hdr_size;
    static const size_t gtp_encap_ext_size = sizeof(struct iphdr) + sizeof(struct udphdr) + gtp_full_hdr_ext_size;

    size_t gtp_encap_size = gtp_encap_base_size;
    size_t gtp_full_hdr_size = gtp_full_hdr_base_size;

    if(use_gtp_ext) {
        gtp_encap_size = gtp_encap_ext_size;
        gtp_full_hdr_size = gtp_full_hdr_ext_size;
    }

// #ifdef NO_GTP_EXTENTION 
//     static const size_t gtp_full_hdr_size = sizeof(struct gtpuhdr);
//     static const size_t gtp_encap_size = sizeof(struct iphdr) + sizeof(struct udphdr) + gtp_full_hdr_size;
// #else
    
//     static const size_t gtp_full_hdr_size = sizeof(struct gtpuhdr) + gtp_ext_hdr_size;
//     static const size_t gtp_encap_size = sizeof(struct iphdr) + sizeof(struct udphdr) + gtp_full_hdr_size;
// #endif

    // int ip_packet_len = (ctx->xdp_ctx->data_end - ctx->xdp_ctx->data) - sizeof(*eth);
    int ip_packet_len = 0;
    if (ctx->ip4)
        ip_packet_len = bounded_wire_length(ctx->ip4->tot_len);
    else if (ctx->ip6)
        ip_packet_len = bounded_wire_length(ctx->ip6->payload_len) + sizeof(struct ipv6hdr);
    else
        return -1;

    int result = bpf_xdp_adjust_head(ctx->xdp_ctx, (__s32)-gtp_encap_size);
    if (result)
        return -1;

    char *data = (char *)(long)ctx->xdp_ctx->data;
    const char *data_end = (const char *)(long)ctx->xdp_ctx->data_end;

    struct ethhdr *orig_eth = (struct ethhdr *)(data + gtp_encap_size);
    if ((const char *)(orig_eth + 1) > data_end)
        return -1;

    struct ethhdr *eth = (struct ethhdr *)data;
    __builtin_memcpy(eth, orig_eth, sizeof(*eth));
    eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((const char *)(ip + 1) > data_end)
        return -1;

    /* Add the outer IP header */
    fill_ip_header(ip, saddr, daddr, tos, ip_packet_len + gtp_encap_size);

    /* Add the UDP header */
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((const char *)(udp + 1) > data_end)
        return -1;

    fill_udp_header(udp, GTP_UDP_PORT, ip_packet_len + sizeof(*udp) + gtp_full_hdr_size);

    /* Add the GTP header */
    struct gtpuhdr *gtp = (struct gtpuhdr *)(udp + 1);
    if ((const char *)(gtp + 1) > data_end)
        return -1;

    if(use_gtp_ext)
    {
        fill_gtp_header(gtp, 1, teid, gtp_ext_hdr_size + ip_packet_len);

        /* Add the GTP ext header */
        struct gtp_hdr_ext *gtp_ext = (struct gtp_hdr_ext *)(gtp + 1);
        if ((const char *)(gtp_ext + 1) > data_end)
            return -1;

        fill_gtp_ext_header(gtp_ext);

        /* Add the GTP PDU session container header */
        struct gtp_hdr_ext_pdu_session_container *gtp_psc = (struct gtp_hdr_ext_pdu_session_container *)(gtp_ext + 1);
        if ((const char *)(gtp_psc + 1) > data_end)
            return -1;

        fill_gtp_ext_header_psc(gtp_psc, qfi, PDU_SESSION_CONTAINER_PDU_TYPE_DL_PSU);
    } else {
        fill_gtp_header(gtp, 0, teid, ip_packet_len);
    }

    ip->check = ipv4_csum(ip, sizeof(*ip));

    /* TODO: implement UDP csum which pass ebpf verifier checks successfully */
    // cs = 0;
    // const void* udp_start = (void*)udp;
    // const __u16 udp_len = bpf_htons(udp->len);
    // ipv4_l4_csum(udp, udp_len, &cs, ip);
    // udp->check = cs;

    /* Update packet pointers */
    context_set_ip4(ctx, (char *)(long)ctx->xdp_ctx->data, (const char *)(long)ctx->xdp_ctx->data_end, eth, ip, udp, gtp);
    return 0;
}

static __always_inline void update_gtp_tunnel(struct packet_context *ctx, int srcip, int dstip, __u8 tos, int teid) {

    ctx->gtp->teid = bpf_htonl(teid);
    ctx->ip4->saddr = srcip;
    ctx->ip4->daddr = dstip;
    ctx->ip4->check = 0;
    ctx->ip4->check = ipv4_header_checksum(ctx->ip4, ctx->data_end);
    ctx->udp->check = 0;
    /* TODO: Implement UDP csum:
     * cs = 0;
     * ipv4_l4_csum(udp, sizeof(*udp), &cs, iph);
     * udp->check = cs;
     */
}
