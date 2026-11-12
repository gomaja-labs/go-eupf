// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/socket.h>

#include "xdp/program_array.h"
#include "xdp/statistics.h"
#include "xdp/qer.h"
#include "xdp/urr.h"
#include "xdp/pdr.h"
#include "xdp/sdf_filter.h"

#include "xdp/utils/common.h"
#include "xdp/utils/trace.h"
#include "xdp/utils/packet_context.h"
#include "xdp/utils/packet_trace.h"
#include "xdp/utils/parsers.h"
#include "xdp/utils/csum.h"
#include "xdp/utils/gtp_utils.h"
#include "xdp/utils/routing.h"
#include "xdp/utils/icmp.h"


#define DEFAULT_XDP_ACTION XDP_PASS
#define UPF_LOCAL_TUNNEL 5
#define UPF_DOWNLINK_IP4 6
#define UPF_DOWNLINK_IP6 7
#define UPF_ROUTER_SOLICITATION 8
#define UPF_ERROR_INDICATION 9
#define UPF_ECHO_RESPONSE 10
#define UPF_SUPPORTED_EXTENSIONS 11
#define UPF_END_MARKER 12

SEC("xdp/upf_ip_entrypoint")
int upf_ip_entrypoint_func(struct xdp_md *ctx);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1); // Number of programs in the chain
    __type(key, __u32);
    __array(values, int (struct xdp_md *));
} jmp_table SEC(".maps") = {
    .values = {
        [0] = (void *)&upf_ip_entrypoint_func, // Map index 0 points to itself
    },
};


struct dataplane_config {
    __u32  n3_ipv4_address;
    __u32  n9_ipv4_address;
    __u8   trace_in;
    __u8   trace_out;
    __u8   trace_blocked;
    __u8   ip6_ra_support;
    __u128 ip6_ra_prefix;
    __u16  ip6_ra_prefix_length;
} global_config;

static __always_inline int is_local_ip(__u32 ip)
{
    return (ip == global_config.n3_ipv4_address || ip == global_config.n9_ipv4_address);
}

static __noinline enum xdp_action handle_gtp_packet(struct packet_context *ctx);

static __always_inline enum xdp_action send_to_gtp_tunnel(struct packet_context *ctx, int srcip, int dstip, __u8 tos, __u8 qfi, int teid, __u8 use_gtp_ext) {
    if (-1 == add_gtp_over_ip4_headers(ctx, srcip, dstip, tos, qfi, teid, use_gtp_ext))
        return XDP_ABORTED;

    if(is_local_ip(ctx->ip4->daddr)) {
        upf_printk("upf: process locally teid:%u remote:%pI4", teid, &ctx->ip4->daddr);
        return UPF_LOCAL_TUNNEL;
        //return handle_gtp_packet(ctx);
    }

    upf_printk("upf: send gtp pdu %pI4 -> %pI4", &ctx->ip4->saddr, &ctx->ip4->daddr);
    increment_counter(ctx->n3_n6_counter, tx_n3);
    return route_ipv4(ctx->xdp_ctx, ctx->eth, ctx->ip4);
}

static __always_inline const struct pdr* check_sdf_filters_ipv4(struct packet_context *ctx, /*const*/ struct pdr_info* session, __u32 ref)
{
    const int sdf_filters_num = sizeof(session->dedicated_pdrs)/sizeof(session->dedicated_pdrs[0]);
    for (int i = 0; i < sdf_filters_num; i++) {
        /*const*/ struct sdf_filter *sdf = &session->dedicated_pdrs[i].sdf_filter;
        if(session->dedicated_pdrs[i].active && match_sdf_filter_ipv4(ctx, sdf)) {
            /*const*/ struct sdf_rule* rule = &session->dedicated_pdrs[i];
            if(rule->notify == 1) { //FIXME: need more appropriate way to make notifications
                rule->notify += 1;
                send_sdf_notify_ip4(ctx, ref);
            }
            return &rule->pdr;
        }
    }

    return 0;
}

static __always_inline const struct pdr* check_sdf_filters_ipv6(struct packet_context *ctx, const struct pdr_info* session, __u32 ref)
{
    const int sdf_filters_num = sizeof(session->dedicated_pdrs)/sizeof(session->dedicated_pdrs[0]);
    for (int i = 0; i < sdf_filters_num; i++) {
        const struct sdf_filter *sdf = &session->dedicated_pdrs[i].sdf_filter;
        if(session->dedicated_pdrs[i].active && match_sdf_filter_ipv6(ctx, sdf)){
             const struct sdf_rule* rule = &session->dedicated_pdrs[i];
            if(rule->notify)
                send_sdf_notify_ip6(ctx, ref);
            return &rule->pdr;
        }
    }

    return 0;
}

static __always_inline const struct pdr* check_sdf_filters_gtp(struct packet_context *ctx, struct pdr_info *session, __u32 ref) {
    // Temporarily parse the inner tuple in the existing cursor. Keeping a
    // second full context on the BPF stack would exceed the 512-byte bound
    // when SDF matching calls its transport-specific subprogram.
    struct iphdr *outer_ip = ctx->ip4;
    struct udphdr *outer_udp = ctx->udp;
    char *payload = ctx->data;
    const char *outer_end = ctx->ip_end;
    const struct pdr *found = 0;
    ctx->ip4=0; ctx->ip6=0; ctx->udp=0; ctx->tcp=0; ctx->ip_end=0;
    if (payload+1 > ctx->data_end) goto done;
    int protocol = guess_eth_protocol(payload);
    if (protocol == ETH_P_IP_BE) {
        int l4 = parse_ip4(ctx);
        if (l4 >= 0 && parse_l4(l4, ctx) >= 0) {
            asm volatile("" ::: "memory");
            found = check_sdf_filters_ipv4(ctx, session, ref);
        }
    } else if (protocol == ETH_P_IPV6_BE) {
        int l4 = parse_ip6(ctx);
        if (l4 >= 0 && parse_l4(l4, ctx) >= 0) {
            asm volatile("" ::: "memory");
            found = check_sdf_filters_ipv6(ctx, session, ref);
        }
    }
 done:
    ctx->ip4=outer_ip; ctx->ip6=0; ctx->udp=outer_udp;ctx->tcp=0;
    ctx->data=payload;ctx->ip_end=outer_end;
    return found;
}

static __noinline enum xdp_action handle_n6_packet_ipv4(struct packet_context *ctx) {
    if (!ctx->ip4 || (const char *)(ctx->ip4+1) > ctx->data_end) return XDP_ABORTED;
    const struct iphdr *ip4 = ctx->ip4;
    struct pdr_info *session = bpf_map_lookup_elem(&pdr_map_downlink_ip4, &ip4->daddr);
    if (!session) {
        upf_printk("upf: [n6] no downlink session for ip:%pI4", &ip4->daddr);
        return DEFAULT_XDP_ACTION;
    }

    upf_printk("upf: [n6] downlink session for ip:%pI4 trace:%d", &ip4->daddr, session->trace_flag);
    ctx->trace = session->trace_flag;
    if(ctx->trace && global_config.trace_in) {
        trace_packet(ctx, PACKET_DIRECTION_IN);
    }

    // Set defaults
    const struct pdr *pdr = &session->default_pdr;
    if (session->sdf_mode) {
        const struct pdr *pdr_sdf = check_sdf_filters_ipv4(ctx, session, ip4->daddr);
        if(pdr_sdf) {
            upf_printk(" [n6] Packet with source ip:%pI4 and destination ip:%pI4 matches SDF filter1", &ip4->saddr, &ip4->daddr);
            pdr = pdr_sdf;
        }
    }

    struct far_info *far = bpf_map_lookup_elem(&far_map, &pdr->far_id);
    if (!far) {
        upf_printk("upf: [n6] no downlink session far for ip:%pI4 far:%d", &ip4->daddr, pdr->far_id);
        return XDP_DROP;
    }

    upf_printk("upf: [n6] downlink session for ip:%pI4  far:%d action:%d", &ip4->daddr, pdr->far_id, far->action);

    if ((far->action & FAR_NOCP) && far->trigger == 0) {
          far->trigger = 1;
    }

    // Only forwarding action is supported at the moment
    if (!(far->action & FAR_FORW))
        return XDP_DROP;

    // Only outer header GTP/UDP/IPv4 is supported at the moment
    if (!(far->outer_header_creation & OHC_GTP_U_UDP_IPv4))
        return XDP_DROP;

    struct qer_info *qer = bpf_map_lookup_elem(&qer_map, &pdr->qer_id);
    if (!qer) {
        upf_printk("upf: [n6] no downlink session qer for ip:%pI4 qer:%d", &ip4->daddr, pdr->qer_id);
        return XDP_DROP;
    }

    upf_printk("upf: [n6] qer:%d gate_status:%d mbr:%u", pdr->qer_id, qer->dl_gate_status, qer->dl_maximum_bitrate);

    if (qer->dl_gate_status != GATE_STATUS_OPEN)
        return XDP_DROP;

    const __u64 packet_size = bpf_ntohs(ip4->tot_len);
    if (packet_size < ip4->ihl * 4 || (const char *)ip4 + packet_size > ctx->data_end) return XDP_DROP;
    enum xdp_action rate_result  = limit_rate_sliding_window(packet_size, &qer->dl_start, qer->dl_maximum_bitrate);
    if (XDP_DROP == rate_result)
        return XDP_DROP;

    __u8 tos = qer->dscp ? qer->dscp : far->transport_level_marking >> 8;

    const int urr_size = sizeof(pdr->urr_id)/sizeof(pdr->urr_id[0]);
    for (int i = 0; i < urr_size; i++) {
        update_urr(pdr->urr_id[i], 0, packet_size);
    }

    upf_printk("upf: [n6] use mapping %pI4 -> teid:%u", &ip4->daddr, far->teid);
    return send_to_gtp_tunnel(ctx, global_config.n3_ipv4_address, far->remoteip, tos, qer->qfi, far->teid, session->nr_flag);
}

static __noinline enum xdp_action handle_n6_packet_ipv6(struct packet_context *ctx) {
    if (!ctx->ip6 || (const char *)(ctx->ip6+1) > ctx->data_end) return XDP_ABORTED;
    const struct ipv6hdr *ip6 = ctx->ip6;
    struct pdr_info *session = bpf_map_lookup_elem(&pdr_map_downlink_ip6, &ip6->daddr);
    if (!session) {
        upf_printk("upf: [n6] no downlink session for ip:%pI6c", &ip6->daddr);
        return DEFAULT_XDP_ACTION;
    }

    upf_printk("upf: [n6] downlink session for ip:%pI6c trace:%d", &ip6->daddr, session->trace_flag);
    ctx->trace = session->trace_flag;
    if(ctx->trace && global_config.trace_in) {
        trace_packet(ctx, PACKET_DIRECTION_IN);
    }

    const struct pdr *pdr = &session->default_pdr;
    if (session->sdf_mode) {
        const struct pdr *pdr_sdf = check_sdf_filters_ipv6(ctx, session, 0);
        if(pdr_sdf) {
            upf_printk(" [n6] Packet with source ip:%pI6c and destination ip:%pI6c matches SDF filter", &ip6->saddr, &ip6->daddr);
            pdr = pdr_sdf;
        }
    }

    struct far_info *far = bpf_map_lookup_elem(&far_map, &pdr->far_id);
    if (!far) {
        upf_printk("upf: [n6] no downlink session far for ip:%pI6c far:%d", &ip6->daddr, pdr->far_id);
        return XDP_DROP;
    }

    if ((far->action & FAR_NOCP) && far->trigger == 0)
        far->trigger = 1;

    upf_printk("upf: [n6] downlink session for ip:%pI6c far:%d action:%d", &ip6->daddr, pdr->far_id, far->action);

    // Only forwarding action supported at the moment
    if (!(far->action & FAR_FORW))
        return XDP_DROP;

    // Only outer header GTP/UDP/IPv4 is supported at the moment
    if (!(far->outer_header_creation & OHC_GTP_U_UDP_IPv4))
        return XDP_DROP;

    struct qer_info *qer = bpf_map_lookup_elem(&qer_map, &pdr->qer_id);
    if (!qer) {
        upf_printk("upf: [n6] no downlink session qer for ip:%pI6c qer:%d", &ip6->daddr, pdr->qer_id);
        return XDP_DROP;
    }

    upf_printk("upf: [n6] qer:%d gate_status:%d mbr:%u", pdr->qer_id, qer->dl_gate_status, qer->dl_maximum_bitrate);

    if (qer->dl_gate_status != GATE_STATUS_OPEN)
        return XDP_DROP;

    const __u64 packet_size = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
    if ((const char *)ip6 + packet_size > ctx->data_end) return XDP_DROP;
    enum xdp_action rate_result = limit_rate_sliding_window(packet_size, &qer->dl_start, qer->dl_maximum_bitrate);
    if (XDP_DROP == rate_result)
        return XDP_DROP;

    __u8 tos = qer->dscp ? qer->dscp : far->transport_level_marking >> 8;

    const int urr_size = sizeof(pdr->urr_id) / sizeof(pdr->urr_id[0]);
    for (int i = 0; i < urr_size; i++) {
        update_urr(pdr->urr_id[i], 0, packet_size);
    }

    upf_printk("upf: [n6] use mapping %pI6c -> teid:%u", &ip6->daddr, far->teid);
    return send_to_gtp_tunnel(ctx, global_config.n3_ipv4_address, far->remoteip, tos, qer->qfi, far->teid, session->nr_flag);
}


static __noinline enum xdp_action handle_gtp_packet(struct packet_context *ctx) {
    if (!ctx->gtp) {
        upf_printk("upf: [n3] unexpected packet context. no gtp header");
        return DEFAULT_XDP_ACTION;
    }

    /*
     *   Step 1: search for PDR and apply PDR instructions
     */
    __u32 teid = bpf_htonl(ctx->gtp->teid);
    struct pdr_info *session = bpf_map_lookup_elem(&pdr_map_teid_ip4, &teid);
    if (!session) {
        // TS 29.281 V19.2.0 clause 7.3.1: discard unknown tunnels, with
        // Error Indication only for a nonzero TEID (subject to error policing).
        if (!teid) return XDP_DROP;
        return UPF_ERROR_INDICATION;
    }

    upf_printk("upf: [n3] teid:%u trace:%d", teid, session->trace_flag);
    ctx->trace = session->trace_flag;
    if(ctx->trace && global_config.trace_in) {
        trace_packet(ctx, PACKET_DIRECTION_IN);
    }

    // Set defaults
    const struct pdr *pdr = &session->default_pdr;
    if (session->sdf_mode) {
        const struct pdr *pdr_sdf = check_sdf_filters_gtp(ctx, session, teid);
        if(pdr_sdf) {
            upf_printk("upf: [n3] sdf filter matches teid:%u", teid);
            pdr = pdr_sdf;
        }
    }

    /*
     *   Step 2: search for FAR and apply FAR instructions
     */
    struct far_info *far = bpf_map_lookup_elem(&far_map, &pdr->far_id);
    if (!far) {
        upf_printk("upf: [n3] no session far for teid:%u far:%d", teid, pdr->far_id);
        return XDP_DROP;
    }

    if ((ctx->unknown_extensions & 2) ||
        ((ctx->unknown_extensions & 1) && !(far->outer_header_creation & OHC_GTP_U_UDP_IPv4)))
        return UPF_SUPPORTED_EXTENSIONS;
    // Unknown bit-pattern 01 extensions must be removed at an intermediate
    // node. Until chain rewriting is supported, leave the intact datagram to
    // the kernel slow path, rather than forwarding forbidden extension data.
    if ((ctx->unknown_extensions & 4) && (far->outer_header_creation & OHC_GTP_U_UDP_IPv4))
        return XDP_PASS;

    upf_printk("upf: [n3] far:%d action:%d outer_header_creation:%d", pdr->far_id, far->action, far->outer_header_creation);

    if ((far->action & FAR_NOCP) && far->trigger == 0) {
          far->trigger = 1;
    }

    // Only forwarding action supported at the moment
    if (!(far->action & FAR_FORW))
        return XDP_DROP;

    /*
     *   Step 3: search for QER and apply QER instructions
     */
    struct qer_info *qer = bpf_map_lookup_elem(&qer_map, &pdr->qer_id);
    if (!qer) {
        upf_printk("upf: [n3] no session qer for teid:%u qer:%d", teid, pdr->qer_id);
        return XDP_DROP;
    }

    upf_printk("upf: [n3] qer:%d gate_status:%d mbr:%u", pdr->qer_id, qer->ul_gate_status, qer->ul_maximum_bitrate);

    if (qer->ul_gate_status != GATE_STATUS_OPEN)
        return XDP_DROP;

    // TS 29.244 V20.1.0 clause 5.2.2.2.1: measure the validated T-PDU
    // after QoS enforcement, excluding GTP and link-layer overhead.
    const __u64 packet_size = ctx->tpdu_length;
    //const __u64 packet_size = ctx->xdp_ctx->data_end - ctx->xdp_ctx->data;
    enum xdp_action rate_result = limit_rate_sliding_window(packet_size, &qer->ul_start, qer->ul_maximum_bitrate);
    if (XDP_DROP == rate_result)
        return XDP_DROP;

    const int urr_size = sizeof(pdr->urr_id)/sizeof(pdr->urr_id[0]);
    for (int i = 0; i < urr_size; i++) {
        update_urr(pdr->urr_id[i], packet_size, 0);
    }

    upf_printk("upf: [n3] session for teid:%u far:%d outer_header_removal:%d", teid, pdr->far_id, pdr->outer_header_removal);

    __u8 tos = qer->dscp ? qer->dscp : far->transport_level_marking >> 8;
    // N9: Only outer header GTP/UDP/IPv4 is supported at the moment
    if (far->outer_header_creation & OHC_GTP_U_UDP_IPv4)
    {
        upf_printk("upf: [n3] session for teid:%u -> %u remote:%pI4", teid, far->teid, &far->remoteip);
        update_gtp_tunnel(ctx, global_config.n9_ipv4_address, far->remoteip, 0, far->teid);

        if(is_local_ip(ctx->ip4->daddr)) {
            upf_printk("upf: [n3] process locally teid:%u -> %u remote:%pI4", teid, far->teid, &far->remoteip);
            return UPF_LOCAL_TUNNEL;
            //return handle_gtp_packet(ctx);
        }
    } else if (pdr->outer_header_removal == OHR_GTP_U_UDP_IPv4 || pdr->outer_header_removal == OHR_GTP_U_UDP_IP) {
        long result = remove_gtp_header(ctx);
        if (result) {
            upf_printk("upf: [n3] handle_gtp_packet: can't remove gtp header: %d", result);
            return XDP_ABORTED;
        }
    }

    /*
     * Decrement IP TTL and reply TTL exeeded message (debug purspose only)
     */
    // if(ctx->ip4 && ctx->ip4->ttl < 2)
    // {
    //     if (-1 == add_icmp_over_ip4_headers(ctx, far->localip, ctx->ip4->saddr))
    //         return XDP_ABORTED;

    //     upf_printk("upf: send icmp ttl exeeded %pI4 -> %pI4", &ctx->ip4->saddr, &ctx->ip4->daddr);
    //     return handle_n6_packet_ipv4(ctx);
    // }

    /*
     * Reply to ping requests (debug purspose only)
     */
    if(ctx->ip4 && is_local_ip(ctx->ip4->daddr) && ctx->ip4->protocol == IPPROTO_ICMP)
    {
        upf_printk("upf: [n3] prepare icmp ping reply to request %pI4 -> %pI4", &ctx->ip4->saddr, &ctx->ip4->daddr);
        if (-1 == prepare_icmp_echo_reply(ctx, ctx->ip4->daddr, ctx->ip4->saddr))
            return XDP_ABORTED;

        upf_printk("upf: [n3] send icmp ping reply %pI4 -> %pI4", &ctx->ip4->saddr, &ctx->ip4->daddr);
        return UPF_DOWNLINK_IP4;
    }

    if(global_config.ip6_ra_support && ctx->ip6 && ctx->ip6->nexthdr == IPPROTO_ICMPV6)
    {
        const struct in6_addr rs_address = { .in6_u.u6_addr8 = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
        if(*((__u128*)ctx->ip6->daddr.s6_addr) == *((__u128*)rs_address.s6_addr))
        {
            const char *data_end = (const char *)(long)ctx->xdp_ctx->data_end;
            struct icmp6hdr *icmp6 = (struct icmp6hdr *)(ctx->ip6 + 1);
            if ((const char *)(icmp6 + 1) <= data_end) {
                if(icmp6->icmp6_type == ICMPV6_ROUTER_SOLICITATION) {
                    return UPF_ROUTER_SOLICITATION;
                }
            }
        }
    }

    /*
     *   Step 4: Route packet finally
     */
    if (ctx->ip4) {
        increment_counter(ctx->n3_n6_counter, tx_n6);
        update_tos_ipv4(ctx->ip4, tos);
        return route_ipv4(ctx->xdp_ctx, ctx->eth, ctx->ip4);
    } else if (ctx->ip6) {
        increment_counter(ctx->n3_n6_counter, tx_n6);
        update_tos_ipv6(ctx->ip6, tos);
        return route_ipv6(ctx->xdp_ctx, ctx->eth, ctx->ip6);
    }

    return XDP_ABORTED;
}

static __noinline enum xdp_action handle_router_solicitation(struct packet_context *ctx) {
    if (!ctx->ip6 || (const char *)(ctx->ip6+1) > ctx->data_end) return XDP_ABORTED;
    int valid = valid_router_solicitation(ctx);
    if (valid <= 0) return valid < 0 ? XDP_PASS : XDP_DROP;
    const struct in6_addr *prefix = (void *)&global_config.ip6_ra_prefix;
    if (prepare_icmp6_ra(ctx, prefix, global_config.ip6_ra_prefix_length))
        return XDP_ABORTED;
    return UPF_DOWNLINK_IP6;
}

static __noinline enum xdp_action handle_end_marker(struct packet_context *ctx) {
    if (!ctx->gtp || !ctx->ip4 || !ctx->udp) return XDP_ABORTED;
            // TS 29.281 V19.2.0 clause 7.3.2: ignore unknown End Markers.
            // An intermediate tunnel forwards via the default FAR without
            // applying user-data QERs or charging URRs. A terminal UPF consumes it.
            increment_counter(ctx->counters, rx_gtp_other);
            __u32 teid=bpf_ntohl(ctx->gtp->teid);
            struct pdr_info *pdr=bpf_map_lookup_elem(&pdr_map_teid_ip4,&teid);
            if (!pdr) return XDP_DROP;
            struct far_info *far=bpf_map_lookup_elem(&far_map,&pdr->default_pdr.far_id);
            if (!far || !(far->action & FAR_FORW) || !(far->outer_header_creation & OHC_GTP_U_UDP_IPv4)) return XDP_DROP;
            update_gtp_tunnel(ctx,global_config.n9_ipv4_address,far->remoteip,0,far->teid);
            if (is_local_ip(ctx->ip4->daddr)) return UPF_LOCAL_TUNNEL;
            return route_ipv4(ctx->xdp_ctx,ctx->eth,ctx->ip4);

}

static __noinline enum xdp_action handle_gtpu(struct packet_context *ctx) {
    int pdu_type = parse_gtp(ctx);
    if (pdu_type == -3) return XDP_PASS;
    if (pdu_type < 0) {
        increment_counter(ctx->counters, rx_gtp_unexp);
        return XDP_DROP;
    }
    switch (pdu_type) {
        case GTPU_G_PDU:
            increment_counter(ctx->counters, rx_gtp_pdu);
            return handle_gtp_packet(ctx);
        case GTPU_ECHO_REQUEST:
            if (ctx->unknown_extensions & 3) return UPF_SUPPORTED_EXTENSIONS;
            increment_counter(ctx->counters, rx_gtp_echo);
            // upf_printk("upf: gtp header [ version=%d, pt=%d, e=%d]", gtp->version, gtp->pt, gtp->e);
            // upf_printk("upf: gtp echo request [ type=%d ]", pdu_type);
            upf_printk("upf: gtp echo request [ %pI4 -> %pI4 ]", &ctx->ip4->saddr, &ctx->ip4->daddr);
            return UPF_ECHO_RESPONSE;
        case GTPU_ECHO_RESPONSE:
            return XDP_PASS; //Pass echo response to userspace program
        case GTPU_END_MARKER: return UPF_END_MARKER;
        case GTPU_ERROR_INDICATION:
        case GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION:
            increment_counter(ctx->counters, rx_gtp_other);
            return DEFAULT_XDP_ACTION;
        default:
            increment_counter(ctx->counters, rx_gtp_unexp);
            upf_printk("upf: unexpected gtp message: type=%d", pdu_type);
            return DEFAULT_XDP_ACTION;
    }
}

static __always_inline enum xdp_action handle_ip4(struct packet_context *ctx) {
    int l4_protocol = parse_ip4(ctx);
    switch (l4_protocol) {
        case IPPROTO_ICMP: {
            increment_counter(ctx->counters, rx_icmp);
            break;
        }
        case IPPROTO_UDP:
            increment_counter(ctx->counters, rx_udp);
            if (GTP_UDP_PORT == parse_udp(ctx)
                && (ctx->ip4->daddr == global_config.n3_ipv4_address
                    || ctx->ip4->daddr == global_config.n9_ipv4_address)) {
                upf_printk("upf: gtp-u received");
                increment_counter(ctx->n3_n6_counter, rx_n3);
                return handle_gtpu(ctx);
            }
            break;
        case IPPROTO_TCP:
            increment_counter(ctx->counters, rx_tcp);
            if (parse_tcp(ctx) < 0) return XDP_PASS;
            break;
        default:
            increment_counter(ctx->counters, rx_other);
            return DEFAULT_XDP_ACTION;
    }

    increment_counter(ctx->n3_n6_counter, rx_n6);
    return handle_n6_packet_ipv4(ctx);
}

static __always_inline enum xdp_action handle_ip6(struct packet_context *ctx) {
    int l4_protocol = parse_ip6(ctx);
    switch (l4_protocol) {
        case IPPROTO_ICMPV6:
            increment_counter(ctx->counters, rx_icmp6);
            break;
        case IPPROTO_UDP:
            increment_counter(ctx->counters, rx_udp);
            if (parse_udp(ctx) < 0) return XDP_PASS;
            // Don't expect GTP over IPv6 at the moment
            // if (GTP_UDP_PORT == parse_udp(ctx))
            // {
            //     upf_printk("upf: gtp-u received");
            //     return handle_gtpu(ctx);
            // }
            break;
        case IPPROTO_TCP:
            increment_counter(ctx->counters, rx_tcp);
            if (parse_tcp(ctx) < 0) return XDP_PASS;
            break;
        default:
            increment_counter(ctx->counters, rx_other);
            return DEFAULT_XDP_ACTION;
    }
    increment_counter(ctx->n3_n6_counter, rx_n6);
    return handle_n6_packet_ipv6(ctx);
}

static __always_inline enum xdp_action process_packet(struct packet_context *ctx) {
    __u16 l3_protocol = parse_ethernet(ctx);
    switch (l3_protocol) {
        case ETH_P_IPV6:
            increment_counter(ctx->counters, rx_ip6);
            return handle_ip6(ctx);
        case ETH_P_IP:
            increment_counter(ctx->counters, rx_ip4);
            return handle_ip4(ctx);
        case ETH_P_ARP:  // Let kernel stack takes care
        {
            increment_counter(ctx->counters, rx_arp);
            upf_printk("upf: arp received. passing to kernel");
            return XDP_PASS;
        }
    }

    return DEFAULT_XDP_ACTION;
}

// Combined N3 & N6 entrypoint. Use for "on-a-stick" interfaces
SEC("xdp/upf_ip_entrypoint")
int upf_ip_entrypoint_func(struct xdp_md *ctx) {
    // upf_printk("upf n3 & n6 combined entrypoint start");
    const __u32 key = 0;
    struct upf_statistic *statistic = bpf_map_lookup_elem(&upf_ext_stat, &key);
    if (!statistic) return XDP_ABORTED;

    // Calculate how short the packet is compared to a physical 64-byte frame
    __u32 current_len = (void *)(long)ctx->data_end - (void *)(long)ctx->data;
    if (current_len < 60) {
        const __u32 padding_needed = 60 - current_len;
        // Expand the packet tail dynamically
        bpf_xdp_adjust_tail(ctx, padding_needed);
    }

    /* These keep track of the packet pointers and statistic */
    struct packet_context context = {
        .data = (char *)(long)ctx->data,
        .data_end = (const char *)(long)ctx->data_end,
        .xdp_ctx = ctx,
        .counters = &statistic->upf_counters,
        .n3_n6_counter = &statistic->upf_n3_n6_counter,
        .trace = 0};

    enum xdp_action action = process_packet(&context);
    if (action == UPF_ERROR_INDICATION)
        action = reply_gtp_control(&context, GTPU_ERROR_INDICATION);
    else if (action == UPF_ECHO_RESPONSE)
        action = reply_gtp_control(&context, GTPU_ECHO_RESPONSE);
    else if (action == UPF_SUPPORTED_EXTENSIONS)
        action = reply_gtp_control(&context, GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION);
    else if (action == UPF_END_MARKER)
        action = handle_end_marker(&context);
    if (action == UPF_ROUTER_SOLICITATION)
        action = handle_router_solicitation(&context);
    if (action == UPF_DOWNLINK_IP4)
        action = handle_n6_packet_ipv4(&context);
    else if (action == UPF_DOWNLINK_IP6)
        action = handle_n6_packet_ipv6(&context);
    // Dispatch local tunnel recursion only from the entry frame. This keeps
    // bounded kernel tail calls independent of ordinary BPF subprogram stacks.
    if (action == UPF_LOCAL_TUNNEL) {
        bpf_tail_call(ctx, &jmp_table, 0);
        action = XDP_ABORTED;
    }
    statistic->xdp_actions[action & EUPF_MAX_XDP_ACTION_MASK] += 1;

    if(global_config.trace_out && context.trace && (action == XDP_TX || action == XDP_REDIRECT)) {
        trace_packet(&context, PACKET_DIRECTION_OUT);
    } else if (global_config.trace_blocked && action != XDP_TX && action != XDP_REDIRECT) {
        trace_packet(&context, PACKET_DIRECTION_BLOCKED);
    }

    return action;
}

char _license[] SEC("license") = "GPL";
