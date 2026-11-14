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
#include "xdp/buffering.h"
#include "xdp/buffer_result.h"
#include "xdp/utils/packet_trace.h"
#include "xdp/utils/parsers.h"
#include "xdp/utils/csum.h"
#include "xdp/utils/gtp_utils.h"
#include "xdp/utils/gtp_handover.h"
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
SEC("xdp/upf_router_solicitation")
int upf_router_solicitation_func(struct xdp_md *ctx);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
#ifdef BUFFER_CONTINUATION
    __uint(max_entries,4);
#else
    __uint(max_entries,3);
#endif // Local recursion, router control and buffering continuation
    __type(key, __u32);
    __array(values, int (struct xdp_md *));
} jmp_table SEC(".maps") = {
    .values = {
        [0] = (void *)&upf_ip_entrypoint_func,
        [1] = (void *)&upf_router_solicitation_func,
        [2] = (void *)&upf_buffer_admission_func,
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

__u64 gtp_error_suppress_until;

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

struct pdi_packet {
    __u128 source;
    __u128 destination;
    __u16 source_port;
    __u16 destination_port;
    __u8 family;
    __u8 protocol;
    __u8 qfi;
    __u8 qfi_present;
    __u8 source_interface;
    __u8 ports_present;
    __u8 reserved[6];
};

// This scalar metadata helper does not re-parse packet headers for each PDR.
__noinline int output_sdf_event(struct xdp_md *ctx,__u64 session_id,__u32 pdr_id,const struct pdi_packet *packet) {
    if (!packet) return 0;
    if (packet->family==1) {
        struct sdf_notify_ip4 meta={.cookie=0x1ea1,.session_id=session_id,.pdr_id=pdr_id};
        meta.tuple5.src_ip=(__u32)packet->source;meta.tuple5.dst_ip=(__u32)packet->destination;
        meta.tuple5.src_port=bpf_htons(packet->source_port);meta.tuple5.dst_port=bpf_htons(packet->destination_port);meta.tuple5.protocol=packet->protocol;
        return bpf_perf_event_output(ctx,&sdf_notify_map,BPF_F_CURRENT_CPU,&meta,sizeof(meta));
    }
    struct sdf_notify_ip6 meta={.cookie=0x2ea2,.session_id=session_id,.pdr_id=pdr_id};
    __builtin_memcpy(&meta.tuple5.src_ip,&packet->source,16);__builtin_memcpy(&meta.tuple5.dst_ip,&packet->destination,16);
    meta.tuple5.src_port=bpf_htons(packet->source_port);meta.tuple5.dst_port=bpf_htons(packet->destination_port);meta.tuple5.protocol=packet->protocol;
    return bpf_perf_event_output(ctx,&sdf_notify_map,BPF_F_CURRENT_CPU,&meta,sizeof(meta));
}

// RFC 6733 section 4.3.1: assigned matches the session's terminal address
// set, including its IPv6 prefix. It is distinct from an unrestricted match.
static __always_inline int match_assigned(const struct pdr_entry *entry, const struct pdi_packet *packet, __u128 address) {
    if (packet->family == 1)
        return entry->assigned_ip4_present && (__u32)address == entry->assigned_ip4;
    __u128 value, mask;
    __builtin_memcpy(&value, entry->assigned_ip6, 16);
    __builtin_memcpy(&mask, entry->assigned_mask6, 16);
    return entry->assigned_ip6_present && !((address ^ value) & mask);
}

// TS 29.244 V20.1.0 clause 5.2.1. This memory-only subprogram is
// verified independently: packet parsing is complete before PDR selection.
int match_pdr_entry(const struct pdr_entry *entry, const struct pdi_packet *packet) {
    if (!entry || !packet) return 0;
    if (entry->source_interface_present && entry->source_interface != packet->source_interface) return 0;
    if (entry->qfi_count > QFI_LIST_SIZE || entry->sdf_count > SDF_LIST_SIZE) return 0;
    if (entry->qfi_count) {
        if (!packet->qfi_present) return 0;
        int found=0;
        for (int i=0;i<QFI_LIST_SIZE;i++) {
            if (i<entry->qfi_count && entry->qfis[i]==packet->qfi) {found=1;break;}
        }
        if (!found) return 0;
    }
    if (entry->ue_ip4_present || entry->ue_ip6_present) {
        __u128 address=entry->ue_destination?packet->destination:packet->source;
        if (packet->family==1) {
            if (!entry->ue_ip4_present || (((__u32)address ^ entry->ue_ip4) & entry->ue_mask4)) return 0;
        } else {
            if (!entry->ue_ip6_present) return 0;
            __u128 value,mask;
            __builtin_memcpy(&value,entry->ue_ip6,16);__builtin_memcpy(&mask,entry->ue_mask6,16);
            if ((address^value)&mask) return 0;
        }
    }
    if (!entry->sdf_count) return 1;
    for (int i=0;i<SDF_LIST_SIZE;i++) {
        if (i>=entry->sdf_count) break;
        const struct sdf_filter *filter=&entry->sdf_filters[i];
        if (filter->protocol!=256 && filter->protocol!=packet->protocol) continue;
        if ((filter->src_addr.type && filter->src_addr.type!=3 && filter->src_addr.type!=packet->family) || (filter->dst_addr.type && filter->dst_addr.type!=3 && filter->dst_addr.type!=packet->family)) continue;
        __u128 src=packet->family==1?bpf_htonl((__u32)filter->src_addr.ip):bpf_htonlll(filter->src_addr.ip);
        __u128 dst=packet->family==1?bpf_htonl((__u32)filter->dst_addr.ip):bpf_htonlll(filter->dst_addr.ip);
        __u128 src_mask=packet->family==1?bpf_htonl((__u32)filter->src_addr.mask):bpf_htonlll(filter->src_addr.mask);
        __u128 dst_mask=packet->family==1?bpf_htonl((__u32)filter->dst_addr.mask):bpf_htonlll(filter->dst_addr.mask);
        if (filter->src_addr.type == 3) { if (!match_assigned(entry, packet, packet->source)) continue; }
        else if (filter->src_addr.type && ((packet->source^src)&src_mask)) continue;
        if (filter->dst_addr.type == 3) { if (!match_assigned(entry, packet, packet->destination)) continue; }
        else if (filter->dst_addr.type && ((packet->destination^dst)&dst_mask)) continue;
        if (filter->ports_present && !packet->ports_present) continue;
        if (filter->ports_present && (packet->source_port<filter->src_port.lower_bound || packet->source_port>filter->src_port.upper_bound || packet->destination_port<filter->dst_port.lower_bound || packet->destination_port>filter->dst_port.upper_bound)) continue;
        return 1;
    }
    return 0;
}

static __noinline const struct pdr *select_pdr(struct packet_context *ctx,struct pdr_info *session,const struct pdi_packet *packet,__u32 ref) {
    for (int i=0;i<PDR_LIST_SIZE;i++) {
        if (i>=session->count) break;
        struct pdr_entry *entry=&session->entries[i];
        if (entry->match_mode) {
            if (entry->match_mode!=1 && entry->match_mode!=packet->source_interface+2) continue;
        } else if (!match_pdr_entry(entry,packet)) continue;
        ctx->trace=entry->trace_flag;ctx->nr_flag=entry->nr_flag;
        ctx->return_pdr=&entry->return_pdr;ctx->return_nr_flag=entry->return_nr_flag;
        if (entry->notify==1 && __sync_val_compare_and_swap(&entry->notify,1,2)==1)
            output_sdf_event(ctx->xdp_ctx,session->session_id,entry->pdr_id,packet);
        return &entry->pdr;
    }
    return 0;
}
// A single unconstrained PDR needs no tuple construction or classifier call.
// match_mode is encoded only when UE, QFI and SDF constraints are absent;
// event notification still takes the complete tuple path. Source Interface
// remains a predicate even on this path.
static __always_inline const struct pdr *select_unfiltered_pdr(struct packet_context *ctx, struct pdr_info *session) {
    if (session->count != 1) return 0;
    struct pdr_entry *entry = &session->entries[0];
    if (!entry->match_mode || entry->notify == 1) return 0;
    if (entry->match_mode != 1 && entry->match_mode != ctx->source_interface + 2) return 0;
    ctx->trace = entry->trace_flag;
    ctx->nr_flag = entry->nr_flag;
    ctx->return_pdr = &entry->return_pdr;
    ctx->return_nr_flag = entry->return_nr_flag;
    return &entry->pdr;
}
static __always_inline void pdi_ports(struct packet_context *ctx,struct pdi_packet *tuple) {
    tuple->source_port=ctx->source_port;
    tuple->destination_port=ctx->destination_port;
    tuple->ports_present=ctx->ports_present;
}
static __always_inline const struct pdr* check_sdf_filters_ipv4(struct packet_context *ctx,struct pdr_info *session,__u32 ref) {
    const struct pdr *unfiltered = select_unfiltered_pdr(ctx, session);
    if (unfiltered) return unfiltered;
    struct pdi_packet packet={.source=ctx->ip4->saddr,.destination=ctx->ip4->daddr,.family=1,.protocol=ctx->ip4->protocol,.qfi=ctx->qfi,.qfi_present=ctx->qfi_present,.source_interface=ctx->source_interface};
    pdi_ports(ctx,&packet);
    return select_pdr(ctx,session,&packet,ref);
}
static __always_inline const struct pdr* check_sdf_filters_ipv6(struct packet_context *ctx,struct pdr_info *session,__u32 ref) {
    const struct pdr *unfiltered = select_unfiltered_pdr(ctx, session);
    if (unfiltered) return unfiltered;
    struct pdi_packet packet={.family=2,.protocol=ctx->ip_protocol,.qfi=ctx->qfi,.qfi_present=ctx->qfi_present,.source_interface=ctx->source_interface};
    __builtin_memcpy(&packet.source,&ctx->ip6->saddr,16);__builtin_memcpy(&packet.destination,&ctx->ip6->daddr,16);
    pdi_ports(ctx,&packet);
    return select_pdr(ctx,session,&packet,ref);
}

static __always_inline const struct pdr* check_sdf_filters_gtp(struct packet_context *ctx, struct pdr_info *session, __u32 ref) {
    const struct pdr *unfiltered = select_unfiltered_pdr(ctx, session);
    if (unfiltered) return unfiltered;
    // Temporarily parse the inner tuple in the existing cursor. Keeping a
    // second full context on the BPF stack would exceed the 512-byte bound
    // when SDF matching calls its transport-specific subprogram.
    struct iphdr *outer_ip = ctx->ip4;
    struct udphdr *outer_udp = ctx->udp;
    char *payload = ctx->data;
    const char *outer_end = ctx->ip_end;
    const struct pdr *found = 0;
    ctx->ip4=0; ctx->ip6=0; ctx->udp=0; ctx->tcp=0; ctx->ip_end=0;
    ctx->source_port=0;ctx->destination_port=0;ctx->ports_present=0;
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

// TS 29.244 V20.1.0 clause 5.4.4: apply every QER in CP binding
// order. The first QER carrying QFI supplies QFI/RQI and DSCP marking.
// Verify one QER independently; carrying each policer branch through the whole
// binding loop otherwise exceeds the verifier's state bound on Linux 5.15.
int apply_qer(struct qer_info *qer, __u64 packet_size, __u32 uplink) {
    if (!qer) return -1;
    if (uplink ? qer->ul_gate_status != GATE_STATUS_OPEN : qer->dl_gate_status != GATE_STATUS_OPEN) return -1;
    // TS 29.244 V20.1.0 clause 5.4.4: old and replacement QERs meter
    // the same flow. Keep their atomic policer state in the initial slot;
    // that anchor is reserved until the logical QER is finally removed.
    struct qer_info *state=qer;
    __u32 policer_id=qer->policer_id;
    if (policer_id) {
        state=bpf_map_lookup_elem(&qer_map,&policer_id);
        if (!state) return -1;
    }
    if (XDP_DROP == limit_rate_sliding_window(packet_size, uplink ? &state->ul_start : &state->dl_start, uplink ? qer->ul_maximum_bitrate : qer->dl_maximum_bitrate)) return -1;
    return ((__u32)qer->dscp << 8) | (qer->qfi_present ? 0x80 | (qer->qfi & 0x3f) | ((qer->rqi & 1) << 6) : 0);
}
int enforce_qers(const struct pdr *pdr,__u64 packet_size,__u32 uplink) {
    if (!pdr || pdr->qer_count>4) return -1;
    if (!pdr->qer_count) return 0;
    if (pdr->qer_count==1) {
        __u32 id=pdr->qer_id[0];if (!id) return -1;
        struct qer_info *qer=bpf_map_lookup_elem(&qer_map,&id);
        int result=apply_qer(qer,packet_size,uplink);
        return result<0?-1:(result&0xffff);
    }
    __u32 marking=0;
    for (int i=0;i<4;i++) {
        if (i>=pdr->qer_count) break;
        __u32 id=pdr->qer_id[i];if (!id) return -1;
        struct qer_info *qer=bpf_map_lookup_elem(&qer_map,&id);
        int result = apply_qer(qer, packet_size, uplink);
        if (result < 0) return -1;
        __u32 bits = result & 0xffff;
        if (!(marking >> 8)) marking |= bits & 0xff00;
        if (!(marking & 0x80)) marking |= bits & 0xff;
    }
    return marking;
}

// Buffering is reached only from the base FORW rejection. Neither binding
// lookup nor notification/accounting state is touched by a plain FORW packet.
// TS 29.244 V20.1.0 clauses 5.2.3.1 and 5.2.4.2.
static __always_inline enum xdp_action buffer_n6_packet(struct packet_context *ctx, const struct pdr *pdr, const struct far_info *far) {
    if (!(far->action & FAR_BUFF)) return XDP_DROP;
    __u64 size;
    if (ctx->ip4) {
        size=bounded_wire_length(ctx->ip4->tot_len);
        if (size<ctx->ip4->ihl*4 || (const char *)ctx->ip4+size>ctx->data_end) return XDP_DROP;
    } else if (ctx->ip6) {
        size=bounded_wire_length(ctx->ip6->payload_len)+sizeof(*ctx->ip6);
        if ((const char *)ctx->ip6+size>ctx->data_end) return XDP_DROP;
    } else return XDP_DROP;
    int marking=enforce_qers(pdr,size,0);
    if (marking<0) return XDP_DROP;
    if (!ctx->locally_generated) {
        if (ctx->ip4) {
            if ((const char *)(ctx->ip4+1)>ctx->data_end) return XDP_ABORTED;
            if (ctx->ip4->ttl<=1) return XDP_PASS;
            __u16 old,new;
            __builtin_memcpy(&old,&ctx->ip4->ttl,sizeof(old));
            ctx->ip4->ttl--;
            __builtin_memcpy(&new,&ctx->ip4->ttl,sizeof(new));
            ipv4_csum_replace(&ctx->ip4->check,old,new);
        } else if (ctx->ip6) {
            if ((const char *)(ctx->ip6+1)>ctx->data_end) return XDP_ABORTED;
            if (ctx->ip6->hop_limit<=1) return XDP_PASS;
            ctx->ip6->hop_limit--;
        } else return XDP_ABORTED;
    }
    for (int i=0;i<URR_LIST_SIZE;i++) update_urr(pdr->urr_id[i],0,size);
    int action=buffer_admit(ctx,pdr,far,marking,0);
    if (action!=BUFFER_DIRECT) {
        if (action==UPF_BUFFER_PACKET) {
            ctx->continuation=2;
#ifdef BUFFER_CONTINUATION
            buffer_result_admitted();
#endif
            return UPF_LOCAL_TUNNEL;
        }
        return action;
    }
    if (!(far->action & FAR_BUFFER_RELEASE) || !(far->outer_header_creation & OHC_GTP_U_UDP_IPv4)) return XDP_DROP;
    __u8 tos=marking>>8 ? marking>>8 : far->transport_level_marking>>8;
    return send_to_gtp_tunnel(ctx,global_config.n3_ipv4_address,far->remoteip,tos,marking&0x7f,far->teid,ctx->nr_flag && (marking&0x80));
}

static __noinline enum xdp_action handle_n6_packet_ipv4(struct packet_context *ctx) {
    if (!ctx->ip4 || (const char *)(ctx->ip4+1) > ctx->data_end) return XDP_ABORTED;
    struct iphdr *ip4 = ctx->ip4;
    int stale=0;
        struct pdr_info *session = lookup_pdr4(&pdr_map_downlink_ip4, ip4->daddr, 1, &stale);
    if (!session) {
        upf_printk("upf: [n6] no downlink session for ip:%pI4", &ip4->daddr);
        return DEFAULT_XDP_ACTION;
    }

    ctx->source_interface=1;
    const struct pdr *pdr = check_sdf_filters_ipv4(ctx,session,ip4->daddr);
    if (!pdr || !pdr->far_id) return XDP_DROP;
    if (ctx->trace && global_config.trace_in) trace_packet(ctx,PACKET_DIRECTION_IN);

    struct far_info *far = bpf_map_lookup_elem(&far_map, &pdr->far_id);
    if (!far) {
        upf_printk("upf: [n6] no downlink session far for ip:%pI4 far:%d", &ip4->daddr, pdr->far_id);
        return XDP_DROP;
    }

    upf_printk("upf: [n6] downlink session for ip:%pI4  far:%d action:%d", &ip4->daddr, pdr->far_id, far->action);


    // Only forwarding action is supported at the moment
    if (!(far->action & FAR_FORW))
        return buffer_n6_packet(ctx,pdr,far);

    // Only outer header GTP/UDP/IPv4 is supported at the moment
    if (!(far->outer_header_creation & OHC_GTP_U_UDP_IPv4))
        return XDP_DROP;

    const __u64 packet_size=bounded_wire_length(ip4->tot_len);
    if (packet_size<ip4->ihl*4 || (const char *)ip4+packet_size>ctx->data_end) return XDP_DROP;
    int marking=enforce_qers(pdr,packet_size,0);if (marking<0) return XDP_DROP;

    // RFC 1812 section 5.3.1: decrement the forwarded inner datagram before
    // encapsulation. Leave exhausted packets intact for kernel ICMP handling.
    if (!ctx->locally_generated) {
        if (ip4->ttl <= 1) return XDP_PASS;
        __u16 old = *(__u16 *)&ip4->ttl;
        ip4->ttl--;
        ipv4_csum_replace(&ip4->check, old, *(__u16 *)&ip4->ttl);
    }

    __u8 tos = marking >> 8 ? marking >> 8 : far->transport_level_marking >> 8;

    const int urr_size = sizeof(pdr->urr_id)/sizeof(pdr->urr_id[0]);
    for (int i = 0; i < urr_size; i++) {
        update_urr(pdr->urr_id[i], 0, packet_size);
    }

    upf_printk("upf: [n6] use mapping %pI4 -> teid:%u", &ip4->daddr, far->teid);
    return send_to_gtp_tunnel(ctx, global_config.n3_ipv4_address, far->remoteip, tos, marking & 0x7f, far->teid, ctx->nr_flag && (marking & 0x80));
}

static __noinline enum xdp_action forward_n6_packet_ipv6(struct packet_context *ctx, const struct pdr *pdr) {
    if (!ctx->ip6 || (const char *)(ctx->ip6+1)>ctx->data_end) return XDP_ABORTED;
    struct ipv6hdr *ip6=ctx->ip6;
    if (!pdr || !pdr->far_id) return XDP_DROP;
    if (ctx->trace && global_config.trace_in) trace_packet(ctx,PACKET_DIRECTION_IN);

    struct far_info *far = bpf_map_lookup_elem(&far_map, &pdr->far_id);
    if (!far) {
        upf_printk("upf: [n6] no downlink session far for ip:%pI6c far:%d", &ip6->daddr, pdr->far_id);
        return XDP_DROP;
    }


    upf_printk("upf: [n6] downlink session for ip:%pI6c far:%d action:%d", &ip6->daddr, pdr->far_id, far->action);

    // Only forwarding action supported at the moment
    if (!(far->action & FAR_FORW))
        return buffer_n6_packet(ctx,pdr,far);

    // Only outer header GTP/UDP/IPv4 is supported at the moment
    if (!(far->outer_header_creation & OHC_GTP_U_UDP_IPv4))
        return XDP_DROP;

    const __u64 packet_size=bounded_wire_length(ip6->payload_len)+sizeof(*ip6);
    if ((const char *)ip6+packet_size>ctx->data_end) return XDP_DROP;
    int marking=enforce_qers(pdr,packet_size,0);if (marking<0) return XDP_DROP;

    // RFC 8200 section 3. Locally originated advertisements retain Hop
    // Limit 255 (RFC 4861 section 4.2); their tunnel outer packet is routed.
    if (!ctx->locally_generated) {
        if (ip6->hop_limit <= 1) return XDP_PASS;
        ip6->hop_limit--;
    }

    __u8 tos = marking >> 8 ? marking >> 8 : far->transport_level_marking >> 8;

    const int urr_size = sizeof(pdr->urr_id) / sizeof(pdr->urr_id[0]);
    for (int i = 0; i < urr_size; i++) {
        update_urr(pdr->urr_id[i], 0, packet_size);
    }

    upf_printk("upf: [n6] use mapping %pI6c -> teid:%u", &ip6->daddr, far->teid);
    return send_to_gtp_tunnel(ctx, global_config.n3_ipv4_address, far->remoteip, tos, marking & 0x7f, far->teid, ctx->nr_flag && (marking & 0x80));
}

// Classification owns its tuple and prefix-key temporaries. They must not
// remain in the forwarding call chain's stack budget on Linux 5.15.
static __noinline const struct pdr *find_downlink_ipv6(struct packet_context *ctx) {
    struct ipv6_pdr_key key={.prefix_length=128};
    __builtin_memcpy(key.address,&ctx->ip6->daddr,16);
    struct pdr_info *session=bpf_map_lookup_elem(&pdr_map_downlink_ip6,&key);
    ctx->pdr_matched_key=session!=0;
    if (!session) return 0;
    ctx->source_interface=1;
    return check_sdf_filters_ipv6(ctx,session,0);
}

static __noinline enum xdp_action handle_n6_packet_ipv6(struct packet_context *ctx) {
    if (!ctx->ip6 || (const char *)(ctx->ip6+1) > ctx->data_end) return XDP_ABORTED;
    const struct pdr *pdr=0;
    if (ctx->locally_generated) {
        // RFC 4861 sections 4.2 and 6.2.6 choose the IPv6 destination;
        // TS 29.244 V20.1.0 clause 5.2.1 keeps the return tunnel tied to
        // the originating PFCP session, including link-local/multicast RAs.
        pdr=ctx->return_pdr;ctx->nr_flag=ctx->return_nr_flag;
    } else {
        pdr=find_downlink_ipv6(ctx);
        if (!pdr) {
            // Unknown destinations retain the kernel path; known buckets with
            // no matching PDR must drop. The classifier records that outcome.
            return ctx->pdr_matched_key ? XDP_DROP : DEFAULT_XDP_ACTION;
        }
    }
    return forward_n6_packet_ipv6(ctx,pdr);
}


static __always_inline enum xdp_action finish_gtp_forwarding(struct packet_context *ctx, const struct far_info *far, int marking, __u32 removal, __u32 *output) {
    int from_cp=ctx->source_interface==3;

    __u8 tos = marking >> 8 ? marking >> 8 : far->transport_level_marking >> 8;
    // N9: Only outer header GTP/UDP/IPv4 is supported at the moment
    if (far->outer_header_creation & OHC_GTP_U_UDP_IPv4)
    {
        if (from_cp) {
            // CP-originated downlink packets need the session's DL QFI and
            // PDU Session Container, rather than retaining an absent CP QFI.
            if (remove_gtp_header(ctx)) return XDP_ABORTED;
            if (add_gtp_over_ip4_headers(ctx,global_config.n3_ipv4_address,far->remoteip,tos,marking&0x7f,far->teid,ctx->nr_flag && (marking&0x80))) return XDP_ABORTED;
            if (is_local_ip(ctx->ip4->daddr)) return UPF_LOCAL_TUNNEL;
            if (!output) increment_counter(ctx->n3_n6_counter,tx_n3);
            return route_ipv4_output(ctx->xdp_ctx,ctx->eth,ctx->ip4,output);
        }
        // TS 29.244 V20.1.0 clause 5.17.3 applies the same container
        // mapping to G-PDUs and End Markers on forwarding tunnels.
        if (((removal>>16)&0xff) & 1) {
            if (delete_gtp_container(ctx)) return XDP_DROP;
        } else if (!ctx->qfi_present && (marking & 0x80)) {
            if (insert_gtp_container(ctx,marking & 0x7f)) return XDP_DROP;
        }
        __u32 local=global_config.n9_ipv4_address;
        if (far->destination_interface_present && far->destination_interface==3) {
            local=global_config.n3_ipv4_address;
            ctx->ip4->tos=tos;
        }
        update_gtp_tunnel(ctx, local, far->remoteip, 0, far->teid);

        if(is_local_ip(ctx->ip4->daddr)) {
            return UPF_LOCAL_TUNNEL;
            //return handle_gtp_packet(ctx);
        }
    } else if (((removal>>8)&0xff) && ((removal&0xff) == OHR_GTP_U_UDP_IPv4 || (removal&0xff) == OHR_GTP_U_UDP_IP)) {
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
        if (!output) increment_counter(ctx->n3_n6_counter, tx_n6);
        update_tos_ipv4(ctx->ip4, tos);
        return route_ipv4_output(ctx->xdp_ctx, ctx->eth, ctx->ip4,output);
    } else if (ctx->ip6) {
        if (!output) increment_counter(ctx->n3_n6_counter, tx_n6);
        update_tos_ipv6(ctx->ip6, tos);
        return route_ipv6_output(ctx->xdp_ctx, ctx->eth, ctx->ip6,output);
    }

    return XDP_ABORTED;
}

static __always_inline enum xdp_action buffer_gtp_packet(struct packet_context *ctx, const struct pdr *pdr, const struct far_info *far) {
    if (!(far->action & FAR_BUFF)) return XDP_DROP;
    int uplink=ctx->source_interface==0 || (ctx->source_interface==3 && far->destination_interface_present &&
        (far->destination_interface==1 || far->destination_interface==2));
    int marking=enforce_qers(pdr,ctx->tpdu_length,uplink);
    if (marking<0) return XDP_DROP;
    for (int i=0;i<URR_LIST_SIZE;i++) update_urr(pdr->urr_id[i],uplink?ctx->tpdu_length:0,uplink?0:ctx->tpdu_length);
    int action=buffer_admit(ctx,pdr,far,marking,uplink);
    if (action!=BUFFER_DIRECT) {
        if (action==UPF_BUFFER_PACKET) {
            ctx->continuation=2;
#ifdef BUFFER_CONTINUATION
            buffer_result_admitted();
#endif
            return UPF_LOCAL_TUNNEL;
        }
        return action;
    }
    if (!(far->action & FAR_BUFFER_RELEASE)) return XDP_DROP;
    __u32 removal=pdr->outer_header_removal | ((__u32)pdr->outer_header_removal_present<<8) | ((__u32)pdr->gtp_extension_header_deletion<<16);
    return finish_gtp_forwarding(ctx,far,marking,removal,0);
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
    int stale=0;
    struct pdr_info *session = lookup_pdr4(&pdr_map_teid_ip4, teid, 0, &stale);
    if (!session) {
        // TS 29.281 V19.2.0 clause 7.3.1: discard unknown tunnels, with
        // Error Indication only for a nonzero TEID (subject to error policing).
        if (!teid || stale) return XDP_DROP;
        // TS 23.527 V20.0.0 clause 4.3.2; TS 23.007 V19.2.0
        // clauses 16.1A.4/17.1b.1: restoration must not tear down bearers.
        if (gtp_error_suppress_until && bpf_ktime_get_ns() < gtp_error_suppress_until) {
            ctx->counters->gtp_error_suppressed++;
            return XDP_DROP;
        }
        return UPF_ERROR_INDICATION;
    }

    ctx->source_interface = ctx->ip4->daddr == global_config.n9_ipv4_address && global_config.n9_ipv4_address != global_config.n3_ipv4_address ? 1 : 0;
    // TS 29.244 V20.1.0 clause 5.3.1: the UP-allocated N4-u TEID
    // identifies the CP-side ingress context, even on the same local address.
    for (int i=0; i<PDR_LIST_SIZE; i++) {
        if (i>=session->count) break;
        if (session->entries[i].source_interface_present && session->entries[i].source_interface==3) {
            ctx->source_interface=3;
            break;
        }
    }
    const struct pdr *pdr = check_sdf_filters_gtp(ctx,session,teid);
    if (!pdr || !pdr->far_id) return XDP_DROP;
    if (ctx->trace && global_config.trace_in) trace_packet(ctx,PACKET_DIRECTION_IN);

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


    // Only forwarding action supported at the moment
    if (!(far->action & FAR_FORW))
        return buffer_gtp_packet(ctx,pdr,far);

    /*
     *   Step 3: search for QER and apply QER instructions
     */
    const __u64 packet_size=ctx->tpdu_length;
    int from_cp=ctx->source_interface==3;
    // TS 29.244 V20.1.0 clause 5.4.4: CP-to-Access is DL,
    // CP-to-Core/SGi/N6 is UL. The TEID identifies CP ingress, not direction.
    int uplink=ctx->source_interface==0 ||
        (from_cp && far->destination_interface_present &&
        (far->destination_interface==1 || far->destination_interface==2));
    int marking=enforce_qers(pdr,packet_size,uplink);if (marking<0) return XDP_DROP;

    const int urr_size = sizeof(pdr->urr_id)/sizeof(pdr->urr_id[0]);
    for (int i = 0; i < urr_size; i++) {
        update_urr(pdr->urr_id[i], uplink ? packet_size : 0, uplink ? 0 : packet_size);
    }

    upf_printk("upf: [n3] session for teid:%u far:%d outer_header_removal:%d", teid, pdr->far_id, pdr->outer_header_removal);

    __u8 tos = marking >> 8 ? marking >> 8 : far->transport_level_marking >> 8;
    // N9: Only outer header GTP/UDP/IPv4 is supported at the moment
    if (far->outer_header_creation & OHC_GTP_U_UDP_IPv4)
    {
        upf_printk("upf: [n3] session for teid:%u -> %u remote:%pI4", teid, far->teid, &far->remoteip);
        if (from_cp) {
            // CP-originated downlink packets need the session's DL QFI and
            // PDU Session Container, rather than retaining an absent CP QFI.
            if (remove_gtp_header(ctx)) return XDP_ABORTED;
            return send_to_gtp_tunnel(ctx,global_config.n3_ipv4_address,far->remoteip,tos,marking&0x7f,far->teid,ctx->nr_flag && (marking&0x80));
        }
        // TS 29.244 V20.1.0 clause 5.17.3 applies the same container
        // mapping to G-PDUs and End Markers on forwarding tunnels.
        if (pdr->gtp_extension_header_deletion & 1) {
            if (delete_gtp_container(ctx)) return XDP_DROP;
        } else if (!ctx->qfi_present && (marking & 0x80)) {
            if (insert_gtp_container(ctx,marking & 0x7f)) return XDP_DROP;
        }
        __u32 local=global_config.n9_ipv4_address;
        if (far->destination_interface_present && far->destination_interface==3) {
            local=global_config.n3_ipv4_address;
            ctx->ip4->tos=tos;
        }
        update_gtp_tunnel(ctx, local, far->remoteip, 0, far->teid);

        if(is_local_ip(ctx->ip4->daddr)) {
            upf_printk("upf: [n3] process locally teid:%u -> %u remote:%pI4", teid, far->teid, &far->remoteip);
            return UPF_LOCAL_TUNNEL;
            //return handle_gtp_packet(ctx);
        }
    } else if (pdr->outer_header_removal_present && (pdr->outer_header_removal == OHR_GTP_U_UDP_IPv4 || pdr->outer_header_removal == OHR_GTP_U_UDP_IP)) {
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

// TS 29.244 V20.1.0 clauses 5.17.3 and 5.2.3.1 NOTE 4: End
// Markers select the E-RAB by ingress interface and QFI, without a T-PDU,
// QoS policing, usage accounting or downlink-data notification.
static __noinline enum xdp_action handle_end_marker(struct packet_context *ctx) {
    if (!ctx->gtp || !ctx->ip4 || !ctx->udp) return XDP_ABORTED;
    increment_counter(ctx->counters,rx_gtp_other);
    __u32 teid=bpf_ntohl(ctx->gtp->teid);
    int stale=0;
    struct pdr_info *session=lookup_pdr4(&pdr_map_teid_ip4,teid,0,&stale);
    if (!session) return XDP_DROP;
    __u8 source=ctx->ip4->daddr==global_config.n9_ipv4_address && global_config.n9_ipv4_address!=global_config.n3_ipv4_address ? 1 : 0;
    const struct pdr *pdr=0;
    for (int i=0;i<PDR_LIST_SIZE;i++) {
        if (i>=session->count) break;
        const struct pdr_entry *entry=&session->entries[i];
        if (entry->source_interface_present && entry->source_interface!=source) continue;
        if (entry->qfi_count) {
            int matches=0;
            for (int j=0;j<QFI_LIST_SIZE;j++) {
                if (j>=entry->qfi_count) break;
                if (ctx->qfi_present && entry->qfis[j]==ctx->qfi) matches=1;
            }
            if (!matches) continue;
        }
        pdr=&entry->pdr;break;
    }
    if (!pdr || !pdr->far_id) return XDP_DROP;
    struct far_info *far=bpf_map_lookup_elem(&far_map,&pdr->far_id);
    if (!far || far->end_marker_suppressed || !(far->action & FAR_FORW) || !(far->outer_header_creation & OHC_GTP_U_UDP_IPv4)) return XDP_DROP;
    // TS 29.281 V19.2.0 figure 5.2.1-2: unknown 01 extensions must
    // not reach the receiver. As for G-PDUs, retain the intact slow path
    // until this extension-content removal is supported.
    if (ctx->unknown_extensions & 4) return XDP_PASS;
    if (pdr->gtp_extension_header_deletion & 1) {
        if (delete_gtp_container(ctx)) return XDP_DROP;
    } else if (!ctx->qfi_present) {
        for (int i=0;i<4;i++) {
            if (i>=pdr->qer_count) break;
            __u32 id=pdr->qer_id[i];
            struct qer_info *qer=bpf_map_lookup_elem(&qer_map,&id);
            if (qer && qer->qfi_present) {
                if (insert_gtp_container(ctx,qer->qfi)) return XDP_DROP;
                break;
            }
        }
    }
    __u32 local=far->destination_interface_present && far->destination_interface==3 ? global_config.n3_ipv4_address : global_config.n9_ipv4_address;
    update_gtp_tunnel(ctx,local,far->remoteip,0,far->teid);
    if (is_local_ip(ctx->ip4->daddr)) return UPF_LOCAL_TUNNEL;
    return route_ipv4(ctx->xdp_ctx,ctx->eth,ctx->ip4);
}

static __always_inline enum xdp_action handle_gtpu(struct packet_context *ctx) {
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
        case IPPROTO_SCTP:
            if (parse_sctp(ctx) < 0) return XDP_PASS;
            break;
        default:
            increment_counter(ctx->counters, rx_other);
            if (l4_protocol < 0) return DEFAULT_XDP_ACTION;
            break;
    }

    increment_counter(ctx->n3_n6_counter, rx_n6);
    return handle_n6_packet_ipv4(ctx);
}

static __always_inline enum xdp_action handle_ip6(struct packet_context *ctx) {
    int l4_protocol=parse_ip6(ctx);
    if (l4_protocol==-2) return XDP_DROP;
    if (l4_protocol<0) return DEFAULT_XDP_ACTION;
    if (parse_l4(l4_protocol,ctx)<0) return XDP_DROP;
    switch(l4_protocol) {
        case IPPROTO_ICMPV6: increment_counter(ctx->counters,rx_icmp6);break;
        case IPPROTO_UDP: increment_counter(ctx->counters,rx_udp);break;
        case IPPROTO_TCP: increment_counter(ctx->counters,rx_tcp);break;
        default: increment_counter(ctx->counters,rx_other);break;
    }
    increment_counter(ctx->n3_n6_counter,rx_n6);
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

// Router control has a separate verifier budget. The continuation carries
// only rule IDs and flags in this packet's private headroom, never shared CPU
// storage or kernel pointers. The kernel RCU reader encloses both tail calls.
struct router_reply_context {
    struct pdr pdr;
    __u32 pdr_id;
    __u32 magic;
    __u32 nr;
    __u32 trace;
};
#define ROUTER_REPLY_MAGIC 0x52534358

static __always_inline int continue_router_solicitation(struct xdp_md *ctx, struct packet_context *packet) {
    if (!packet->return_pdr) return XDP_DROP;
    struct router_reply_context saved={.pdr_id=buffer_pdr_id(packet),.magic=ROUTER_REPLY_MAGIC,.nr=packet->return_nr_flag,.trace=packet->trace};
    __builtin_memcpy(&saved.pdr,packet->return_pdr,sizeof(saved.pdr));
    if (bpf_xdp_adjust_head(ctx,-(int)sizeof(saved))) return XDP_ABORTED;
    void *data=(void *)(long)ctx->data;
    if (data+sizeof(saved)>(void *)(long)ctx->data_end) return XDP_ABORTED;
    __builtin_memcpy(data,&saved,sizeof(saved));
    bpf_tail_call(ctx,&jmp_table,1);
    return XDP_ABORTED;
}

SEC("xdp/upf_router_solicitation")
int upf_router_solicitation_func(struct xdp_md *ctx) {
    void *data=(void *)(long)ctx->data;
    if (data+sizeof(struct router_reply_context)>(void *)(long)ctx->data_end) BUFFER_RETURN(ctx,XDP_ABORTED);
    struct router_reply_context saved;
    // The prepended packet metadata can be unaligned. Copy one word at a
    // time into its aligned stack image: a whole-struct memcpy makes clang
    // keep many byte-assembly temporaries live and spill beyond the call-chain
    // budget (Linux v5.15 kernel/bpf/verifier.c:3679 rounds each frame to 32).
    #pragma unroll
    for (int i=0;i<sizeof(saved)/sizeof(__u32);i++) {
        __u32 word;
        __builtin_memcpy(&word,data+i*sizeof(word),sizeof(word));
        ((volatile __u32 *)&saved)[i]=word;
    }
    if (saved.magic!=ROUTER_REPLY_MAGIC) BUFFER_RETURN(ctx,XDP_ABORTED);
    if (bpf_xdp_adjust_head(ctx,sizeof(saved))) BUFFER_RETURN(ctx,XDP_ABORTED);
    __u32 key=0;
    struct upf_statistic *statistic=bpf_map_lookup_elem(&upf_ext_stat,&key);
    if (!statistic) BUFFER_RETURN(ctx,XDP_ABORTED);
    struct packet_context packet={
        .data=(void *)(long)ctx->data,.data_end=(void *)(long)ctx->data_end,.xdp_ctx=ctx,
        .counters=&statistic->upf_counters,.n3_n6_counter=&statistic->upf_n3_n6_counter,
        .return_pdr=&saved.pdr,.return_nr_flag=saved.nr,.trace=saved.trace,.pdr_id=saved.pdr_id,
    };
    if (parse_ethernet(&packet)!=ETH_P_IPV6 || parse_ip6(&packet)!=IPPROTO_ICMPV6) BUFFER_RETURN(ctx,XDP_DROP);
    int action=handle_router_solicitation(&packet);
    if (action==UPF_DOWNLINK_IP6) {
        packet.locally_generated=1;
        packet.nr_flag=packet.return_nr_flag;
        action=forward_n6_packet_ipv6(&packet,&saved.pdr);
    }
    if (action==UPF_LOCAL_TUNNEL) {
        bpf_tail_call(ctx,&jmp_table,packet.continuation);
        BUFFER_RETURN(ctx,XDP_ABORTED);
    }
    statistic->xdp_actions[action & EUPF_MAX_XDP_ACTION_MASK]++;
    if (global_config.trace_out && packet.trace && (action==XDP_TX || action==XDP_REDIRECT))
        trace_packet(&packet,PACKET_DIRECTION_OUT);
    else if (global_config.trace_blocked && action!=XDP_TX && action!=XDP_REDIRECT)
        trace_packet(&packet,PACKET_DIRECTION_BLOCKED);
    BUFFER_RETURN(ctx,action);
}

// Combined N3 & N6 entrypoint. Use for "on-a-stick" interfaces
SEC("xdp/upf_ip_entrypoint")
int upf_ip_entrypoint_func(struct xdp_md *ctx) {
    // upf_printk("upf n3 & n6 combined entrypoint start");
    const __u32 key = 0;
    struct upf_statistic *statistic = bpf_map_lookup_elem(&upf_ext_stat, &key);
    if (!statistic) BUFFER_RETURN(ctx,XDP_ABORTED);
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
        { int continued=continue_router_solicitation(ctx,&context);BUFFER_RETURN(ctx,continued); }
    if (action == UPF_DOWNLINK_IP4)
        action = handle_n6_packet_ipv4(&context);
    else if (action == UPF_DOWNLINK_IP6)
        action = handle_n6_packet_ipv6(&context);
    // Dispatch local tunnel recursion only from the entry frame. This keeps
    // bounded kernel tail calls independent of ordinary BPF subprogram stacks.
    if (action == UPF_LOCAL_TUNNEL) {
        bpf_tail_call(ctx, &jmp_table, context.continuation);
        BUFFER_RETURN(ctx,XDP_ABORTED);
    }
    statistic->xdp_actions[action & EUPF_MAX_XDP_ACTION_MASK] += 1;

    if(global_config.trace_out && context.trace && (action == XDP_TX || action == XDP_REDIRECT)) {
        trace_packet(&context, PACKET_DIRECTION_OUT);
    } else if (global_config.trace_blocked && action != XDP_TX && action != XDP_REDIRECT) {
        trace_packet(&context, PACKET_DIRECTION_BLOCKED);
    }

    BUFFER_RETURN(ctx,action);
}

#ifdef BUFFER_CONTINUATION
// A generated IPv4 echo reply uses normal downlink processing in a fresh
// program frame, just as router replies have their own continuation budget.
SEC("xdp/upf_buffer_downlink")
int upf_buffer_downlink_func(struct xdp_md *ctx) {
    __u32 zero=0;
    struct upf_statistic *statistic=bpf_map_lookup_elem(&upf_ext_stat,&zero);
    if (!statistic) return buffer_result_finish(ctx,XDP_ABORTED,0);
    struct packet_context packet={.data=(void *)(long)ctx->data,.data_end=(void *)(long)ctx->data_end,.xdp_ctx=ctx,.locally_generated=1,
        .counters=&statistic->upf_counters,.n3_n6_counter=&statistic->upf_n3_n6_counter};
    int protocol=parse_ethernet(&packet),action=XDP_ABORTED;
    if (protocol==ETH_P_IP && parse_ip4(&packet)>=0) action=handle_n6_packet_ipv4(&packet);
    else if (protocol==ETH_P_IPV6 && parse_ip6(&packet)>=0) action=handle_n6_packet_ipv6(&packet);
    if (action==UPF_LOCAL_TUNNEL) { bpf_tail_call(ctx,&jmp_table,packet.continuation);return buffer_result_finish(ctx,XDP_ABORTED,0); }
    return buffer_result_finish(ctx,action,0);
}
#endif

#include "xdp/buffer_render.h"

char _license[] SEC("license") = "GPL";
