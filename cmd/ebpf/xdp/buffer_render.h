// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors
#pragma once

// Private BPF_PROG_TEST_RUN renderer. The prefix has the buffer record's scalar
// header; pdr_id carries the pinned current FAR slot on input, length carries
// the resolved interface on output, and reserved carries the forwarding action.
// TS 29.244 V20.1.0 clause 5.2.4.2: buffered packets have already undergone
// classification, QER policing and URR accounting. Native inner TTL/Hop Limit
// was also processed before admission; only the resulting outer route remains.
SEC("xdp/upf_buffer_render")
int upf_buffer_render_func(struct xdp_md *xdp) {
    struct buffer_record *input=(void *)(long)xdp->data;
    const char *end=(void *)(long)xdp->data_end;
    if ((const char *)input+64>end) return XDP_ABORTED;
    __u32 slot=input->pdr_id;
    __u32 length=input->length;
    if (length<14 || length>BUFFER_FRAME_SIZE || (const char *)input+64+length>end) return XDP_ABORTED;
    struct far_info *far=bpf_map_lookup_elem(&far_map,&slot);
    if (!far || !(far->action&FAR_FORW) || !input->cookie ||
        far->buffer_session_id!=input->session_id || far->buffer_cookie!=input->cookie ||
        far->buffer_lane!=input->lane) return XDP_ABORTED;
    int marking=input->marking;
    __u32 kind=input->kind;
    __u32 removal=input->outer_removal | ((__u32)input->outer_removal_present<<8) | ((__u32)input->extension_deletion<<16);
    __u8 nr=input->nr,source=input->source_interface;
    __u32 key=0;
    struct upf_statistic *statistic=bpf_map_lookup_elem(&upf_ext_stat,&key);
    if (!statistic) return XDP_ABORTED;
    if (bpf_xdp_adjust_head(xdp,64)) return XDP_ABORTED;
    struct packet_context packet={.data=(void *)(long)xdp->data,.data_end=(void *)(long)xdp->data_end,.xdp_ctx=xdp,
        .counters=&statistic->upf_counters,.n3_n6_counter=&statistic->upf_n3_n6_counter,.nr_flag=nr,.source_interface=source};
    int protocol=parse_ethernet(&packet);
    int action=XDP_ABORTED;
    __u32 output=0;
    if ((kind==1 || kind==3) && protocol==ETH_P_IP) {
        int transport=parse_ip4(&packet);
        if (transport<0) return XDP_ABORTED;
        if (kind==3) {
            if (transport!=IPPROTO_UDP || parse_udp(&packet)!=GTP_UDP_PORT || parse_gtp(&packet)!=GTPU_G_PDU) return XDP_ABORTED;
            action=finish_gtp_forwarding(&packet,far,marking,removal,&output);
            goto done;
        }
    } else if (kind==2 && protocol==ETH_P_IPV6) {
        if (parse_ip6(&packet)<0) return XDP_ABORTED;
    } else return XDP_ABORTED;
    if (kind==1 || kind==2) {
        if (!(far->outer_header_creation&OHC_GTP_U_UDP_IPv4)) return XDP_ABORTED;
        __u8 tos=marking>>8 ? marking>>8 : far->transport_level_marking>>8;
        if (add_gtp_over_ip4_headers(&packet,global_config.n3_ipv4_address,far->remoteip,tos,marking&0x7f,far->teid,nr && (marking&0x80))) return XDP_ABORTED;
        if (is_local_ip(packet.ip4->daddr)) action=UPF_LOCAL_TUNNEL;
        else action=route_ipv4_output(xdp,packet.eth,packet.ip4,&output);
    }
done:
    if (bpf_xdp_adjust_head(xdp,-64)) return XDP_ABORTED;
    struct buffer_record *result=(void *)(long)xdp->data;
    if ((char *)result+64>(char *)(long)xdp->data_end) return XDP_ABORTED;
    __builtin_memset(result,0,64);
    result->length=output;
    result->reserved=action;
    return XDP_PASS;
}
