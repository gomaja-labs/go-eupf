// SPDX-License-Identifier: Apache-2.0
#pragma once

// TS 29.244 V20.1.0 clauses 5.17.3 and 8.2.64: preserve the other
// extension headers and signalling body while changing the PDU container.
// Move only the prefix, never the potentially large user payload. Helpers
// available on Linux 5.15 suffice; no shared per-CPU packet scratch is used.
int shift_gtp_bytes(struct xdp_md *xdp, __u64 prefix, __s64 change) {
    char *base=(void *)(long)xdp->data;
    const char *end=(void *)(long)xdp->data_end;
    if (prefix>16464 || change>8 || change < -1024 || !change) return -1;
    if (change<0) {
        __u64 remove=-change;
        asm volatile("" : "+r"(remove));
        remove &= 0x7ff;
        if (!remove || remove>1024) return -1;
        if (base+prefix+remove>end) return -1;
        // Copy backwards in words to keep the minimum-kernel verifier's
        // branch history bounded even for a 16-header extension chain.
        for (int n=0;n<2058;n++) {
            if (prefix<8) break;
            prefix-=8;
            __u64 offset=prefix;
            asm volatile("" : "+r"(offset));
            offset &= 0x7fff;
            char *src=base+offset;
            char *dst=src+remove;
            asm volatile("" : "+r"(src), "+r"(dst));
            if (src+8>end || dst+8>end) return -1;
            __u64 value=*(__u64 *)src;
            *(__u64 *)dst=value;
        }
        for (int n=0;n<7;n++) {
            if (!prefix) break;
            prefix--;
            __u64 offset=prefix & 7;
            char *src=base+offset;
            char *dst=src+remove;
            asm volatile("" : "+r"(src), "+r"(dst));
            if (src+1>end || dst+1>end) return -1;
            *dst=*src;
        }
        if (bpf_xdp_adjust_head(xdp,remove)) return -1;
    } else {
        // Linux 5.15 does not recover change's positive range from
        // clang's combined signed interval check above. Bound the offset
        // explicitly before any packet-pointer arithmetic.
        __u64 growth=change;
        asm volatile("" : "+r"(growth));
        growth &= 0xf;
        if (!growth || growth>8) return -1;
        if (bpf_xdp_adjust_head(xdp,-(__s32)growth)) return -1;
        base=(void *)(long)xdp->data;
        end=(void *)(long)xdp->data_end;
        // Insertions precede the first extension; the prefix is at most
        // Ethernet + IPv4 (including options) + UDP + GTP + optional word.
        if (prefix>94) return -1;
        for (int i=0;i<94;i++) {
            if ((__u32)i>=prefix) break;
            if (base+i+growth+1>end || base+i+1>end) return -1;
            base[i]=base[i+growth];
        }
    }
    return 0;
}

static __noinline int shift_gtp_prefix(struct packet_context *ctx, __u64 prefix, __s32 change) {
    if (bpf_ntohs(ctx->ip4->tot_len)+change>65535 || bpf_ntohs(ctx->udp->len)+change>65535) return -1;
    if (shift_gtp_bytes(ctx->xdp_ctx,prefix,change)) return -1;
    char *base=(void *)(long)ctx->xdp_ctx->data;
    const char *end=(void *)(long)ctx->xdp_ctx->data_end;
    struct ethhdr *eth=(void *)base;
    struct iphdr *ip=(void *)(eth+1);
    if ((const char *)(ip+1)>end) return -1;
    __u32 ihl=ip->ihl*4;
    if (ihl<20 || ihl>60) return -1;
    struct udphdr *udp=(void *)ip+ihl;
    if ((const char *)(udp+1)>end) return -1;
    struct gtpuhdr *gtp=(void *)(udp+1);
    if ((const char *)(gtp+1)>end) return -1;
    context_set_ip4(ctx,base,end,eth,ip,udp,gtp);
    ctx->ip4->tot_len=bpf_htons(bpf_ntohs(ctx->ip4->tot_len)+change);
    ctx->udp->len=bpf_htons(bpf_ntohs(ctx->udp->len)+change);
    ctx->gtp->message_length=bpf_htons(bpf_ntohs(ctx->gtp->message_length)+change);
    ctx->ip4->check=0;
    ctx->ip4->check=ipv4_header_checksum(ctx->ip4,ctx->data_end);
    ctx->udp->check=0;
    ctx->gtp_header_length+=change;
    ctx->ip_end=(char *)ip+bpf_ntohs(ip->tot_len);
    ctx->data=(char *)gtp+ctx->gtp_header_length;
    return 0;
}

static __noinline int delete_gtp_container(struct packet_context *ctx) {
    char *base=(void *)(long)ctx->xdp_ctx->data;
    __u64 gtp_offset=(char *)ctx->gtp-base;
    asm volatile("" : "+r"(gtp_offset));
    gtp_offset &= 0x7fff;
    if (gtp_offset>82) return -1;
    __u64 previous=gtp_offset+11;
    __u64 cursor=gtp_offset+12;
    if (!ctx->gtp->e) return 0;
    if (base+cursor>ctx->data_end) return -1;
    char *first=base+previous;
    if (first+1>ctx->data_end) return -1;
    __u8 next=*first;
    for (int i=0;i<16 && next;i++) {
        if (cursor>16464 || base+cursor+4>ctx->data_end) return -1;
        __u64 span=(__u8)base[cursor]*4;
        if (!span || base+cursor+span>ctx->data_end) return -1;
        __u64 last_offset=(cursor+span-1)&0x7fff;
        asm volatile("" : "+r"(last_offset));
        last_offset &= 0x7fff;
        char *last=base+last_offset;
        asm volatile("" : "+r"(last));
        if (last+1>ctx->data_end) return -1;
        __u8 following=*last;
        if (next==GTPU_EXT_TYPE_PDU_SESSION_CONTAINER) {
            char *link=base+previous;
            if (link+1>ctx->data_end) return -1;
            *link=following;
            // Remove the optional word as well only if no other header
            // or sequence/N-PDU field still needs it.
            if (previous==gtp_offset+11 && !following) {
                ctx->gtp->e=0;
                if (!ctx->gtp->s && !ctx->gtp->pn) { cursor-=4;span+=4; }
            }
            return shift_gtp_prefix(ctx,cursor,-(__s32)span);
        }
        next=following;previous=cursor+span-1;cursor+=span;
    }
    return 0;
}

// TS 38.415 V19.1.0 clause 5.5.2.1: signalling needs only DL PDU
// type and QFI; do not copy user-data RQI/PPP or measurement flags.
static __noinline int insert_gtp_container(struct packet_context *ctx, __u8 qfi) {
    char *base=(void *)(long)ctx->xdp_ctx->data;
    __u32 offset=(char *)(ctx->gtp+1)-base;
    __u8 optional=ctx->gtp->e || ctx->gtp->s || ctx->gtp->pn;
    __u8 following=0;
    if (optional) {
        struct gtp_hdr_ext *opt=(void *)(ctx->gtp+1);
        if ((const char *)(opt+1)>ctx->data_end) return -1;
        following=ctx->gtp->e ? opt->next_ext : 0;
        offset+=4;
    }
    if (shift_gtp_prefix(ctx,offset,optional?4:8)) return -1;
    struct gtp_hdr_ext *opt=(void *)(ctx->gtp+1);
    struct gtp_hdr_ext_pdu_session_container *psc=(void *)(opt+1);
    if ((const char *)(psc+1)>ctx->data_end) return -1;
    ctx->gtp->e=1;
    if (!optional) {opt->sqn=0;opt->npdu=0;}
    opt->next_ext=GTPU_EXT_TYPE_PDU_SESSION_CONTAINER;
    fill_gtp_ext_header_psc(psc,qfi,0);
    psc->next_ext=following;
    return 0;
}
