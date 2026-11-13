// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors
#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define BUFFER_FAR_LANES 128
#define BUFFER_FRAME_SIZE 2048
#define BUFFER_DIRECT 8
#define BUFFER_HOLD 1
#define BUFFER_DRAIN 2
#define BUFFER_FORWARD 3
#define BUFFER_DISCARD 4

struct buffer_far {
    __u64 cookie;
    __u64 produced;
    __u64 completed;
    __u32 mode;
    __u32 ready;
    __u32 preparing;
    __u32 reserved;
};

static __always_inline void buffer_maybe_forward(struct buffer_far *far) {
    if (far->mode==BUFFER_DRAIN && far->ready && !far->preparing && far->produced==far->completed)
        far->mode=BUFFER_FORWARD;
}

// One lock shares the BAR packet bound across all FARs/QoS flows of a session.
// TS 29.244 V20.1.0 clauses 5.2.4.1 and 8.2.30.
struct buffer_anchor {
    struct bpf_spin_lock lock;
    __u32 outstanding;
    __u32 limit;
    __u32 reserved;
    struct buffer_far far[BUFFER_FAR_LANES];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct buffer_anchor);
} buffer_anchors SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} buffer_events SEC(".maps");

struct buffer_record {
    __u64 session_id;
    __u64 cookie;
    __u64 sequence;
    __u64 received_ns;
    __u32 lane;
    __u32 pdr_id;
    __u32 length;
    __u32 ingress_ifindex;
    __u16 marking;
    __u8 kind;
    __u8 nr;
    __u8 source_interface;
    __u8 outer_removal;
    __u8 outer_removal_present;
    __u8 extension_deletion;
    __u8 qfi;
    __u8 qfi_present;
    __u8 ppi;
    __u8 notify;
    __u32 reserved;
    __u8 packet[BUFFER_FRAME_SIZE];
};

struct buffer_command {
    __u64 session_id;
    __u64 cookie;
    __u64 sequence;
    __u32 lane;
    __u32 operation; // 0: acknowledge, 1: mode/ready, 2: shared limit, 3: read
    __u32 mode;
    __u32 ready;
    __u32 limit;
    __u32 outstanding;
    __u64 produced;
    __u64 completed;
};

// Private test-run control entry; never placed in the attached program array.
SEC("xdp/upf_buffer_control")
int upf_buffer_control_func(struct xdp_md *ctx) {
    struct buffer_command *command=(void *)(long)ctx->data;
    if ((void *)(command+1)>(void *)(long)ctx->data_end) return XDP_ABORTED;
    __u64 id=command->session_id, cookie=command->cookie, sequence=command->sequence;
    __u64 lane=command->lane;
    __u32 operation=command->operation, mode=command->mode;
    __u32 ready=command->ready, limit=command->limit;
    if (lane>=BUFFER_FAR_LANES || operation>6 || mode>BUFFER_DISCARD || ready>1) return XDP_ABORTED;
    asm volatile("" : "+r"(lane));
    lane &= BUFFER_FAR_LANES-1;
    struct buffer_anchor *anchor=bpf_map_lookup_elem(&buffer_anchors,&id);
    if (!anchor) return XDP_ABORTED;
    int action=XDP_ABORTED;
    bpf_spin_lock(&anchor->lock);
    struct buffer_far *far=&anchor->far[lane];
    if (operation==5 && cookie && !far->cookie && mode==BUFFER_HOLD) {
        far->cookie=cookie;
        far->mode=mode;
        far->ready=0;
        far->produced=far->completed=0;
        far->preparing=0;
        action=XDP_DROP;
    } else if (cookie && far->cookie==cookie) {
        if (!operation) {
            if (sequence<=far->completed) action=XDP_DROP;
            else if (sequence==far->completed+1 && sequence<=far->produced && anchor->outstanding) {
                far->completed=sequence;
                anchor->outstanding--;
                action=XDP_DROP;
            }
        } else if (operation==1 && (mode==BUFFER_DISCARD ||
            (mode==BUFFER_HOLD && far->mode>=BUFFER_HOLD && far->mode<=BUFFER_FORWARD) ||
            (mode==BUFFER_DRAIN && (far->mode==BUFFER_HOLD || far->mode==BUFFER_DRAIN ||
                (far->mode==BUFFER_FORWARD && ready && far->produced==far->completed))))) {
            far->mode=mode;
            far->ready=ready;
            action=XDP_DROP;
        } else if (operation==2) {
            anchor->limit=limit;
            action=XDP_DROP;
        } else if (operation==3) action=XDP_DROP;
        // Journal rollback restores controls, never producer/consumer counters.
        else if (operation==4 && mode>=BUFFER_HOLD) {
            far->mode=mode;
            far->ready=ready;
            action=XDP_DROP;
        } else if (operation==6 && !far->preparing && far->produced==far->completed &&
            (far->mode==BUFFER_DISCARD || far->mode==BUFFER_FORWARD)) {
            far->cookie=far->produced=far->completed=0;
            far->mode=far->ready=0;
            action=XDP_DROP;
        }
        buffer_maybe_forward(far);
        command->sequence=far->preparing;
        command->mode=far->mode;
        command->ready=far->ready;
        command->outstanding=anchor->outstanding;
        command->limit=anchor->limit;
        command->produced=far->produced;
        command->completed=far->completed;
    }
    bpf_spin_unlock(&anchor->lock);
    return action;
}

// Scalar continuation state is per CPU. An XDP invocation remains on its CPU
// through the tail call; packet/map pointers never cross this boundary.
struct buffer_pending {
    __u64 session_id;
    __u64 cookie;
    __u32 lane;
    __u32 pdr_id;
    __u32 ingress_ifindex;
    __u32 ppi_offset;
    __u16 marking;
    __u8 kind;
    __u8 nr;
    __u8 source_interface;
    __u8 outer_removal;
    __u8 outer_removal_present;
    __u8 extension_deletion;
    __u8 qfi;
    __u8 qfi_present;
    __u8 notify;
};
struct {
    __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries,1);
    __type(key,__u32);
    __type(value,struct buffer_pending);
} buffer_pending_packet SEC(".maps");
#define UPF_BUFFER_PACKET 13

static __noinline int buffer_admit(struct packet_context *ctx, const struct pdr *pdr, const struct far_info *far, int marking, int uplink) {
    __u64 id=far->buffer_session_id, cookie=far->buffer_cookie;
    __u64 lane=far->buffer_lane;
    __u32 key=0;
    if (!id || !cookie || lane>=BUFFER_FAR_LANES) return XDP_DROP;
    asm volatile("" : "+r"(lane));
    lane &= BUFFER_FAR_LANES-1;
    struct buffer_anchor *anchor=bpf_map_lookup_elem(&buffer_anchors,&id);
    if (!anchor) return XDP_DROP;
    int direct=0, eligible=0;
    bpf_spin_lock(&anchor->lock);
    struct buffer_far *state=&anchor->far[lane];
    if (state->cookie==cookie) {
        buffer_maybe_forward(state);
        direct=state->mode==BUFFER_FORWARD;
        eligible=(state->mode==BUFFER_HOLD || state->mode==BUFFER_DRAIN) && state->preparing!=~0U;
        if (eligible) state->preparing++;
    }
    bpf_spin_unlock(&anchor->lock);
    if (direct) return BUFFER_DIRECT;
    if (!eligible) return XDP_DROP;
    struct buffer_pending *pending=bpf_map_lookup_elem(&buffer_pending_packet,&key);
    if (!pending) {
        bpf_spin_lock(&anchor->lock);
        if (state->cookie==cookie && state->preparing) { state->preparing--; buffer_maybe_forward(state); }
        bpf_spin_unlock(&anchor->lock);
        return XDP_DROP;
    }
    pending->session_id=id;
    pending->cookie=cookie;
    pending->lane=lane;
    pending->pdr_id=ctx->pdr_id;
    pending->ingress_ifindex=ctx->xdp_ctx->ingress_ifindex;
    pending->marking=marking;
    pending->kind=ctx->gtp ? 3 : ctx->ip6 ? 2 : 1;
    pending->nr=ctx->nr_flag;
    pending->source_interface=ctx->source_interface;
    pending->outer_removal=pdr->outer_header_removal;
    pending->outer_removal_present=pdr->outer_header_removal_present;
    pending->extension_deletion=pdr->gtp_extension_header_deletion;
    pending->qfi=(marking&0x80) ? marking&0x3f : ctx->qfi;
    pending->qfi_present=(marking&0x80) || ctx->qfi_present;
    pending->notify=(far->action&FAR_NOCP) && !uplink;
    // Ethernet is followed by either the native IP header or by the parsed
    // IPv4/UDP/GTP envelope. Keep only a bounded scalar cursor across tail calls.
    __u32 offset=14;
    if (ctx->gtp) {
        if (!ctx->ip4 || (const char *)(ctx->ip4+1)>ctx->data_end) {
            bpf_spin_lock(&anchor->lock);
            if (state->cookie==cookie && state->preparing) { state->preparing--; buffer_maybe_forward(state); }
            bpf_spin_unlock(&anchor->lock);
            return XDP_DROP;
        }
        offset+=ctx->ip4->ihl*4+8+ctx->gtp_header_length;
    }
    pending->ppi_offset=offset<BUFFER_FRAME_SIZE-1 ? offset : ~0U;
    return UPF_BUFFER_PACKET;
}

static __always_inline void buffer_prepare_failed(struct buffer_anchor *anchor, __u64 lane, __u64 cookie) {
    bpf_spin_lock(&anchor->lock);
    struct buffer_far *far=&anchor->far[lane];
    if (far->cookie==cookie && far->preparing) {
        far->preparing--;
        buffer_maybe_forward(far);
    }
    bpf_spin_unlock(&anchor->lock);
}

// Fixed slots are copied before sequence assignment. Reservation/copy failures
// cannot strand a sequence. No helper runs while the admission lock is held.
// TS 29.244 V20.1.0 clauses 5.2.3.1 and 5.2.4.2.
SEC("xdp/upf_buffer_admission")
int upf_buffer_admission_func(struct xdp_md *ctx) {
    __u32 key=0;
    struct upf_statistic *statistic=bpf_map_lookup_elem(&upf_ext_stat,&key);
    if (statistic) statistic->xdp_actions[XDP_DROP]++;
    struct buffer_pending *pending=bpf_map_lookup_elem(&buffer_pending_packet,&key);
    if (!pending) return XDP_DROP;
    __u64 id=pending->session_id, cookie=pending->cookie;
    __u64 lane=pending->lane;
    if (!id || !cookie || lane>=BUFFER_FAR_LANES) return XDP_DROP;
    asm volatile("" : "+r"(lane));
    lane &= BUFFER_FAR_LANES-1;
    struct buffer_anchor *anchor=bpf_map_lookup_elem(&buffer_anchors,&id);
    if (!anchor) return XDP_DROP;
    __u64 raw_length=(__u64)ctx->data_end-ctx->data;
    if (raw_length<14 || raw_length>BUFFER_FRAME_SIZE) { buffer_prepare_failed(anchor,lane,cookie); return XDP_DROP; }
    __u32 length=raw_length;
    asm volatile("" : "+r"(length));
    length &= 0xfff;
    if (length<14 || length>BUFFER_FRAME_SIZE) { buffer_prepare_failed(anchor,lane,cookie); return XDP_DROP; }
    struct buffer_record *record=bpf_ringbuf_reserve(&buffer_events,sizeof(*record),0);
    if (!record) { buffer_prepare_failed(anchor,lane,cookie); return XDP_DROP; }
    volatile __u64 *words=(void *)record->packet;
#pragma clang loop unroll(full)
    for (int i=0;i<BUFFER_FRAME_SIZE/8;i++) words[i]=0;
    if (bpf_probe_read_kernel(record->packet,length,(void *)(long)ctx->data)) {
        bpf_ringbuf_discard(record,0);
        buffer_prepare_failed(anchor,lane,cookie);
        return XDP_DROP;
    }
    record->session_id=id;
    record->cookie=cookie;
    record->received_ns=bpf_ktime_get_ns();
    record->lane=lane;
    record->pdr_id=pending->pdr_id;
    record->length=length;
    record->ingress_ifindex=pending->ingress_ifindex;
    record->marking=pending->marking;
    record->kind=pending->kind;
    record->nr=pending->nr;
    record->source_interface=pending->source_interface;
    record->outer_removal=pending->outer_removal;
    record->outer_removal_present=pending->outer_removal_present;
    record->extension_deletion=pending->extension_deletion;
    record->qfi=pending->qfi;
    record->qfi_present=pending->qfi_present;
    record->ppi=0;
    __u32 offset=pending->ppi_offset;
    if (offset<BUFFER_FRAME_SIZE-1 && offset+2<=length) {
        __u8 first=record->packet[offset],second=record->packet[offset+1];
        if ((first>>4)==4) record->ppi=second>>2;
        else if ((first>>4)==6) record->ppi=((first&15)<<2)|(second>>6);
    }
    record->notify=pending->notify;
    record->reserved=0;
    int admitted=0;
    bpf_spin_lock(&anchor->lock);
    struct buffer_far *state=&anchor->far[lane];
    if (state->cookie==cookie && state->preparing) {
        state->preparing--;
        if ((state->mode==BUFFER_HOLD || state->mode==BUFFER_DRAIN) &&
            state->produced!=~0ULL && anchor->outstanding<anchor->limit) {
            record->sequence=++state->produced;
            anchor->outstanding++;
            admitted=1;
        }
        buffer_maybe_forward(state);
    }
    bpf_spin_unlock(&anchor->lock);
    if (!admitted) { bpf_ringbuf_discard(record,0); return XDP_DROP; }
    bpf_ringbuf_submit(record,0);
    return XDP_DROP;
}
