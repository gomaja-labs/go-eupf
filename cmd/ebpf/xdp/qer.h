// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#include "xdp/sizing.h"
#include "xdp/rate_math.h"

enum gate_status {
    GATE_STATUS_OPEN = 0,
    GATE_STATUS_CLOSED = 1,
    GATE_STATUS_RESERVED1 = 2,
    GATE_STATUS_RESERVED2 = 3,
};

struct qer_info {
    __u8 ul_gate_status;
    __u8 dl_gate_status;
    __u8 qfi;
    __u8 qfi_present;
    __u8 rqi;
    __u8 dscp;
    __u64 ul_maximum_bitrate;
    __u64 dl_maximum_bitrate;
    volatile __u64 ul_start;
    volatile __u64 dl_start;
};

/* QER ID -> QER */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct qer_info);
    __uint(max_entries, QER_MAP_SIZE);
} qer_map SEC(".maps");

static __always_inline enum xdp_action limit_rate_simple(struct xdp_md *ctx, __u64 *end, const __u64 rate) {
    static const __u64 NSEC_PER_SEC = 1000000000ULL;

    /* Currently 0 rate means that traffic rate is not limited */
    if (rate == 0)
        return XDP_PASS;
        
    __u64 now = bpf_ktime_get_ns();
    if (now > *end) {
        __u64 tx_time = (ctx->data_end - ctx->data) * 8 * NSEC_PER_SEC / rate;
        *end = now + tx_time;
        return XDP_PASS;
    }

    return XDP_DROP;
}

// Keep credit arithmetic separate from the bounded CAS retry loop. This
// prevents the verifier from multiplying every arithmetic branch per attempt.
__u64 qer_credit_finish(__u64 start, __u64 now, __u64 tx_time) {
    const __u64 window_size=5000000ULL;
    if (tx_time > window_size) {
        if (start > now || now > ~0ULL-tx_time) return 0;
        return now+tx_time;
    }
    __u64 floor=now>window_size?now-window_size:0;
    __u64 base=start<floor?floor:start;
    if (base>now || tx_time>now-base) return 0;
    return base+tx_time;
}

enum xdp_action limit_rate_sliding_window(const __u64 packet_size, volatile __u64 *windows_start, const __u64 rate) {
    if (!windows_start || packet_size>65575) return XDP_DROP;
    if (!rate) return XDP_PASS;
    // TS 29.244 V20.1.0 clauses 5.4.4 and 8.2.8: charge IP octets
    // against a shared 5ms burst budget, with rates expressed in bits/s.
    __u64 tx_time=packet_tx_time_ns(packet_size,rate);
    __u64 now=bpf_ktime_get_ns();
    for (int i=0;i<4;i++) {
        __u64 start=*windows_start;
        __u64 finish=qer_credit_finish(start,now,tx_time);
        if (!finish) return XDP_DROP;
        if (__sync_val_compare_and_swap(windows_start,start,finish)==start) return XDP_PASS;
    }
    return XDP_DROP;
}
