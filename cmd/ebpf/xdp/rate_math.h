// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors
#pragma once

#include <linux/types.h>

// TS 29.244 V20.1.0 clause 8.2.8: rate is bits per second. The caller
// bounds bytes to the maximum IP packet size (65575), so the product fits
// in 64 bits. Ceiling division avoids both truncation and rate+numerator
// overflow, including a rate of UINT64_MAX. Zero means unlimited.
static __inline __u64 packet_tx_time_ns(__u64 bytes, __u64 rate) {
    if (!rate) return 0;
    __u64 numerator = bytes * 8000000000ULL;
    return numerator / rate + (numerator % rate != 0);
}
