// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "xdp/utils/trace.h"
#include "xdp/utils/packet_context.h"
#include "xdp/utils/types.h"

struct ip_subnet {
    __u8 type; // 0: any, 1: ip4, 2: ip6
    // If type != any, ip field has meaningful value.
    // If IPv4 -> lower 32 bits. If IPv6 -> all 128 bits.
    __u128 ip;
    // If type != any, mask field has meaningful value.
    // If IPv4 mask -> lower 32 bits. If IPv6 mask -> all 128 bits.
    // Should always be applied to matching ip (except type == any).
    __u128 mask;
};

struct port_range {
    __u16 lower_bound; // If not specified in SDF: 0
    __u16 upper_bound; // If not specified in SDF: 65535
};

struct sdf_filter {
    __u8 protocol; // Required by SDF. 0: icmp, 1: ip, 2: tcp, 3: udp
    struct ip_subnet src_addr;
    struct port_range src_port;
    struct ip_subnet dst_addr;
    struct port_range dst_port;
};


static __always_inline __u8 get_sdf_protocol(__u8 ip_protocol) {
    switch(ip_protocol)
    {
        case IPPROTO_ICMP: return 0;
        case IPPROTO_ICMPV6: return 4;
        case IPPROTO_TCP: return 2;
        case IPPROTO_UDP: return 3;
        default: return 1;
    }
}

#define MAX_CPUS 4096
#define SAMPLE_SIZE 1024ul

struct tuple5 {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
} __attribute__((packed));

struct tuple5_ip6 {
    __u128 src_ip;
    __u128 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
} __attribute__((packed));

struct sdf_notify_ip4 {
	__u16 cookie;
    __u64 session_id;
    __u32 pdr_id;
	struct tuple5 tuple5;
} __attribute__((packed));

struct sdf_notify_ip6 {
	__u16 cookie;
    __u64 session_id;
    __u32 pdr_id;
	struct tuple5_ip6 tuple5;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, __u32);
	__uint(max_entries, MAX_CPUS);
} sdf_notify_map SEC(".maps");
