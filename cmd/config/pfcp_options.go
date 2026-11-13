// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

package config

import (
	"fmt"
	"net/netip"
)

// PFCPPeerPrefixes validates the optional source-address admission policy.
// Addresses mean one host; CIDR prefixes admit that network. IPv4-mapped
// addresses are normalized to the IPv4 form used by the UDP receive path.
func (c *UpfConfig) PFCPPeerPrefixes() ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(c.PfcpPeerAllowList))
	for _, text := range c.PfcpPeerAllowList {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			addr, parseErr := netip.ParseAddr(text)
			if parseErr != nil {
				return nil, fmt.Errorf("PFCP peer %q: %w", text, parseErr)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, fmt.Errorf("PFCP mapped IPv4 prefix %q is too broad", text)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

// ValidatePFCP checks transport budgets independently of unrelated dataplane
// options. Zero selects the documented default for the new capacity/time fields.
func (c *UpfConfig) ValidatePFCP() error {
	if _, err := c.PFCPPeerPrefixes(); err != nil {
		return err
	}
	for key, bound := range map[string]struct{ value, max uint32 }{
		"pfcp_request_timeout": {c.PfcpRequestTimeout, 3600}, "pfcp_request_retries": {c.PfcpRequestRetries, 100},
		"heartbeat_timeout": {c.HeartbeatTimeout, 3600}, "heartbeat_retries": {c.HeartbeatRetries, 100},
		"heartbeat_interval": {c.HeartbeatInterval, 3600}, "heartbeat_failure_grace": {c.HeartbeatFailureGrace, 86400},
		"pfcp_response_retention": {c.PfcpResponseRetention, 86400}, "pfcp_max_replay_entries": {c.PfcpMaxReplayEntries, 1048576},
		"pfcp_max_originated_requests": {c.PfcpMaxOriginatedRequests, 65536},
		"pfcp_replay_memory_mib":       {c.PfcpReplayMemoryMiB, 1024},
		"pfcp_max_associations":        {c.PfcpMaxAssociations, 65536},
		"resource_reuse_delay":         {c.ResourceReuseDelay, 86400},
	} {
		if bound.value > bound.max {
			return fmt.Errorf("%s must not exceed %d", key, bound.max)
		}
	}

	if c.PfcpReplayMemoryMiB != 0 && c.PfcpReplayMemoryMiB < 16 {
		return fmt.Errorf("pfcp_replay_memory_mib must be between 16 and 1024")
	}
	timeout := c.PfcpRequestTimeout
	if timeout == 0 {
		timeout = 5
	}
	retention := c.PfcpResponseRetention
	if retention == 0 {
		retention = 60
	}
	if retention < 20 {
		return fmt.Errorf("pfcp_response_retention must be at least 20 seconds for the minimum replay window")
	}
	if uint64(retention) < uint64(timeout)*(uint64(c.PfcpRequestRetries)+1) || uint64(retention) < uint64(c.HeartbeatTimeout)*(uint64(c.HeartbeatRetries)+1) {
		return fmt.Errorf("pfcp_response_retention must cover pfcp_request_timeout and heartbeat_timeout retry windows")
	}
	return nil
}
