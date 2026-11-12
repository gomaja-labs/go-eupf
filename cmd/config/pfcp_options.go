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
	if c.PfcpRequestTimeout > 3600 || c.PfcpRequestRetries > 100 || c.HeartbeatTimeout > 3600 || c.HeartbeatRetries > 100 || c.HeartbeatInterval > 3600 || c.HeartbeatFailureGrace > 86400 || c.PfcpResponseRetention > 86400 || c.PfcpMaxTransactions > 65536 || c.PfcpMaxAssociations > 65536 {
		return fmt.Errorf("PFCP transport option exceeds its supported bound")
	}
	timeout := c.PfcpRequestTimeout
	if timeout == 0 {
		timeout = 5
	}
	retention := c.PfcpResponseRetention
	if retention == 0 {
		retention = 60
	}
	if uint64(retention) < uint64(timeout)*(uint64(c.PfcpRequestRetries)+1) || uint64(retention) < uint64(c.HeartbeatTimeout)*(uint64(c.HeartbeatRetries)+1) {
		return fmt.Errorf("PFCP response retention must cover the configured request retry window")
	}
	return nil
}
