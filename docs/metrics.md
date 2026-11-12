# eUPF metrics

## PFCP message metrics

This set of metrics describes how many requests of each type has been processed with outcome specified.

**Note:** `upf_pfcp_rx` and `upf_pfcp_rx_errors` have different implementation and counted at different points, we will drop one or another after evaluation, or implement a different counters altogether.

Metric Name         | Description                                                | Labels
------------------- | ---------------------------------------------------------- | ----------------------------
upf_pfcp_rx         | The total number of received PFCP messages                 | `message_name`
upf_pfcp_tx         | The total number of transmitted PFCP messages              | `message_name`
upf_pfcp_rx_errors  | The total number of received PFCP messages with cause code | `message_name`, `cause_code`
pfcp_upf_pfcp_rx_latency | PFCP processing duration in microseconds (summary)      | `message_type`

## XDP Action metrics

This set of metrics are used to count the number of packets with different outcomes, such as the total number of aborted, dropped, passed, transmitted, and redirected packets.

Metric Name      | Description
---------------- | ---------------------------------------
upf_xdp_aborted  | The total number of aborted packets
upf_xdp_drop     | The total number of dropped packets
upf_xdp_pass     | The total number of passed packets
upf_xdp_tx       | The total number of transmitted packets
upf_xdp_redirect | The total number of redirected packets

## Packet metrics

Various packet counters with `packet_type` label.

Metric Name                | Description
-------------------------- | ----------------------------------------------------------------------
upf_rx `arp`               | The total number of received ARP packets
upf_rx `icmp`              | The total number of received ICMP packets
upf_rx `icmp6`             | The total number of received ICMPv6 packets
upf_rx `ip4`               | The total number of received IPv4 packets
upf_rx `ip6`               | The total number of received IPv6 packets
upf_rx `tcp`               | The total number of received TCP packets
upf_rx `udp`               | The total number of received UDP packets
upf_rx `other`             | The total number of received other packets
upf_rx `gtp-echo`          | The total number of received GTP echo packets
upf_rx `gtp-pdu`           | The total number of received GTP PDU packets
upf_rx `gtp-other`         | The total number of received GTP other packets
upf_rx `gtp-unexp`         | The total number of received GTP error packets
upf_route `ip4-ok`         | The total number of IPv4 packets successfully routed
upf_route `ip4-error-drop` | The total number of IPv4 packets dropped due to routing errors
upf_route `ip4-error-pass` | The total number of IPv4 packets passed to stack due to routing errors
upf_route `ip6-ok`         | The total number of IPv6 packets successfully routed
upf_route `ip6-error-drop` | The total number of IPv6 packets dropped due to routing errors
upf_route `ip6-error-pass` | The total number of IPv6 packets passed to stack due to routing errors

## PFCP Session metrics

Metric Name                 | Description                                            | Labels
--------------------------- | ------------------------------------------------------ | ---------
upf_pfcp_sessions           | Number of currently established sessions               | -
upf_pfcp_associations_total | The total number of currently established associations | -

Packet and route counters add only the increase since the preceding scrape; concurrent scrapes share one snapshot. An observed counter decrease is treated as a reset. Association metrics expose aggregate counts only, so peer-controlled Node IDs do not create metric labels.

`upf_pfcp_retransmissions` counts retry attempts and `upf_pfcp_request_timeouts`
counts exhausted budgets, each with the finite `message_name` label.
`upf_pfcp_association_prunes` counts association removals after the unreachable
period, including any configured grace. These counters do not use peer labels.
