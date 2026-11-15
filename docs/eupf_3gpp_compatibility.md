# eUPF 3GPP compatibility

The current implementation uses 3GPP TS 29.244 V20.1.0 for PFCP and
TS 29.281 V19.2.0 for GTP-U. Support is limited to the documented procedures
and rule fields; this is not a claim of complete conformance to either release.

The maintained capability descriptions are:

- [Rule capabilities](rule-capabilities.md): supported and rejected PFCP IEs,
  feature advertisement, rule transactions, and their specification clauses.
- [PFCP transport](pfcp-transport.md): association, reliable delivery, recovery,
  usage report outcomes, and resource limits.
- [Data plane](dataplane.md): GTP-U packet processing, forwarding, QoS, usage,
  and control-message behavior.

Ordinary N3/N9/EPC End Markers are generated on a per-FAR SNDEM request when
the downstream F-TEID changes. Transmission follows rule publication and the
data-plane grace period, using the old tunnel's destination, port, and TEID.
The source is the local N3/N9 address currently programmed for G-PDUs, including
REST changes; advertised F-TEID, S1-U/S5S8 and PA addresses do not select it
(TS 29.281 V19.2.0 clause 4.4.3.6).
EMPU is advertised. Labeled N3/N9 data-forwarding tunnels use the old PDR
container-deletion instruction or a mapped QER QFI for SNDEM. Received markers
select the E-RAB by QFI when it is present and apply the same insertion/deletion
as G-PDUs. A container-less ordinary End Marker follows the first PDR matching
the ingress interface, regardless of QFI lists; a present unmatched QFI is dropped.
One frame leaves per received marker (TS 29.281 V19.2.0 clauses 5.2.2.7 and
7.3.2.1; TS 29.244 V20.1.0 clause 5.17.3).
N19 and N19mb do not emit or relay End Markers
(TS 29.244 V20.1.0 clause 5.3.2; TS 29.281 V19.2.0 clause 7.3.2).

BUFF, NOCP, BAR, and the buffering capability bits remain unsupported.
UP-initiated session release with final USAR/UISR, TEBUR, and PSDBU is not
implemented; EPFAR is not advertised. The management session-release helper
does not provide the clause 5.18.2 procedure.

Unknown-tunnel Error Indications are suppressed during `restoration_period`
after startup, using the same period as automatic UE IPv4 restoration
(TS 23.527 V20.0.0 clause 4.3.2; TS 23.007 V19.2.0 clauses 16.1A.4 and
17.1b.1). See the [configuration reference](Configuration.md) for its bounds.

PDU Session Container insertion on relayed G-PDUs and End Markers requires the
FAR's 3GPP Interface Type to be N3 or N9 for data forwarding (TS 29.244 V20.1.0
clause 5.17.3). The UPF cannot otherwise identify an EPS-to-5GS forwarding tunnel.
Ordinary N9 and N4-u relays preserve received extension headers; their QER QFI
alone does not request insertion of a downlink container.
