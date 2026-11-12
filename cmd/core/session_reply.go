package core

import (
	"slices"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func requestHasQFI(rules []*ie.IE) bool {
	for _, rule := range rules {
		field, _, err := qerQFI(rule)
		if err == nil && field != nil && !isNullIE(field) {
			return true
		}
	}
	return false
}

// bindSessionReplies selects the highest-precedence IPv6 downlink PDR for
// generated control traffic of this session. User-plane PDI matching remains
// independent; an RA's link-local/multicast destination is not a UE lookup key.
func (conn *PfcpConnection) bindSessionReplies(session *Session) error {
	var selected *SPDRInfo
	for _, pdr := range session.PDRs {
		if pdr.Teid != 0 || pdr.Ipv6 == nil || pdr.PdrInfo.FarId == 0 {
			continue
		}
		if selected == nil || pdr.PdrInfo.Precedence < selected.PdrInfo.Precedence || (pdr.PdrInfo.Precedence == selected.PdrInfo.Precedence && pdr.PdrID < selected.PdrID) {
			copy := pdr
			selected = &copy
		}
	}
	for id, pdr := range session.PDRs {
		changed := pdr.PdrInfo.NRFlag != session.Is5G
		pdr.PdrInfo.NRFlag = session.Is5G
		if pdr.Teid == 0 {
			if changed {
				if err := applyPDR(pdr, conn.mapOperations); err != nil {
					return &ruleFailure{ie.RuleIDTypePDR, id, err}
				}
				session.PDRs[id] = pdr
			}
			continue
		}
		far := uint32(0)
		var qers []uint32
		nr := false
		if selected != nil {
			far = selected.PdrInfo.FarId
			qers = slices.Clone(selected.PdrInfo.QerIDs)
			nr = session.Is5G
		}
		if !changed && pdr.PdrInfo.ReturnFarID == far && slices.Equal(pdr.PdrInfo.ReturnQerIDs, qers) && pdr.PdrInfo.ReturnNR == nr {
			continue
		}
		pdr.PdrInfo.ReturnFarID, pdr.PdrInfo.ReturnQerIDs, pdr.PdrInfo.ReturnNR = far, qers, nr
		if err := conn.mapOperations.PutPdrUplink(pdr.Teid, pdr.PdrInfo); err != nil {
			return &ruleFailure{ie.RuleIDTypePDR, id, err}
		}
		session.PDRs[id] = pdr
	}
	return nil
}
func sessionFailureResponse(request message.Message, remote uint64, err error) message.Message {
	switch request.(type) {
	case *message.SessionEstablishmentRequest:
		return message.NewSessionEstablishmentResponse(remote, request.Sequence(), ruleFailureIEs(err)...)
	default:
		return message.NewSessionModificationResponse(remote, request.Sequence(), ruleFailureIEs(err)...)
	}
}

var _ ebpf.ForwardingPlaneController = (*ebpf.BpfObjects)(nil)
