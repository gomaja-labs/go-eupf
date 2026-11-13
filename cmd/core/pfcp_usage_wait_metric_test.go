package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/prometheus/client_golang/prometheus"
)

func usageWaitSample(t *testing.T) (count uint64, sum float64) {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "upf_pfcp_final_usage_wait_seconds" {
			for _, metric := range family.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "message_type" && label.GetValue() == message.MessageTypeName(message.MsgTypeSessionDeletionRequest) {
						return metric.GetHistogram().GetSampleCount(), metric.GetHistogram().GetSampleSum()
					}
				}
			}
		}
	}
	return
}

func TestFinalUsageResponseRecordsItsGraceWait(t *testing.T) {
	conn := newProtocolConnection(t)
	plane := &delayedUsagePlane{}
	conn.mapOperations = plane
	cp := identityPeer(t, "127.0.0.31", 0)
	identitySetup(t, conn, cp, "wait.example")
	s := NewSession(11, 77, "", "", false)
	s.CPFSEIDIPv4 = net.ParseIP("127.0.0.31")
	s.NewUrr(9, 1, ebpf.UrrInfo{})
	conn.associationByID("wait.example").Sessions[11] = s
	count, before := usageWaitSample(t)
	conn.Handle(protocolWire(t, message.NewSessionDeletionRequest(11, 2)), cp.LocalAddr().(*net.UDPAddr))
	time.Sleep(20 * time.Millisecond)
	plane.transaction.finish(t)
	_ = identityRead(t, cp)
	afterCount, after := usageWaitSample(t)
	if afterCount-count != 1 || after-before < 0.020 {
		t.Fatalf("grace wait samples %d duration %g", afterCount-count, after-before)
	}
}
