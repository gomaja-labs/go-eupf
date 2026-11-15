package core

import (
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestAssociationReleaseSendDurationIsExactlyRepresentable(t *testing.T) {
	// The only duration IE currently encoded by the UPF is Graceful Release
	// Period. TS 29.244 V20.1.0 clause 8.2.78 requires whole two-second units.
	for _, seconds := range []uint32{0, 1, 2, 3, 4, 5, 59, 60} {
		for _, retries := range []uint32{0, 1, 3, 10} {
			conn := &PfcpConnection{requestTimeout: time.Duration(seconds) * time.Second, requestRetries: retries}
			period := conn.AssociationReleaseTimeout()
			if period < 2*time.Second || period > 8*time.Second || period%(2*time.Second) != 0 {
				t.Fatalf("T1=%d N1=%d period=%s", seconds, retries, period)
			}
			request := message.NewAssociationUpdateRequest(1, ie.NewNodeIDFQDN("cp.example"), ie.NewGracefulReleasePeriod(period))
			wire, err := request.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := message.ParseAssociationUpdateRequest(wire)
			if err != nil {
				t.Fatal(err)
			}
			value, err := decoded.GracefulReleasePeriod.GracefulReleasePeriod()
			if err != nil || value != period {
				t.Fatalf("encoded=%s requested=%s error=%v", value, period, err)
			}
		}
	}
}
