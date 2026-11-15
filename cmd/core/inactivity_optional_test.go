package core

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// TS 29.244 V20.1.0 table 7.5.2.1-1 and clause 7.6.8: the
// establishment timer is optional; its consistent IE Length is not 7.6.7.
func TestInactivityIncorrectOptionalEstablishmentTimerIsIgnored(t *testing.T) {
	for _, local := range []time.Duration{0, time.Second} {
		for _, payload := range [][]byte{{1}, {1, 2, 3}} {
			t.Run(fmt.Sprintf("length%d/local%s", len(payload), local), func(t *testing.T) {
				conn := sessionLimitConnection(t, 16, nil, nil)
				conn.inactivityReleaseTimeout = local
				plane := &activityPlane{MapOperationsMock: &MapOperationsMock{}}
				conn.mapOperations = plane
				peer := identityPeer(t, "127.0.0.25", 8805)
				identitySetup(t, conn, peer, "inactive.example")
				request := sessionLimitRequest("inactive.example", 2, 1)
				request.UserPlaneInactivityTimer = ie.New(ie.UserPlaneInactivityTimer, payload)
				conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
				response := identityRead(t, peer).(*message.SessionEstablishmentResponse)
				if cause := pipelineCause(t, response); cause != ie.CauseRequestAccepted {
					t.Fatalf("optional timer rejected valid establishment: cause=%d", cause)
				}
				fseid, err := response.UPFSEID.FSEID()
				if err != nil {
					t.Fatal(err)
				}
				session := conn.associationByID("inactive.example").Sessions[fseid.SEID]
				if session == nil || session.inactivityArmed || session.inactivityTimer != 0 || len(session.PDRs) != 1 {
					t.Fatal("invalid optional timer affected accepted rules")
				}
				if (session.activity != nil) != (local > 0) || plane.active != (local > 0) {
					t.Fatal("discarded timer changed local-policy activity ownership")
				}
			})
		}
	}
}

func TestInactivityIncorrectConditionalModificationTimerRejectsAtomically(t *testing.T) {
	conn, assoc, session, plane, peer := inactivityFixture(t, 10*time.Second, 0)
	original := session
	conn.Handle(protocolWire(t, message.NewSessionModificationRequest(session.LocalSEID, 3, ie.New(ie.UserPlaneInactivityTimer, []byte{1, 2, 3}))), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.SessionModificationResponse)
	if pipelineCause(t, response) != ie.CauseMandatoryIEIncorrect {
		t.Fatal("incorrect conditional timer accepted")
	}
	offending, err := response.OffendingIE.OffendingIE()
	if err != nil || offending != ie.UserPlaneInactivityTimer {
		t.Fatal("conditional rejection omitted offending timer")
	}
	if assoc.Sessions[session.LocalSEID] != original || !session.inactivityArmed || session.inactivityTimer != 10*time.Second || !plane.active || len(plane.released) != 0 {
		t.Fatal("rejected update changed live ownership")
	}
}

// Table 8.1.2-1 marks IE117 Extendable: unknown octets after the fixed
// four-octet timer must be ignored, not treated as an incorrect value.
func TestInactivityTimerIgnoresUnknownExtensionOctets(t *testing.T) {
	conn := sessionLimitConnection(t, 16, nil, nil)
	plane := &activityPlane{MapOperationsMock: &MapOperationsMock{}}
	conn.mapOperations = plane
	peer := identityPeer(t, "127.0.0.25", 8805)
	identitySetup(t, conn, peer, "inactive.example")
	request := sessionLimitRequest("inactive.example", 2, 1)
	request.UserPlaneInactivityTimer = ie.New(ie.UserPlaneInactivityTimer, []byte{0, 0, 0, 1, 255})
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	response := identityRead(t, peer).(*message.SessionEstablishmentResponse)
	if pipelineCause(t, response) != ie.CauseRequestAccepted {
		t.Fatal("timer extension rejected")
	}
	fseid, err := response.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}
	assoc := conn.associationByID("inactive.example")
	session := assoc.Sessions[fseid.SEID]
	if session == nil || session.inactivityTimer != time.Second || !session.inactivityArmed || !plane.active {
		t.Fatal("timer extension changed fixed value")
	}
	inactivityUpdate(t, conn, session, peer, 3, ie.New(ie.UserPlaneInactivityTimer, []byte{0, 0, 0, 2, 255}))
	if current := assoc.Sessions[session.LocalSEID]; current.inactivityTimer != 2*time.Second || !current.inactivityArmed {
		t.Fatal("updated extension changed fixed value")
	}
}
