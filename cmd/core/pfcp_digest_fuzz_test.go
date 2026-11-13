package core

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func FuzzReplayRequestDigest(f *testing.F) {
	for _, msg := range []message.Message{
		message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("digest.example"), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0))),
		message.NewSessionModificationRequest(11, 2, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(2))),
		message.NewSessionDeletionRequest(11, 3, ie.New(4000, []byte{1, 2, 3})),
	} {
		wire := make([]byte, msg.MarshalLen())
		if err := msg.MarshalTo(wire); err != nil {
			f.Fatal(err)
		}
		f.Add(wire)
		spare := append([]byte(nil), wire...)
		spare[0] |= 0x18
		f.Add(spare)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		messages, err := message.ParseDatagram(wire)
		if err != nil {
			return
		}
		for _, msg := range messages {
			if !msg.IsRequest() {
				continue
			}
			canonical := make([]byte, msg.MarshalLen())
			if err := msg.MarshalTo(canonical); err != nil {
				continue
			}
			got, err := requestDigest(msg, wire)
			if err != nil {
				t.Fatal(err)
			}
			if got != sha256.Sum256(canonical) {
				t.Fatal("received-frame digest differs from canonical request encoding")
			}
		}
	})
}
