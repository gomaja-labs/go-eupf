package core

import "testing"

func TestUpdateHeartbeatTimeoutWithIdleAssociation(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.NodeAssociations["127.0.0.1"] = NewNodeAssociation("synthetic.example", "127.0.0.1")
	UpdateHeartbeatTimeout(map[string]*PfcpConnection{"n4": conn}, 2)
}
