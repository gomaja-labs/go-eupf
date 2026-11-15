package core

// Address references are owned by stateMu. Shared CP entity addresses remain
// ambiguous until all but one association drop their final reference.
// TS 29.244 V20.1.0 clauses 4.2.2, 4.3.2 and 5.8.1.
func (conn *PfcpConnection) addressReference(assoc *NodeAssociation, address string, delta int) {
	if address == "" || address == "<nil>" {
		return
	}
	if conn.addressIndex == nil {
		conn.addressIndex = make(map[string]map[*NodeAssociation]int)
	}
	refs := conn.addressIndex[address]
	if refs == nil {
		refs = make(map[*NodeAssociation]int)
		conn.addressIndex[address] = refs
	}
	refs[assoc] += delta
	if refs[assoc] <= 0 {
		delete(refs, assoc)
	}
	if len(refs) == 0 {
		delete(conn.addressIndex, address)
	}
}
func (conn *PfcpConnection) indexSession(assoc *NodeAssociation, session *Session, delta int) {
	conn.watchSessionActivity(assoc, session, delta)
	conn.addressReference(assoc, session.CPFSEIDIPv4.String(), delta)
	conn.addressReference(assoc, session.CPFSEIDIPv6.String(), delta)
}
func (conn *PfcpConnection) indexAssociation(assoc *NodeAssociation, delta int) {
	conn.addressReference(assoc, assoc.Addr, delta)
	conn.addressReference(assoc, assoc.setupSource, delta)
	for _, session := range assoc.Sessions {
		conn.indexSession(assoc, session, delta)
	}
}
func (conn *PfcpConnection) forgetSession(assoc *NodeAssociation, seid uint64) {
	if assoc.retired && assoc.Sessions[seid] != nil {
		PfcpCleanupPending.Dec()
	}
	if session := assoc.Sessions[seid]; session != nil && !assoc.retired {
		conn.indexSession(assoc, session, -1)
	}
	delete(conn.activitySessions, seid)
	delete(conn.activityDirty, seid)
	delete(assoc.Sessions, seid)
	delete(assoc.sessionEntities, seid)
	delete(assoc.cleanupFailures, seid)
}
