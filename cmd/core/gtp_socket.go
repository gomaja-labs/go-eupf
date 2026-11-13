package core

import (
	"errors"
	"syscall"
)

// GTP control senders can share a local UDP port. Connected Echo sockets retain
// more specific receive demultiplexing than unconnected End Marker senders.
func reuseGTPSourcePort(_, _ string, raw syscall.RawConn) error {
	var optionErr error
	err := raw.Control(func(fd uintptr) {
		optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	return errors.Join(err, optionErr)
}
