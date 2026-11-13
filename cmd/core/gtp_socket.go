package core

import (
	"errors"
	"syscall"
)

// GTP diagnostic/control senders share UDP 2152. Connected Echo sockets retain
// more specific receive demultiplexing than unconnected End Marker senders.
func reuseGTPSourcePort(_, _ string, raw syscall.RawConn) error {
	var optionErr error
	err := raw.Control(func(fd uintptr) {
		optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	return errors.Join(err, optionErr)
}
