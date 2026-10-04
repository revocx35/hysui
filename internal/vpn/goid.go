package vpn

import (
	"errors"
	"io"
	"net"
	"runtime"
)

// goid returns the current goroutine's id, parsed from the "goroutine N [" header
// of runtime.Stack. It is only used once per new TCP stream / UDP session, not per
// packet, so the cost (~1µs) does not matter.
func goid() uint64 {
	var buf [64]byte
	b := buf[:runtime.Stack(buf[:], false)]
	const prefix = "goroutine "
	if len(b) < len(prefix) {
		return 0
	}
	var id uint64
	for _, c := range b[len(prefix):] {
		if c < '0' || c > '9' {
			break
		}
		id = id*10 + uint64(c-'0')
	}
	return id
}

func isClosedErr(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}
