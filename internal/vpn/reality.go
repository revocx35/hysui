//go:build with_utls

package vpn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	utls "github.com/metacubex/utls"
)

// RealityServer accepts VLESS over Reality: to anyone without the server's key it
// looks like (and is proxied to) the real website at Dest.
type RealityServer struct {
	ln net.Listener
	h  *vlessHandler
	c  *utls.RealityConfig
}

// NewRealityServer listens on TCP o.Listen.
func NewRealityServer(o RealityOptions, m *Manager, log *slog.Logger) (*RealityServer, error) {
	if len(o.PrivateKey) != 32 {
		return nil, errors.New("reality: private key must be 32 bytes")
	}
	names := map[string]bool{}
	for _, n := range o.ServerNames {
		names[n] = true
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	c := &utls.RealityConfig{
		DialContext: dialer.DialContext,
		Type:        "tcp",
		Dest:        o.Dest,
		ServerNames: names,
		PrivateKey:  o.PrivateKey,
		ShortIds:    map[[8]byte]bool{o.ShortID: true},
	}
	c.SessionTicketsDisabled = true
	ln, err := net.Listen("tcp", o.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen tcp %s: %w", o.Listen, err)
	}
	return &RealityServer{ln: ln, h: newVLESSHandler(m, log, flowVision), c: c}, nil
}

// Addr is the listening address.
func (r *RealityServer) Addr() net.Addr { return r.ln.Addr() }

// Serve accepts connections until Close.
func (r *RealityServer) Serve() error {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return err
		}
		go r.handle(c)
	}
}

func (r *RealityServer) handle(c net.Conn) {
	// The context only bounds dialing Dest; probes that get the real site keep it as
	// long as they like, like the site itself would.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	tlsConn, err := utls.RealityServer(ctx, c, r.c)
	cancel()
	if err != nil {
		// Not one of our clients (a probe or a browser): Reality has handed the
		// connection to the real website.
		r.h.log.Debug("reality: not a client", "addr", c.RemoteAddr().String(), "err", err)
		return
	}
	r.h.serve(tlsConn)
}

// Close stops accepting connections.
func (r *RealityServer) Close() error { return r.ln.Close() }
