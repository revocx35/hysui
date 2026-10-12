//go:build !with_utls

package vpn

import (
	"errors"
	"log/slog"
	"net"
)

// RealityServer is unavailable: VLESS Vision only works when hysui is built with
// -tags with_utls (the Dockerfile does this).
type RealityServer struct{}

func NewRealityServer(RealityOptions, *Manager, *slog.Logger) (*RealityServer, error) {
	return nil, errors.New("this build has no VLESS Reality support; build with -tags with_utls")
}

func (*RealityServer) Addr() net.Addr { return nil }
func (*RealityServer) Serve() error   { return nil }
func (*RealityServer) Close() error   { return nil }
