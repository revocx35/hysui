package vpn

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/apernet/hysteria/core/v2/server"

	"github.com/revocx35/hysui/internal/store"
)

// NewServer creates the Hysteria server listening on UDP addr.
func NewServer(listen string, m *Manager, certs CertSource, masq http.Handler) (server.Server, error) {
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", listen, err)
	}
	return NewServerConn(pc, m, certs, masq)
}

// NewServerConn creates the Hysteria server on an existing UDP socket.
func NewServerConn(pc net.PacketConn, m *Manager, certs CertSource, masq http.Handler) (server.Server, error) {
	s, err := server.NewServer(&server.Config{
		TLSConfig:     server.TLSConfig{GetCertificate: certs.GetCertificate},
		Conn:          pc,
		Outbound:      NewOutbound(m),
		Authenticator: m,
		EventLogger:   m,
		TrafficLogger: m,
		MasqHandler:   masq,
	})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return s, nil
}

// Masquerade returns the handler that answers unauthenticated HTTP/3 requests, so the
// server looks like an ordinary website to probes. An empty target serves a 404.
func Masquerade(target string) (http.Handler, error) {
	if target == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "404 page not found", http.StatusNotFound)
		}), nil
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid masquerade URL %q", target)
	}
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u)
			r.Out.Host = u.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusBadGateway)
		},
	}, nil
}

// LinkOptions describe how clients reach the server.
type LinkOptions struct {
	Host string // public domain
	Port int    // public UDP port
	Pin  string // certificate pin for self-signed certificates
}

// ShareLink returns the hysteria2:// URI for u.
func ShareLink(o LinkOptions, u store.User) string {
	q := url.Values{}
	q.Set("sni", o.Host)
	if o.Pin != "" {
		q.Set("insecure", "1")
		q.Set("pinSHA256", o.Pin)
	}
	return (&url.URL{
		Scheme:   "hysteria2",
		User:     url.UserPassword(u.Name, u.Password),
		Host:     net.JoinHostPort(o.Host, strconv.Itoa(o.Port)),
		Path:     "/",
		RawQuery: q.Encode(),
		Fragment: u.Name,
	}).String()
}
