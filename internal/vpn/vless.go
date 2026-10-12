package vpn

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/revocx35/hysui/internal/store"
)

// VLESS flow that hides the TLS-in-TLS pattern of proxied HTTPS. Needs a real TLS
// connection underneath (Reality), so plain-TCP tests use no flow.
const flowVision = "xtls-rprx-vision"

// vlessNamespace derives each user's VLESS UUID from their name and password, so
// changing the password also changes the UUID and old links stop working.
var vlessNamespace = uuid.NewV5(uuid.Nil, "hysui vless")

// VLESSUUID returns the VLESS user ID for u.
func VLESSUUID(u store.User) string {
	return uuid.NewV5(vlessNamespace, u.Name+":"+u.Password).String()
}

// vlessHandler serves VLESS requests on already-authenticated transport connections
// (Reality in production) and applies the same per-user policies as Hysteria.
type vlessHandler struct {
	m    *Manager
	out  *Outbound
	log  *slog.Logger
	flow string

	mu      sync.Mutex
	gen     uint64
	service atomic.Pointer[vless.Service[string]]
}

func newVLESSHandler(m *Manager, log *slog.Logger, flow string) *vlessHandler {
	return &vlessHandler{m: m, out: NewOutbound(m), log: log, flow: flow}
}

// currentService returns a VLESS service for the current user list. The service's
// user table isn't safe to update while connections read it, so a new one is built
// whenever the users change.
func (h *vlessHandler) currentService() *vless.Service[string] {
	gen := h.m.gen.Load()
	h.mu.Lock()
	defer h.mu.Unlock()
	if s := h.service.Load(); s != nil && h.gen == gen {
		return s
	}
	users := h.m.store.Users()
	names, ids, flows := make([]string, len(users)), make([]string, len(users)), make([]string, len(users))
	for i, u := range users {
		names[i], ids[i], flows[i] = u.Name, VLESSUUID(u), h.flow
	}
	s := vless.NewService[string](logger.NOP(), h) // Vision logs through it unconditionally; nil crashes
	s.UpdateUsers(names, ids, flows)
	h.service.Store(s)
	h.gen = gen
	return s
}

// serve handles one VLESS connection. It returns when the connection is done.
func (h *vlessHandler) serve(conn net.Conn) {
	defer h.recover(conn)
	source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
	done := make(chan struct{})
	var once sync.Once
	onClose := func(error) { once.Do(func() { close(done) }) }
	if err := h.currentService().NewConnection(context.Background(), conn, source, onClose); err != nil {
		h.log.Debug("vless request refused", "addr", source.String(), "err", err)
		_ = conn.Close()
		return
	}
	<-done
}

// user returns the authenticated user for ctx if they may connect now.
func (h *vlessHandler) user(ctx context.Context) (*userState, string, bool) {
	name, _ := auth.UserFromContext[string](ctx)
	st := h.m.get(name)
	return st, name, st != nil && st.allowedAt(h.m.now())
}

// NewConnectionEx relays a TCP request.
func (h *vlessHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	onClose = orNoop(onClose)
	st, name, ok := h.user(ctx)
	if !ok {
		_ = conn.Close()
		onClose(errDenied)
		return
	}
	st.vlessOpen(source.Addr)
	defer st.vlessClose(source.Addr)
	remote, err := h.out.dialTCP(st, destination.String())
	if err != nil {
		h.log.Debug("vless tcp error", "user", name, "target", destination.String(), "err", err)
		_ = conn.Close()
		onClose(err)
		return
	}
	onClose(h.relay(name, conn, remote))
}

// relay copies both ways, counting traffic and applying the user's limits on every
// chunk (LogTraffic waits on the speed limiter and refuses over-quota, disabled or
// kicked users).
func (h *vlessHandler) relay(name string, client, remote net.Conn) error {
	up := make(chan error, 1)
	go func() {
		err := errCrashed
		defer func() { up <- err }() // runs last, after a recovered panic too
		defer h.recover(client, remote)
		err = copyCounted(remote, client, func(n int) bool { return h.m.LogTraffic(name, uint64(n), 0) })
		if err == nil { // client finished sending; let the destination see EOF
			if cw, ok := remote.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		} else {
			_ = remote.Close()
			_ = client.Close()
		}
	}()
	err := copyCounted(client, remote, func(n int) bool { return h.m.LogTraffic(name, 0, uint64(n)) })
	_ = remote.Close()
	_ = client.Close()
	if upErr := <-up; err == nil {
		err = upErr
	}
	return err
}

// recover keeps a panic in one VLESS connection (Vision reaches into TLS internals)
// from taking down the whole server, Hysteria included.
func (h *vlessHandler) recover(conns ...io.Closer) {
	if r := recover(); r != nil {
		h.log.Error("vless connection crashed", "panic", r, "stack", string(debug.Stack()))
		for _, c := range conns {
			_ = c.Close()
		}
	}
}

var (
	errLimited = errors.New("refused by user policy")
	errCrashed = errors.New("connection crashed")
)

// orNoop guards against a nil close callback, which the mux path passes.
func orNoop(f N.CloseHandlerFunc) N.CloseHandlerFunc {
	if f == nil {
		return func(error) {}
	}
	return f
}

// copyCounted copies src to dst, asking allow before forwarding each chunk.
// It returns nil when src ends normally.
func copyCounted(dst io.Writer, src io.Reader, allow func(int) bool) error {
	b := make([]byte, 32<<10) // within minBurst, so one chunk never exceeds the limiter's burst
	for {
		n, err := src.Read(b)
		if n > 0 {
			if !allow(n) {
				return errLimited
			}
			if _, werr := dst.Write(b[:n]); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// udpIdle closes a VLESS UDP session after this long without packets from the
// destination side.
const udpIdle = 2 * time.Minute

// NewPacketConnectionEx relays UDP (VLESS UDP or XUDP mux).
func (h *vlessHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	onClose = orNoop(onClose)
	st, name, ok := h.user(ctx)
	if !ok {
		_ = conn.Close()
		onClose(errDenied)
		return
	}
	st.vlessOpen(source.Addr)
	defer st.vlessClose(source.Addr)
	remote, err := h.out.openUDP(st, destination.String())
	if err != nil {
		h.log.Debug("vless udp error", "user", name, "target", destination.String(), "err", err)
		_ = conn.Close()
		onClose(err)
		return
	}
	writer := bufio.NewNetPacketWriter(conn)
	go func() {
		defer conn.Close()
		defer remote.Close()
		defer h.recover()
		b := make([]byte, 64<<10)
		for {
			_ = remote.pc.SetReadDeadline(time.Now().Add(udpIdle))
			n, from, err := remote.ReadFrom(b)
			if err != nil || !h.m.LogTraffic(name, 0, uint64(n)) {
				return
			}
			ap, err := netip.ParseAddrPort(from)
			if err != nil {
				continue
			}
			if _, err := writer.WriteTo(b[:n], M.SocksaddrFromNetIP(ap)); err != nil {
				return
			}
		}
	}()
	b := make([]byte, 64<<10)
	for {
		// ReadPacket keeps a domain destination as a name, so the outbound resolves
		// and checks it like any other request.
		packet := buf.With(b)
		dest, err := conn.ReadPacket(packet)
		if err != nil || !h.m.LogTraffic(name, uint64(packet.Len()), 0) {
			break
		}
		if packet.Len() == 0 {
			continue // some clients send an empty packet just to flush the request header
		}
		_, _ = remote.WriteTo(packet.Bytes(), dest.String()) // blocked destinations are dropped
	}
	_ = conn.Close()
	_ = remote.Close()
	onClose(nil)
}
