package vpn

import (
	"cmp"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/server"

	"github.com/revocx35/hysui/internal/netpolicy"
)

var (
	errBlocked = errors.New("destination not allowed for this user")
	errDenied  = errors.New("user not allowed")
	errRevoked = errors.New("access revoked")
)

// Outbound dials destinations on behalf of users and enforces home-network access.
type Outbound struct {
	m        *Manager
	resolver *net.Resolver
	dialer   net.Dialer
}

// NewOutbound returns an outbound for m.
func NewOutbound(m *Manager) *Outbound {
	return &Outbound{m: m, resolver: net.DefaultResolver, dialer: net.Dialer{Timeout: 8 * time.Second}}
}

var _ server.Outbound = (*Outbound)(nil)

// resolve returns the addresses for host, IPv4 first.
func (o *Outbound) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	ips, err := o.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for i := range ips {
		ips[i] = ips[i].Unmap()
	}
	slices.SortStableFunc(ips, func(a, b netip.Addr) int { return cmp.Compare(a.BitLen(), b.BitLen()) })
	return ips, nil
}

func splitPort(addr string) (string, uint16, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(p), nil
}

// TCP dials reqAddr for the user core announced on this goroutine.
func (o *Outbound) TCP(reqAddr string) (net.Conn, error) {
	st := o.m.takeBinding()
	if st != nil && !st.allowedAt(o.m.now()) {
		return nil, errDenied
	}
	host, port, err := splitPort(reqAddr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ips, err := o.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	lastErr := errBlocked
	for _, ip := range ips {
		class := o.m.policy.Classify(ip)
		if !st.mayReach(class) {
			continue
		}
		c, err := o.dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, port).String())
		if err != nil {
			lastErr = err
			continue
		}
		if st == nil {
			return c, nil // internet only, nothing to revoke
		}
		return &tcpConn{Conn: c, st: st, home: class == netpolicy.Home}, nil
	}
	return nil, lastErr
}

// tcpConn re-checks the user's access on every read and write, so disabling a user or
// revoking home-network access cuts existing connections too.
type tcpConn struct {
	net.Conn
	st   *userState
	home bool
}

func (c *tcpConn) check() error {
	if !c.st.active() || (c.home && !c.st.homeAccess.Load()) {
		_ = c.Conn.Close()
		return errRevoked
	}
	return nil
}

func (c *tcpConn) Read(b []byte) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *tcpConn) Write(b []byte) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// CheckUDP allows everything here; udpConn checks each packet's destination.
func (o *Outbound) CheckUDP(string) error { return nil }

// UDP opens a UDP session for the user core announced on this goroutine.
func (o *Outbound) UDP(reqAddr string) (server.UDPConn, error) {
	st := o.m.takeBinding()
	if st != nil && !st.allowedAt(o.m.now()) {
		return nil, errDenied
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	u := &udpConn{pc: pc, o: o, st: st, cache: map[string]udpCacheEntry{}}
	if _, err := u.destination(reqAddr); err != nil {
		_ = pc.Close()
		return nil, err
	}
	return u, nil
}

type udpCacheEntry struct {
	addrs   []netip.AddrPort
	expires time.Time
}

type udpConn struct {
	pc *net.UDPConn
	o  *Outbound
	st *userState // nil = unknown user, internet only

	mu    sync.Mutex
	cache map[string]udpCacheEntry
}

func (u *udpConn) allowed(a netip.Addr) bool {
	if u.st != nil && !u.st.active() {
		return false
	}
	return u.st.mayReach(u.o.m.policy.Classify(a))
}

// destination resolves addr (cached for a minute) and returns the first address the
// user may reach. Access is re-evaluated on every packet.
func (u *udpConn) destination(addr string) (netip.AddrPort, error) {
	u.mu.Lock()
	e, ok := u.cache[addr]
	u.mu.Unlock()
	if !ok || time.Now().After(e.expires) {
		host, port, err := splitPort(addr)
		if err != nil {
			return netip.AddrPort{}, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ips, err := u.o.resolve(ctx, host)
		cancel()
		if err != nil {
			return netip.AddrPort{}, err
		}
		e = udpCacheEntry{expires: time.Now().Add(time.Minute)}
		for _, ip := range ips {
			e.addrs = append(e.addrs, netip.AddrPortFrom(ip, port))
		}
		u.mu.Lock()
		if len(u.cache) >= 256 {
			clear(u.cache)
		}
		u.cache[addr] = e
		u.mu.Unlock()
	}
	for _, ap := range e.addrs {
		if u.allowed(ap.Addr()) {
			return ap, nil
		}
	}
	return netip.AddrPort{}, errBlocked
}

func (u *udpConn) WriteTo(b []byte, addr string) (int, error) {
	ap, err := u.destination(addr)
	if err != nil {
		return 0, err
	}
	return u.pc.WriteToUDPAddrPort(b, ap)
}

// ReadFrom drops packets from sources the user may not reach (e.g. unsolicited LAN traffic).
func (u *udpConn) ReadFrom(b []byte) (int, string, error) {
	for {
		n, ap, err := u.pc.ReadFromUDPAddrPort(b)
		if err != nil {
			return 0, "", err
		}
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if !u.allowed(ap.Addr()) {
			continue
		}
		return n, ap.String(), nil
	}
}

func (u *udpConn) Close() error { return u.pc.Close() }
