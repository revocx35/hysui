// Package vpn runs a Hysteria 2 server (using Hysteria's own core library) with
// per-user speed limits, data quotas and home-network access.
//
// Hysteria's core has no per-user policies, so this package plugs into its hooks:
//   - Authenticator: checks "user:password" against the store.
//   - TrafficLogger: LogTraffic is called synchronously for every chunk a user's
//     streams relay, before the chunk is written on. Waiting on a per-user token
//     bucket there throttles that user. Returning false disconnects them (quota,
//     disabled, kicked).
//   - Outbound: dials destinations and enforces home-network access. Core does not
//     tell the outbound which user is asking, but it calls EventLogger.TCPRequest /
//     UDPRequest with the user name on the same goroutine immediately before
//     Outbound.TCP / Outbound.UDP. The manager remembers the user per goroutine in
//     between. If that pairing ever breaks (for example after a core upgrade), the
//     outbound finds no user and fails closed: no home-network access.
package vpn

import (
	"crypto/subtle"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"golang.org/x/time/rate"

	"github.com/revocx35/hysui/internal/netpolicy"
	"github.com/revocx35/hysui/internal/store"
)

// kickWindow is how long a kicked user's traffic is refused. Every connection that
// moves data in this window is dropped; clients reconnect on their own afterwards.
const kickWindow = 3 * time.Second

// minBurst must be at least the largest chunk core hands to LogTraffic (32 KiB TCP
// copy buffer, or one UDP datagram).
const minBurst = 64 << 10

// Manager holds runtime state for all users and implements Hysteria's
// Authenticator, TrafficLogger and EventLogger interfaces.
type Manager struct {
	store  *store.Store
	policy *netpolicy.Policy
	log    *slog.Logger
	now    func() time.Time

	syncMu sync.Mutex
	users  atomic.Pointer[map[string]*userState] // copy-on-write; read on every relayed chunk

	bindings       sync.Map // goroutine id -> user name, see package doc
	warnedNoBinder atomic.Bool
}

type userState struct {
	name string

	enabled    atomic.Bool
	homeAccess atomic.Bool
	removed    atomic.Bool
	quota      atomic.Int64
	kickUntil  atomic.Int64 // unix nanos

	tx, rx atomic.Int64 // lifetime totals: client upload / download
	online atomic.Int32 // open connections

	up, down         atomic.Pointer[rate.Limiter]
	upMbps, downMbps float64 // guarded by Manager.syncMu

	lastTx, lastRx   int64 // only touched by Sync (before publishing) and the sampler
	speedTx, speedRx atomic.Int64
}

// NewManager creates a manager and loads users from the store.
func NewManager(s *store.Store, p *netpolicy.Policy, log *slog.Logger) *Manager {
	m := &Manager{store: s, policy: p, log: log, now: time.Now}
	empty := map[string]*userState{}
	m.users.Store(&empty)
	m.Sync()
	return m
}

func (m *Manager) get(name string) *userState {
	return (*m.users.Load())[name]
}

// Sync reloads user settings from the store. Call it after every store change.
// Speed-limit and access changes apply to live connections immediately.
func (m *Manager) Sync() {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	old := *m.users.Load()
	next := make(map[string]*userState, len(old))
	for _, u := range m.store.Users() {
		st := old[u.Name]
		if st == nil {
			st = &userState{name: u.Name}
			st.tx.Store(u.UsedTx)
			st.rx.Store(u.UsedRx)
			st.lastTx, st.lastRx = u.UsedTx, u.UsedRx
		}
		st.enabled.Store(u.Enabled)
		st.homeAccess.Store(u.HomeAccess)
		st.quota.Store(u.QuotaBytes)
		if st.downMbps != u.DownMbps || (u.DownMbps > 0 && st.down.Load() == nil) {
			st.down.Store(newLimiter(u.DownMbps))
			st.downMbps = u.DownMbps
		}
		if st.upMbps != u.UpMbps || (u.UpMbps > 0 && st.up.Load() == nil) {
			st.up.Store(newLimiter(u.UpMbps))
			st.upMbps = u.UpMbps
		}
		next[u.Name] = st
	}
	for name, st := range old {
		if _, ok := next[name]; !ok {
			st.removed.Store(true)
		}
	}
	m.users.Store(&next)
}

func newLimiter(mbps float64) *rate.Limiter {
	if mbps <= 0 {
		return nil
	}
	bytesPerSec := mbps * 125_000
	burst := int(bytesPerSec / 5) // ~200 ms worth
	if burst < minBurst {
		burst = minBurst
	}
	return rate.NewLimiter(rate.Limit(bytesPerSec), burst)
}

// wait blocks until n bytes may pass the limiter.
func wait(l *rate.Limiter, n uint64) {
	for n > 0 {
		chunk := min(n, uint64(l.Burst()))
		// Reserve instead of Wait: no context to cancel, and it never errors for n <= burst.
		if d := l.ReserveN(time.Now(), int(chunk)).Delay(); d > 0 {
			time.Sleep(d)
		}
		n -= chunk
	}
}

// active reports whether the user exists and is enabled (ignores kicks).
func (st *userState) active() bool {
	return st.enabled.Load() && !st.removed.Load()
}

func (st *userState) allowedAt(now time.Time) bool {
	return st.active() && now.UnixNano() >= st.kickUntil.Load() && !st.overQuota()
}

func (st *userState) overQuota() bool {
	q := st.quota.Load()
	return q > 0 && st.tx.Load()+st.rx.Load() >= q
}

// mayReach reports whether the user may send traffic to a destination of class c.
// st may be nil (unknown user), which only allows the internet.
func (st *userState) mayReach(c netpolicy.Class) bool {
	switch c {
	case netpolicy.Internet:
		return true
	case netpolicy.Home:
		return st != nil && st.homeAccess.Load()
	default:
		return false
	}
}

// ---- server.Authenticator ----

// Authenticate accepts "name:password".
func (m *Manager) Authenticate(addr net.Addr, auth string, _ uint64) (bool, string) {
	name, pass, ok := strings.Cut(auth, ":")
	if !ok {
		return false, ""
	}
	u, found := m.store.User(name)
	want := u.Password
	if !found {
		want = "\x00 no such user \x00" // still do the comparison to keep timing uniform
	}
	if subtle.ConstantTimeCompare([]byte(pass), []byte(want)) != 1 || !found {
		return false, ""
	}
	st := m.get(name)
	if st == nil || !st.allowedAt(m.now()) {
		return false, ""
	}
	return true, name
}

// ---- server.TrafficLogger ----

// LogTraffic counts traffic, enforces quota/disable/kick and applies speed limits.
// tx is client upload, rx is client download.
func (m *Manager) LogTraffic(id string, tx, rx uint64) bool {
	st := m.get(id)
	if st == nil || !st.active() || m.now().UnixNano() < st.kickUntil.Load() {
		return false
	}
	t := st.tx.Add(int64(tx))
	r := st.rx.Add(int64(rx))
	if q := st.quota.Load(); q > 0 && t+r > q {
		return false
	}
	if tx > 0 {
		if l := st.up.Load(); l != nil {
			wait(l, tx)
		}
	}
	if rx > 0 {
		if l := st.down.Load(); l != nil {
			wait(l, rx)
		}
	}
	return true
}

func (m *Manager) LogOnlineState(id string, online bool) {
	st := m.get(id)
	if st == nil {
		return
	}
	if online {
		st.online.Add(1)
	} else if st.online.Add(-1) < 0 {
		st.online.Store(0)
	}
}

func (m *Manager) TraceStream(server.HyStream, *server.StreamStats) {}
func (m *Manager) UntraceStream(server.HyStream)                    {}

// ---- server.EventLogger ----

func (m *Manager) Connect(addr net.Addr, id string, _ uint64) {
	m.log.Info("client connected", "user", id, "addr", addr.String())
}

func (m *Manager) Disconnect(addr net.Addr, id string, err error) {
	m.log.Info("client disconnected", "user", id, "addr", addr.String(), "reason", errString(err))
}

func (m *Manager) TCPRequest(_ net.Addr, id, _ string) { m.bindings.Store(goid(), id) }

func (m *Manager) TCPError(addr net.Addr, id, reqAddr string, err error) {
	if err != nil && !isClosedErr(err) {
		m.log.Debug("tcp error", "user", id, "addr", addr.String(), "target", reqAddr, "err", err)
	}
}

func (m *Manager) UDPRequest(_ net.Addr, id string, _ uint32, _ string) { m.bindings.Store(goid(), id) }

func (m *Manager) UDPError(addr net.Addr, id string, _ uint32, err error) {
	if err != nil && !isClosedErr(err) {
		m.log.Debug("udp error", "user", id, "addr", addr.String(), "err", err)
	}
}

// takeBinding returns the user that core announced on this goroutine just before
// calling the outbound, or nil.
func (m *Manager) takeBinding() *userState {
	v, ok := m.bindings.LoadAndDelete(goid())
	if !ok {
		if !m.warnedNoBinder.Swap(true) {
			m.log.Warn("outbound call without a user binding; denying home-network access (Hysteria core changed?)")
		}
		return nil
	}
	return m.get(v.(string))
}

// ---- admin operations ----

// Kick drops the user's active connections. Clients reconnect automatically.
func (m *Manager) Kick(name string) {
	if st := m.get(name); st != nil {
		st.kickUntil.Store(m.now().Add(kickWindow).UnixNano())
	}
}

// ResetUsage zeroes a user's traffic counters.
func (m *Manager) ResetUsage(name string) error {
	st := m.get(name)
	if st == nil {
		return store.ErrNotFound
	}
	st.tx.Store(0)
	st.rx.Store(0)
	return m.store.SetUsage(map[string]store.Usage{name: {}})
}

// Stats is a user's live state.
type Stats struct {
	Online    int   `json:"online"`
	Tx        int64 `json:"tx"`
	Rx        int64 `json:"rx"`
	SpeedTx   int64 `json:"speedTx"` // bytes/s
	SpeedRx   int64 `json:"speedRx"` // bytes/s
	OverQuota bool  `json:"overQuota"`
}

// Stats returns live state for all users.
func (m *Manager) Stats() map[string]Stats {
	out := map[string]Stats{}
	for name, st := range *m.users.Load() {
		out[name] = Stats{
			Online:    int(st.online.Load()),
			Tx:        st.tx.Load(),
			Rx:        st.rx.Load(),
			SpeedTx:   st.speedTx.Load(),
			SpeedRx:   st.speedRx.Load(),
			OverQuota: st.overQuota(),
		}
	}
	return out
}

// Sample updates live speeds; call it periodically with the elapsed time.
func (m *Manager) Sample(elapsed time.Duration) {
	secs := elapsed.Seconds()
	if secs <= 0 {
		return
	}
	for _, st := range *m.users.Load() {
		tx, rx := st.tx.Load(), st.rx.Load()
		st.speedTx.Store(max(0, int64(float64(tx-st.lastTx)/secs)))
		st.speedRx.Store(max(0, int64(float64(rx-st.lastRx)/secs)))
		st.lastTx, st.lastRx = tx, rx
	}
}

// Flush writes traffic totals to the store.
func (m *Manager) Flush() error {
	usage := map[string]store.Usage{}
	for name, st := range *m.users.Load() {
		usage[name] = store.Usage{Tx: st.tx.Load(), Rx: st.rx.Load()}
	}
	return m.store.SetUsage(usage)
}

// Run samples speeds every 2s and persists usage every 30s until stop is closed.
func (m *Manager) Run(stop <-chan struct{}) {
	sample := time.NewTicker(2 * time.Second)
	flush := time.NewTicker(30 * time.Second)
	defer sample.Stop()
	defer flush.Stop()
	last := time.Now()
	for {
		select {
		case <-stop:
			if err := m.Flush(); err != nil {
				m.log.Error("saving usage", "err", err)
			}
			return
		case now := <-sample.C:
			m.Sample(now.Sub(last))
			last = now
		case <-flush.C:
			if err := m.Flush(); err != nil {
				m.log.Error("saving usage", "err", err)
			}
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
