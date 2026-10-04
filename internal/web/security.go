package web

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ---- client address behind proxies ----

func contains(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func peerAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// clientIP returns the real client address. X-Forwarded-For is only honoured when the
// direct peer is a trusted proxy, and then the right-most untrusted entry wins:
// proxies such as Nginx Proxy Manager append to (not replace) a client-sent header,
// so entries further left are attacker-controlled.
func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := peerAddr(r)
	if !contains(trusted, peer) {
		return peer
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	addr := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return addr
		}
		addr = a.Unmap()
		if !contains(trusted, addr) {
			return addr
		}
	}
	return addr
}

// isHTTPS reports whether the browser reached us over HTTPS.
func isHTTPS(r *http.Request, trusted []netip.Prefix) bool {
	if r.TLS != nil {
		return true
	}
	return contains(trusted, peerAddr(r)) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// ---- login throttling ----

type throttleRule struct {
	free    int           // failures allowed before delays start
	base    time.Duration // first delay
	max     time.Duration // longest delay
	forgive time.Duration // failures are forgotten after this long without one
}

var (
	ipRule      = throttleRule{free: 5, base: 30 * time.Second, max: 15 * time.Minute, forgive: 30 * time.Minute}
	accountRule = throttleRule{free: 20, base: 10 * time.Second, max: 5 * time.Minute, forgive: 30 * time.Minute}
)

type throttleEntry struct {
	failures int
	last     time.Time
	until    time.Time
}

// Throttle slows down repeated failed logins per key (client IP, account name).
// The per-account rule is looser so a stranger cannot lock the owner out for long.
type Throttle struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*throttleEntry
}

func NewThrottle(now func() time.Time) *Throttle {
	return &Throttle{now: now, entries: map[string]*throttleEntry{}}
}

func (t *Throttle) entry(key string, rule throttleRule, now time.Time) *throttleEntry {
	e := t.entries[key]
	if e != nil && now.Sub(e.last) > rule.forgive {
		delete(t.entries, key)
		e = nil
	}
	return e
}

// Wait returns how long the caller must wait before trying again (0 = go ahead).
func (t *Throttle) Wait(ip, account string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var wait time.Duration
	for _, k := range []struct {
		key  string
		rule throttleRule
	}{{"ip:" + ip, ipRule}, {"acct:" + account, accountRule}} {
		if e := t.entry(k.key, k.rule, now); e != nil && e.until.After(now) {
			wait = max(wait, e.until.Sub(now))
		}
	}
	return wait
}

// Fail records a failed login.
func (t *Throttle) Fail(ip, account string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if len(t.entries) > 10000 { // bound memory under a flood of distinct IPs
		for k, e := range t.entries {
			if now.Sub(e.last) > ipRule.forgive {
				delete(t.entries, k)
			}
		}
	}
	for _, k := range []struct {
		key  string
		rule throttleRule
	}{{"ip:" + ip, ipRule}, {"acct:" + account, accountRule}} {
		e := t.entry(k.key, k.rule, now)
		if e == nil {
			e = &throttleEntry{}
			t.entries[k.key] = e
		}
		e.failures++
		e.last = now
		if over := e.failures - k.rule.free; over > 0 {
			d := k.rule.base << min(over-1, 20)
			e.until = now.Add(min(d, k.rule.max))
		}
	}
}

// Succeed clears the client's IP record (not the account's: a successful login from
// one place should not hide an ongoing attack from another).
func (t *Throttle) Succeed(ip string) {
	t.mu.Lock()
	delete(t.entries, "ip:"+ip)
	t.mu.Unlock()
}

// ---- sessions ----

const sessionTTL = 7 * 24 * time.Hour

type Sessions struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]time.Time // token -> expiry
}

func NewSessions(now func() time.Time) *Sessions {
	return &Sessions{now: now, m: map[string]time.Time{}}
}

func (s *Sessions) New() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, exp := range s.m {
		if now.After(exp) {
			delete(s.m, k)
		}
	}
	s.m[tok] = now.Add(sessionTTL)
	return tok
}

func (s *Sessions) Valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[tok]
	if ok && s.now().After(exp) {
		delete(s.m, tok)
		return false
	}
	return ok
}

func (s *Sessions) Delete(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// DeleteAll logs out every session.
func (s *Sessions) DeleteAll() {
	s.mu.Lock()
	clear(s.m)
	s.mu.Unlock()
}

// ---- CSRF ----

// sameOrigin rejects cross-site state-changing requests. The custom header cannot be
// sent cross-origin without a CORS preflight (which we never approve), and the
// session cookie is SameSite=Strict on top of that.
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("X-Hysui") != "1" {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return true
}
