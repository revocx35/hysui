package web

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, v := range s {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}

func TestClientIP(t *testing.T) {
	npm := prefixes("192.168.1.20/32")
	req := func(remote string, xff ...string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	cases := []struct {
		name    string
		r       *http.Request
		trusted []netip.Prefix
		want    string
	}{
		{"direct, no trust", req("192.168.1.50:1234", "1.2.3.4"), nil, "192.168.1.50"},
		{"untrusted peer ignores XFF", req("192.168.1.50:1234", "1.2.3.4"), npm, "192.168.1.50"},
		{"trusted proxy", req("192.168.1.20:1234", "8.8.8.8"), npm, "8.8.8.8"},
		{"spoofed left entries ignored", req("192.168.1.20:1234", "6.6.6.6, 8.8.8.8"), npm, "8.8.8.8"},
		{"multiple headers", req("192.168.1.20:1234", "6.6.6.6", "8.8.8.8"), npm, "8.8.8.8"},
		{"chain of trusted proxies", req("10.0.0.1:1", "8.8.8.8, 192.168.1.20"), prefixes("10.0.0.0/8", "192.168.1.20/32"), "8.8.8.8"},
		{"garbage stops the walk", req("192.168.1.20:1234", "8.8.8.8, junk"), npm, "192.168.1.20"},
		{"ipv6 peer", req("[2001:db8::1]:443"), nil, "2001:db8::1"},
	}
	for _, c := range cases {
		if got := clientIP(c.r, c.trusted); got.String() != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestIsHTTPS(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.20:1"
	r.Header.Set("X-Forwarded-Proto", "https")
	if isHTTPS(r, nil) {
		t.Error("untrusted X-Forwarded-Proto honoured")
	}
	if !isHTTPS(r, prefixes("192.168.1.20/32")) {
		t.Error("trusted X-Forwarded-Proto ignored")
	}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

func TestThrottlePerIP(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	th := NewThrottle(clk.now)
	for i := range ipRule.free {
		if w := th.Wait("1.1.1.1", "admin"); w != 0 {
			t.Fatalf("attempt %d delayed by %v", i+1, w)
		}
		th.Fail("1.1.1.1", "admin")
	}
	th.Fail("1.1.1.1", "admin") // 6th failure
	if w := th.Wait("1.1.1.1", "admin"); w != 30*time.Second {
		t.Fatalf("after 6 failures wait = %v, want 30s", w)
	}
	if w := th.Wait("2.2.2.2", "admin"); w != 0 {
		t.Fatalf("other IP delayed by %v", w)
	}
	clk.add(31 * time.Second)
	th.Fail("1.1.1.1", "admin") // 7th: doubles
	if w := th.Wait("1.1.1.1", "admin"); w != time.Minute {
		t.Fatalf("after 7 failures wait = %v, want 1m", w)
	}
	for range 30 {
		th.Fail("1.1.1.1", "x")
	}
	if w := th.Wait("1.1.1.1", "x"); w != ipRule.max {
		t.Fatalf("delay not capped: %v", w)
	}
	th.Succeed("1.1.1.1")
	if w := th.Wait("1.1.1.1", "admin"); w != 0 {
		t.Fatalf("success did not clear IP: %v", w)
	}
}

func TestThrottlePerAccountAndForgiveness(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	th := NewThrottle(clk.now)
	// A distributed attack: one failure per IP still trips the account rule.
	for i := range accountRule.free + 1 {
		th.Fail(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}).String(), "admin")
	}
	if w := th.Wait("9.9.9.9", "admin"); w != accountRule.base {
		t.Fatalf("account wait = %v, want %v", w, accountRule.base)
	}
	if w := th.Wait("9.9.9.9", "other"); w != 0 {
		t.Fatalf("other account delayed: %v", w)
	}
	clk.add(accountRule.forgive + time.Second)
	if w := th.Wait("9.9.9.9", "admin"); w != 0 {
		t.Fatalf("not forgiven: %v", w)
	}
}

func TestSessions(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s := NewSessions(clk.now)
	a, b := s.New(), s.New()
	if a == b || len(a) < 40 || !s.Valid(a) || s.Valid("") || s.Valid("nope") {
		t.Fatal("basic session checks failed")
	}
	s.Delete(a)
	if s.Valid(a) || !s.Valid(b) {
		t.Fatal("delete")
	}
	clk.add(sessionTTL + time.Second)
	if s.Valid(b) {
		t.Fatal("expired session still valid")
	}
}

func TestSameOrigin(t *testing.T) {
	mk := func(h map[string]string) *http.Request {
		r := httptest.NewRequest("POST", "http://panel.lan:8080/api/users", nil)
		for k, v := range h {
			r.Header.Set(k, v)
		}
		return r
	}
	ok := []map[string]string{
		{"X-Hysui": "1"},
		{"X-Hysui": "1", "Origin": "http://panel.lan:8080", "Sec-Fetch-Site": "same-origin"},
	}
	bad := []map[string]string{
		{},
		{"X-Hysui": "1", "Origin": "http://evil.example"},
		{"X-Hysui": "1", "Sec-Fetch-Site": "cross-site"},
		{"X-Hysui": "1", "Sec-Fetch-Site": "same-site"},
	}
	for _, h := range ok {
		if !sameOrigin(mk(h)) {
			t.Errorf("rejected %v", h)
		}
	}
	for _, h := range bad {
		if sameOrigin(mk(h)) {
			t.Errorf("accepted %v", h)
		}
	}
}
