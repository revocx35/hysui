package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/revocx35/hysui/internal/netpolicy"
	"github.com/revocx35/hysui/internal/store"
	"github.com/revocx35/hysui/internal/vpn"
)

const adminPass = "correct horse battery"

func TestMain(m *testing.M) {
	bcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}

type panel struct {
	t      *testing.T
	srv    *Server
	st     *store.Store
	mgr    *vpn.Manager
	clk    *fakeClock
	cookie *http.Cookie
}

func newPanel(t *testing.T) *panel {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "hysui.json"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword(adminPass)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAdmin(store.Admin{Username: "admin", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := netpolicy.NewDefault(nil)
	mgr := vpn.NewManager(st, policy, log)
	certs, err := vpn.NewSelfSigned(dir, "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddDomain("vpn.example.com"); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	srv := New(Options{
		Version: "test", Store: st, Manager: mgr, Certs: certs, Policy: policy,
		PublicPort: 443, Listen: ":443", SecureCookies: "auto", Log: log, Now: clk.now,
		LookupHost: func(_ context.Context, host string) ([]string, error) {
			if host == "vpn.example.com." {
				return []string{"203.0.113.7"}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		},
	})
	return &panel{t: t, srv: srv, st: st, mgr: mgr, clk: clk}
}

type resp struct {
	code int
	body string
	hdr  http.Header
}

func (p *panel) do(method, path, body string, hdr map[string]string) resp {
	p.t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "http://panel.lan:8080"+path, r)
	req.RemoteAddr = "192.168.1.50:5555"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("X-Hysui", "1")
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	if p.cookie != nil {
		req.AddCookie(p.cookie)
	}
	w := httptest.NewRecorder()
	p.srv.ServeHTTP(w, req)
	return resp{code: w.Code, body: w.Body.String(), hdr: w.Header()}
}

func (p *panel) login(pass string) resp {
	p.t.Helper()
	r := p.do("POST", "/api/login", `{"username":"admin","password":"`+pass+`"}`, nil)
	if r.code == http.StatusOK {
		for _, c := range (&http.Response{Header: r.hdr}).Cookies() {
			if c.Name == cookieName {
				p.cookie = c
			}
		}
	}
	return r
}

func TestAuthRequired(t *testing.T) {
	p := newPanel(t)
	if r := p.do("GET", "/api/users", "", nil); r.code != http.StatusUnauthorized {
		t.Fatalf("users without login: %d", r.code)
	}
	if r := p.do("GET", "/", "", nil); r.code != http.StatusSeeOther || r.hdr.Get("Location") != "/login" {
		t.Fatalf("index without login: %d %s", r.code, r.hdr.Get("Location"))
	}
	if r := p.do("GET", "/login", "", nil); r.code != http.StatusOK || !strings.Contains(r.body, "Sign in") {
		t.Fatalf("login page: %d", r.code)
	}
	if r := p.do("GET", "/assets/app.js", "", nil); r.code != http.StatusOK {
		t.Fatalf("asset: %d", r.code)
	}
	if r := p.do("GET", "/healthz", "", nil); r.code != http.StatusOK {
		t.Fatalf("healthz: %d", r.code)
	}
	r := p.do("GET", "/login", "", nil)
	if csp := r.hdr.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || r.hdr.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("security headers missing: %v", r.hdr)
	}
}

func TestLogin(t *testing.T) {
	p := newPanel(t)
	if r := p.do("POST", "/api/login", `{"username":"admin","password":"`+adminPass+`"}`, map[string]string{"X-Hysui": ""}); r.code != http.StatusForbidden {
		t.Fatalf("login without X-Hysui: %d", r.code)
	}
	if r := p.login("wrong password"); r.code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", r.code)
	}
	if r := p.do("POST", "/api/login", `{"username":"nobody","password":"`+adminPass+`"}`, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("wrong user: %d", r.code)
	}
	if r := p.login(adminPass); r.code != http.StatusOK {
		t.Fatalf("login: %d %s", r.code, r.body)
	}
	if !p.cookie.HttpOnly || p.cookie.SameSite != http.SameSiteStrictMode || p.cookie.Secure {
		t.Fatalf("cookie flags: %+v", p.cookie)
	}
	if r := p.do("GET", "/", "", nil); r.code != http.StatusOK || !strings.Contains(r.body, "Add user") {
		t.Fatalf("index after login: %d", r.code)
	}
	if r := p.do("POST", "/api/logout", "", nil); r.code != http.StatusNoContent {
		t.Fatalf("logout: %d", r.code)
	}
	if r := p.do("GET", "/api/users", "", nil); r.code != http.StatusUnauthorized {
		t.Fatalf("session survived logout: %d", r.code)
	}
}

func TestLoginThrottled(t *testing.T) {
	p := newPanel(t)
	for range ipRule.free + 1 {
		p.login("wrong password")
	}
	r := p.login(adminPass)
	if r.code != http.StatusTooManyRequests || r.hdr.Get("Retry-After") != "30" {
		t.Fatalf("expected 429 with Retry-After 30, got %d %q", r.code, r.hdr.Get("Retry-After"))
	}
	p.clk.add(31 * time.Second)
	if r := p.login(adminPass); r.code != http.StatusOK {
		t.Fatalf("login after delay: %d", r.code)
	}
}

func TestCrossSiteRefused(t *testing.T) {
	p := newPanel(t)
	p.login(adminPass)
	r := p.do("POST", "/api/users", `{"name":"x"}`, map[string]string{"Origin": "http://evil.example"})
	if r.code != http.StatusForbidden {
		t.Fatalf("cross-origin create: %d", r.code)
	}
	r = p.do("POST", "/api/users", `{"name":"x"}`, map[string]string{"X-Hysui": ""})
	if r.code != http.StatusForbidden {
		t.Fatalf("create without X-Hysui: %d", r.code)
	}
	r = p.do("POST", "/api/users", `{"name":"x"}`, map[string]string{"Content-Type": "text/plain"})
	if r.code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain body: %d", r.code)
	}
}

func TestUserLifecycle(t *testing.T) {
	p := newPanel(t)
	p.login(adminPass)

	r := p.do("POST", "/api/users", `{"name":"iphone","downMbps":20,"homeAccess":true,"note":"Mom's phone"}`, nil)
	if r.code != http.StatusCreated {
		t.Fatalf("create: %d %s", r.code, r.body)
	}
	var created userView
	_ = json.Unmarshal([]byte(r.body), &created)
	if len(created.Password) != 24 || !created.Enabled || !created.HomeAccess || created.DownMbps != 20 {
		t.Fatalf("created: %+v", created)
	}
	if r := p.do("POST", "/api/users", `{"name":"iphone"}`, nil); r.code != http.StatusConflict {
		t.Fatalf("duplicate: %d", r.code)
	}
	if r := p.do("POST", "/api/users", `{"name":"bad name"}`, nil); r.code != http.StatusBadRequest {
		t.Fatalf("invalid name: %d", r.code)
	}
	if r := p.do("POST", "/api/users", `{"name":"x","bogus":1}`, nil); r.code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", r.code)
	}

	r = p.do("PUT", "/api/users/iphone", `{"homeAccess":false,"upMbps":5,"quotaBytes":1000000000}`, nil)
	if r.code != http.StatusOK {
		t.Fatalf("update: %d %s", r.code, r.body)
	}
	u, _ := p.st.User("iphone")
	if u.HomeAccess || u.UpMbps != 5 || u.QuotaBytes != 1e9 || u.DownMbps != 20 || u.Password != created.Password {
		t.Fatalf("after update: %+v", u)
	}
	if r := p.do("PUT", "/api/users/ghost", `{"enabled":false}`, nil); r.code != http.StatusNotFound {
		t.Fatalf("update missing: %d", r.code)
	}

	r = p.do("GET", "/api/users/iphone/link", "", nil)
	var link struct{ URI, QR string }
	_ = json.Unmarshal([]byte(r.body), &link)
	if r.code != http.StatusOK || !strings.HasPrefix(link.URI, "hysteria2://iphone:"+created.Password+"@vpn.example.com:443/") ||
		!strings.Contains(link.URI, "pinSHA256=") || !strings.HasPrefix(link.QR, "data:image/png;base64,") {
		t.Fatalf("link: %d %+v", r.code, link)
	}

	r = p.do("GET", "/api/users", "", nil)
	var list []userView
	_ = json.Unmarshal([]byte(r.body), &list)
	if len(list) != 1 || list[0].Name != "iphone" || list[0].Note != "Mom's phone" {
		t.Fatalf("list: %s", r.body)
	}

	for _, path := range []string{"/api/users/iphone/kick", "/api/users/iphone/reset-usage"} {
		if r := p.do("POST", path, "", nil); r.code != http.StatusNoContent {
			t.Fatalf("%s: %d", path, r.code)
		}
	}
	if r := p.do("DELETE", "/api/users/iphone", "", nil); r.code != http.StatusNoContent {
		t.Fatalf("delete: %d", r.code)
	}
	if r := p.do("DELETE", "/api/users/iphone", "", nil); r.code != http.StatusNotFound {
		t.Fatalf("second delete: %d", r.code)
	}

	r = p.do("GET", "/api/status", "", nil)
	if r.code != http.StatusOK || !strings.Contains(r.body, `"domain":"vpn.example.com"`) || !strings.Contains(r.body, `"mode":"self-signed"`) {
		t.Fatalf("status: %d %s", r.code, r.body)
	}
}

func TestChangeAdminPassword(t *testing.T) {
	p := newPanel(t)
	p.login(adminPass)
	old := p.cookie
	if r := p.do("POST", "/api/admin/password", `{"current":"nope","new":"another long password"}`, nil); r.code != http.StatusForbidden {
		t.Fatalf("wrong current: %d", r.code)
	}
	if r := p.do("POST", "/api/admin/password", `{"current":"`+adminPass+`","new":"short"}`, nil); r.code != http.StatusBadRequest {
		t.Fatalf("short new: %d", r.code)
	}
	r := p.do("POST", "/api/admin/password", `{"current":"`+adminPass+`","new":"another long password","username":"boss"}`, nil)
	if r.code != http.StatusOK {
		t.Fatalf("change: %d %s", r.code, r.body)
	}
	if p.st.Admin().Username != "boss" {
		t.Fatal("username not changed")
	}
	// The old session is gone; the response carried a fresh one.
	p.cookie = old
	if r := p.do("GET", "/api/users", "", nil); r.code != http.StatusUnauthorized {
		t.Fatalf("old session still valid: %d", r.code)
	}
	if r := p.do("POST", "/api/login", `{"username":"boss","password":"another long password"}`, nil); r.code != http.StatusOK {
		t.Fatalf("login with new credentials: %d", r.code)
	}
}

func TestDomains(t *testing.T) {
	p := newPanel(t)
	p.login(adminPass)
	if r := p.do("POST", "/api/users", `{"name":"iphone"}`, nil); r.code != http.StatusCreated {
		t.Fatalf("create user: %d", r.code)
	}

	type listing struct {
		Active  string
		Mode    string
		Domains []domainView
	}
	list := func() listing {
		t.Helper()
		r := p.do("GET", "/api/domains", "", nil)
		if r.code != http.StatusOK {
			t.Fatalf("list: %d %s", r.code, r.body)
		}
		var l listing
		_ = json.Unmarshal([]byte(r.body), &l)
		return l
	}
	l := list()
	if l.Active != "vpn.example.com" || l.Mode != "self-signed" || len(l.Domains) != 1 ||
		!l.Domains[0].Active || l.Domains[0].Cert.State != "ok" || len(l.Domains[0].Addrs) != 1 {
		t.Fatalf("initial list: %+v", l)
	}

	r := p.do("POST", "/api/domains", `{"name":"Backup.Example.NET"}`, nil)
	if r.code != http.StatusCreated || !strings.Contains(r.body, `"backup.example.net"`) {
		t.Fatalf("add: %d %s", r.code, r.body)
	}
	if r := p.do("POST", "/api/domains", `{"name":"backup.example.net"}`, nil); r.code != http.StatusConflict {
		t.Fatalf("duplicate: %d", r.code)
	}
	if r := p.do("POST", "/api/domains", `{"name":"https://x.example.com/"}`, nil); r.code != http.StatusBadRequest {
		t.Fatalf("invalid: %d", r.code)
	}
	l = list()
	if len(l.Domains) != 2 || l.Domains[1].Active || l.Domains[1].DNSError != "no DNS record" {
		t.Fatalf("after add: %+v", l)
	}

	if r := p.do("POST", "/api/domains/ghost.example.com/activate", "", nil); r.code != http.StatusNotFound {
		t.Fatalf("activate unknown: %d", r.code)
	}
	if r := p.do("POST", "/api/domains/backup.example.net/activate", "", nil); r.code != http.StatusNoContent {
		t.Fatalf("activate: %d %s", r.code, r.body)
	}
	r = p.do("GET", "/api/users/iphone/link", "", nil)
	if !strings.Contains(r.body, "@backup.example.net:443/") || !strings.Contains(r.body, "sni=backup.example.net") {
		t.Fatalf("link does not use the new domain: %s", r.body)
	}
	if r := p.do("GET", "/api/status", "", nil); !strings.Contains(r.body, `"domain":"backup.example.net"`) {
		t.Fatalf("status: %s", r.body)
	}

	if r := p.do("DELETE", "/api/domains/backup.example.net", "", nil); r.code != http.StatusConflict {
		t.Fatalf("delete active: %d", r.code)
	}
	if r := p.do("DELETE", "/api/domains/vpn.example.com", "", nil); r.code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", r.code, r.body)
	}
	if r := p.do("DELETE", "/api/domains/vpn.example.com", "", nil); r.code != http.StatusNotFound {
		t.Fatalf("second delete: %d", r.code)
	}
	if l := list(); len(l.Domains) != 1 || l.Active != "backup.example.net" {
		t.Fatalf("after delete: %+v", l)
	}
}
