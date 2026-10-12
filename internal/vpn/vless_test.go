package vpn

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/revocx35/hysui/internal/store"
)

// startVLESS serves VLESS over plain TCP (no Reality, no Vision), exercising the
// same handler and policies as production.
func (e *env) startVLESS() string {
	e.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	h := newVLESSHandler(e.mgr, slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.serve(c)
		}
	}()
	e.t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func vlessClient(t *testing.T, server, id string) *http.Client {
	t.Helper()
	c, err := vless.NewClient(id, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", server)
				if err != nil {
					return nil, err
				}
				return c.DialConn(raw, M.ParseSocksaddr(addr))
			},
		},
	}
}

func fetch(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestVLESSPolicies(t *testing.T) {
	e := newEnv(t,
		store.User{Name: "home", Enabled: true, HomeAccess: true},
		store.User{Name: "guest", Enabled: true},
		store.User{Name: "off", Enabled: false},
	)
	srv := e.startVLESS()
	uid := func(name string) string { u, _ := e.store.User(name); return VLESSUUID(u) }

	home, guest := vlessClient(t, srv, uid("home")), vlessClient(t, srv, uid("guest"))
	for _, tc := range []struct {
		name   string
		c      *http.Client
		target string
		ok     bool
	}{
		{"home user, internet", home, e.inet, true},
		{"home user, LAN", home, e.home, true},
		{"guest, internet", guest, e.inet, true},
		{"guest, LAN", guest, e.home, false},
		{"disabled user", vlessClient(t, srv, uid("off")), e.inet, false},
		{"unknown id", vlessClient(t, srv, "00000000-0000-0000-0000-000000000001"), e.inet, false},
	} {
		body, err := fetch(tc.c, "http://"+tc.target+"/")
		if got := err == nil && strings.HasPrefix(body, "hello"); got != tc.ok {
			t.Errorf("%s: reached=%v (err %v), want %v", tc.name, got, err, tc.ok)
		}
	}
	if s := e.mgr.Stats()["guest"]; s.Tx == 0 || s.Rx == 0 {
		t.Fatalf("VLESS traffic not counted: %+v", s)
	}

	// A new password changes the UUID; the old link must stop working.
	old := uid("guest")
	if _, err := e.store.Update("guest", func(u *store.User) error { u.Password = "a-new-password"; return nil }); err != nil {
		t.Fatal(err)
	}
	e.mgr.Sync()
	if _, err := fetch(vlessClient(t, srv, old), "http://"+e.inet+"/"); err == nil {
		t.Fatal("old UUID still accepted after a password change")
	}
	if _, err := fetch(vlessClient(t, srv, uid("guest")), "http://"+e.inet+"/"); err != nil {
		t.Fatalf("new UUID refused: %v", err)
	}
}

func TestVLESSQuotaAndDevices(t *testing.T) {
	e := newEnv(t, store.User{Name: "q", Enabled: true, QuotaBytes: 200_000})
	srv := e.startVLESS()
	u, _ := e.store.User("q")
	c := vlessClient(t, srv, VLESSUUID(u))

	// Hold a connection open and check it counts as an online device.
	cl, _ := vless.NewClient(VLESSUUID(u), "", nil)
	raw, err := net.Dial("tcp", srv)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cl.DialConn(raw, M.ParseSocksaddr(e.inet))
	if err != nil {
		t.Fatal(err)
	}
	// An unfinished request keeps the connection open: the HTTP server waits for the rest.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.mgr.Stats()["q"].Online == 1 }, "VLESS device shown online")
	conn.Close()
	waitFor(t, func() bool { return e.mgr.Stats()["q"].Online == 0 }, "VLESS device shown offline after closing")

	if _, err := fetch(c, "http://"+e.inet+"/bytes?n=1000000"); err == nil {
		t.Fatal("download past the quota succeeded")
	}
	if !e.mgr.Stats()["q"].OverQuota {
		t.Fatal("quota not reached")
	}
	if _, err := fetch(c, "http://"+e.inet+"/"); err == nil {
		t.Fatal("over-quota user still connects")
	}
}

func TestVLESSUDP(t *testing.T) {
	e := newEnv(t, store.User{Name: "phone", Enabled: true}, store.User{Name: "lan", Enabled: true, HomeAccess: true})
	srv := e.startVLESS()
	echo := func(user, target string, xudp bool) bool {
		t.Helper()
		u, _ := e.store.User(user)
		cl, _ := vless.NewClient(VLESSUUID(u), "", nil)
		raw, err := net.Dial("tcp", srv)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		dest := M.ParseSocksaddr(target)
		var pc net.PacketConn
		if xudp {
			pc, err = cl.DialEarlyXUDPPacketConn(raw, dest) // the Mux command real XUDP clients send
		} else {
			pc, err = cl.DialPacketConn(raw, dest)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		to, _ := net.ResolveUDPAddr("udp", target)
		for range 3 {
			if _, err := pc.WriteTo([]byte("ping"), to); err != nil {
				return false
			}
			_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			b := make([]byte, 64)
			if n, _, err := pc.ReadFrom(b); err == nil {
				return string(b[:n]) == "ping"
			}
		}
		return false
	}
	for _, xudp := range []bool{false, true} {
		if !echo("phone", e.inetU, xudp) {
			t.Errorf("xudp=%v: internet UDP failed", xudp)
		}
		if echo("phone", e.homeU, xudp) {
			t.Errorf("xudp=%v: internet-only user reached LAN over UDP", xudp)
		}
		if !echo("lan", e.homeU, xudp) {
			t.Errorf("xudp=%v: home user could not reach LAN over UDP", xudp)
		}
	}
}

func TestRealityKeysAndLink(t *testing.T) {
	k, sid, err := NewRealityKeys()
	if err != nil {
		t.Fatal(err)
	}
	priv, rawSID, pub, err := ParseRealityKeys(k, sid)
	if err != nil || len(priv) != 32 || len(pub) != 43 || len(sid) != 16 || rawSID == [8]byte{} {
		t.Fatalf("keys: priv=%d pub=%q sid=%q err=%v", len(priv), pub, sid, err)
	}
	u := store.User{Name: "iphone", Password: "abc-DEF_123.xyz"}
	got := RealityLink(RealityLinkOptions{Host: "vpn.example.com", Port: 443, ServerName: "www.example.org", PublicKey: pub, ShortID: sid}, u)
	want := "vless://" + VLESSUUID(u) + "@vpn.example.com:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=" + pub +
		"&security=reality&sid=" + sid + "&sni=www.example.org&type=tcp#iphone%20(Reality)"
	if got != want {
		t.Fatalf("link:\ngot  %s\nwant %s", got, want)
	}
	if VLESSUUID(u) == VLESSUUID(store.User{Name: "iphone", Password: "other-password"}) {
		t.Fatal("UUID does not depend on the password")
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
	}
}
