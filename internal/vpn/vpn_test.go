package vpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/caddyserver/certmagic"

	"github.com/revocx35/hysui/internal/netpolicy"
	"github.com/revocx35/hysui/internal/store"
)

// The test network: 127.0.0.1 plays "the internet", 127.0.0.2 plays the home LAN.
const (
	inetIP = "127.0.0.1"
	homeIP = "127.0.0.2"
	pass   = "testpassword123"
)

type env struct {
	t      *testing.T
	store  *store.Store
	mgr    *Manager
	server net.Addr
	inet   string // HTTP target on the "internet"
	home   string // HTTP target on the "home network"
	inetU  string // UDP echo on the "internet"
	homeU  string // UDP echo on the "home network"
}

func newEnv(t *testing.T, users ...store.User) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "hysui.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Password == "" {
			u.Password = pass
		}
		if err := st.Add(u); err != nil {
			t.Fatal(err)
		}
	}
	policy := netpolicy.New(nil, []netip.Prefix{netip.MustParsePrefix(homeIP + "/32")})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewManager(st, policy, log)
	certs, err := NewSelfSigned(dir, "hysui.test")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	masq, _ := Masquerade("")
	srv, err := NewServerConn(pc, mgr, certs, masq)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Close() })

	return &env{
		t: t, store: st, mgr: mgr, server: pc.LocalAddr(),
		inet: startHTTP(t, inetIP), home: startHTTP(t, homeIP),
		inetU: startEcho(t, inetIP), homeU: startEcho(t, homeIP),
	}
}

// startHTTP serves /bytes?n=N (N zero bytes), /sink (discards the body) and /hold
// (keeps the connection open, echoing lines).
func startHTTP(t *testing.T, ip string) string {
	t.Helper()
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/bytes", func(w http.ResponseWriter, r *http.Request) {
		var n int64
		fmt.Sscan(r.URL.Query().Get("n"), &n)
		w.Header().Set("Content-Length", fmt.Sprint(n))
		_, _ = io.CopyN(w, zeroReader{}, n)
	})
	mux.HandleFunc("/sink", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, n)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hello from "+ip) })
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func startEcho(t *testing.T, ip string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }

func (e *env) connect(user, password string) (client.Client, error) {
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: e.server,
		Auth:       user + ":" + password,
		TLSConfig:  client.TLSConfig{ServerName: "hysui.test", InsecureSkipVerify: true},
	})
	return c, err
}

func (e *env) mustConnect(user string) client.Client {
	e.t.Helper()
	c, err := e.connect(user, pass)
	if err != nil {
		e.t.Fatalf("connect %s: %v", user, err)
	}
	e.t.Cleanup(func() { _ = c.Close() })
	return c
}

func httpVia(c client.Client) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:       func(_ context.Context, _, addr string) (net.Conn, error) { return c.TCP(addr) },
			DisableKeepAlives: true,
		},
	}
}

func get(c client.Client, url string) (string, error) {
	resp, err := httpVia(c).Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func udpEcho(t *testing.T, c client.Client, target string) bool {
	t.Helper()
	u, err := c.UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	got := make(chan []byte, 1)
	go func() {
		b, _, err := u.Receive()
		if err == nil {
			got <- b
		}
	}()
	for range 3 {
		if err := u.Send([]byte("ping"), target); err != nil {
			t.Fatal(err)
		}
		select {
		case b := <-got:
			return string(b) == "ping"
		case <-time.After(400 * time.Millisecond):
		}
	}
	return false
}

func TestHomeAccessPerUser(t *testing.T) {
	e := newEnv(t,
		store.User{Name: "lan", Enabled: true, HomeAccess: true},
		store.User{Name: "nolan", Enabled: true, HomeAccess: false},
	)
	lan, nolan := e.mustConnect("lan"), e.mustConnect("nolan")

	if body, err := get(lan, "http://"+e.home+"/"); err != nil || body != "hello from "+homeIP {
		t.Fatalf("lan -> home: %q %v", body, err)
	}
	if body, err := get(nolan, "http://"+e.inet+"/"); err != nil || body != "hello from "+inetIP {
		t.Fatalf("nolan -> internet: %q %v", body, err)
	}
	if body, err := get(nolan, "http://"+e.home+"/"); err == nil {
		t.Fatalf("nolan reached the home network: %q", body)
	}

	// Many interleaved requests from both users: the per-goroutine user binding must
	// never hand one user's access to the other.
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	for i := range 40 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := get(lan, "http://"+e.home+"/"); err != nil {
				mu.Lock()
				failures = append(failures, fmt.Sprintf("lan #%d denied: %v", i, err))
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := get(nolan, "http://"+e.home+"/"); err == nil {
				mu.Lock()
				failures = append(failures, fmt.Sprintf("nolan #%d reached home", i))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("%d mix-ups, first: %s", len(failures), failures[0])
	}
}

func TestHomeAccessUDP(t *testing.T) {
	e := newEnv(t,
		store.User{Name: "lan", Enabled: true, HomeAccess: true},
		store.User{Name: "nolan", Enabled: true},
	)
	lan, nolan := e.mustConnect("lan"), e.mustConnect("nolan")
	if !udpEcho(t, lan, e.homeU) {
		t.Fatal("lan: no UDP echo from home")
	}
	if !udpEcho(t, nolan, e.inetU) {
		t.Fatal("nolan: no UDP echo from internet")
	}
	if udpEcho(t, nolan, e.homeU) {
		t.Fatal("nolan: got UDP echo from home")
	}
}

func TestRevokeHomeAccessCutsLiveConnection(t *testing.T) {
	e := newEnv(t, store.User{Name: "lan", Enabled: true, HomeAccess: true})
	c := e.mustConnect("lan")
	conn, err := c.TCP(e.home)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bytes.NewBufferString("GET /bytes?n=10 HTTP/1.1\r\nHost: x\r\n\r\n")
	if _, err := io.Copy(conn, br); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("first response: %v", err)
	}

	if _, err := e.store.Update("lan", func(u *store.User) error { u.HomeAccess = false; return nil }); err != nil {
		t.Fatal(err)
	}
	e.mgr.Sync()

	_, _ = conn.Write([]byte("GET /bytes?n=10 HTTP/1.1\r\nHost: x\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("connection still works after revoke: %q", buf[:n])
	}
	if _, err := get(c, "http://"+e.home+"/"); err == nil {
		t.Fatal("new home connection allowed after revoke")
	}
	if _, err := get(c, "http://"+e.inet+"/"); err != nil {
		t.Fatalf("internet broken after revoke: %v", err)
	}
}

func timeDownload(t *testing.T, c client.Client, target string, n int) time.Duration {
	t.Helper()
	start := time.Now()
	body, err := get(c, fmt.Sprintf("http://%s/bytes?n=%d", target, n))
	if err != nil || len(body) != n {
		t.Fatalf("download: %d bytes, %v", len(body), err)
	}
	return time.Since(start)
}

func timeUpload(t *testing.T, c client.Client, target string, n int) time.Duration {
	t.Helper()
	start := time.Now()
	resp, err := httpVia(c).Post("http://"+target+"/sink", "application/octet-stream", io.LimitReader(zeroReader{}, int64(n)))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.TrimSpace(string(b)) != fmt.Sprint(n) {
		t.Fatalf("upload: server got %s bytes", b)
	}
	return time.Since(start)
}

func TestSpeedLimits(t *testing.T) {
	e := newEnv(t,
		store.User{Name: "slow", Enabled: true, DownMbps: 8, UpMbps: 4},
		store.User{Name: "fast", Enabled: true},
	)
	slow, fast := e.mustConnect("slow"), e.mustConnect("fast")
	const size = 3 << 20

	// Margins are wide so slow CI runners (and -race) don't flake; the limited and
	// unlimited cases are still far apart.
	// 8 Mbps = 1 MB/s with a 200 KB burst: 3 MiB takes ~2.9 s.
	if d := timeDownload(t, slow, e.inet, size); d < 2600*time.Millisecond || d > 8*time.Second {
		t.Errorf("limited download of 3 MiB took %v, want ~2.9s", d)
	}
	if d := timeDownload(t, fast, e.inet, size); d > 2*time.Second {
		t.Errorf("unlimited download took %v", d)
	}
	// 4 Mbps = 500 KB/s with a 100 KB burst: 1.5 MiB takes ~2.9 s.
	if d := timeUpload(t, slow, e.inet, 3<<19); d < 2600*time.Millisecond || d > 8*time.Second {
		t.Errorf("limited upload of 1.5 MiB took %v, want ~2.9s", d)
	}

	// Removing the limit applies to the live session.
	if _, err := e.store.Update("slow", func(u *store.User) error { u.DownMbps = 0; return nil }); err != nil {
		t.Fatal(err)
	}
	e.mgr.Sync()
	if d := timeDownload(t, slow, e.inet, size); d > 2*time.Second {
		t.Errorf("download after removing limit took %v", d)
	}
}

func TestQuota(t *testing.T) {
	e := newEnv(t, store.User{Name: "q", Enabled: true, QuotaBytes: 256 << 10})
	c := e.mustConnect("q")
	if _, err := get(c, fmt.Sprintf("http://%s/bytes?n=%d", e.inet, 1<<20)); err == nil {
		t.Fatal("download past the quota succeeded")
	}
	if !e.mgr.Stats()["q"].OverQuota {
		t.Fatal("user not marked over quota")
	}
	if _, err := e.connect("q", pass); err == nil {
		t.Fatal("over-quota user could reconnect")
	}
	if err := e.mgr.ResetUsage("q"); err != nil {
		t.Fatal(err)
	}
	c2, err := e.connect("q", pass)
	if err != nil {
		t.Fatalf("reconnect after reset: %v", err)
	}
	defer c2.Close()
}

func TestAuth(t *testing.T) {
	e := newEnv(t,
		store.User{Name: "on", Enabled: true},
		store.User{Name: "off", Enabled: false},
	)
	if _, err := e.connect("on", "wrongpassword"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := e.connect("off", pass); err == nil {
		t.Fatal("disabled user accepted")
	}
	if _, err := e.connect("ghost", pass); err == nil {
		t.Fatal("unknown user accepted")
	}
	c := e.mustConnect("on")

	// Disabling a connected user cuts their traffic.
	if _, err := e.store.Update("on", func(u *store.User) error { u.Enabled = false; return nil }); err != nil {
		t.Fatal(err)
	}
	e.mgr.Sync()
	if _, err := get(c, "http://"+e.inet+"/"); err == nil {
		t.Fatal("disabled user still has traffic")
	}
}

func TestKickAndStats(t *testing.T) {
	e := newEnv(t, store.User{Name: "k", Enabled: true})
	c := e.mustConnect("k")
	if _, err := get(c, fmt.Sprintf("http://%s/bytes?n=%d", e.inet, 100000)); err != nil {
		t.Fatal(err)
	}
	s := e.mgr.Stats()["k"]
	if s.Online != 1 || s.Rx < 100000 || s.Tx == 0 {
		t.Fatalf("stats = %+v", s)
	}
	e.mgr.Kick("k")
	if _, err := get(c, "http://"+e.inet+"/"); err == nil {
		t.Fatal("kicked client still works")
	}
	if _, err := e.connect("k", pass); err == nil {
		t.Fatal("reconnect inside kick window succeeded")
	}
	time.Sleep(kickWindow + 200*time.Millisecond)
	c2, err := e.connect("k", pass)
	if err != nil {
		t.Fatalf("reconnect after kick window: %v", err)
	}
	defer c2.Close()

	if err := e.mgr.Flush(); err != nil {
		t.Fatal(err)
	}
	if u, _ := e.store.User("k"); u.UsedRx < 100000 {
		t.Fatalf("usage not persisted: %+v", u)
	}
}

func TestGoid(t *testing.T) {
	a := goid()
	if a == 0 || a != goid() {
		t.Fatalf("goid unstable: %d", a)
	}
	ch := make(chan uint64)
	go func() { ch <- goid() }()
	if b := <-ch; b == 0 || b == a {
		t.Fatalf("goroutines share id: %d %d", a, b)
	}
}

type obfsConnFactory struct{ password string }

func (f obfsConnFactory) New(net.Addr) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return obfs.WrapPacketConnSalamander(pc, []byte(f.password))
}

func TestObfuscatedListener(t *testing.T) {
	e := newEnv(t, store.User{Name: "phone", Enabled: true})
	free, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := free.LocalAddr().(*net.UDPAddr)
	free.Close()
	certs, err := NewSelfSigned(t.TempDir(), "hysui.test")
	if err != nil {
		t.Fatal(err)
	}
	masq, _ := Masquerade("")
	srv, err := NewServer(addr.String(), "obfs-password", e.mgr, certs, masq)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Close() })

	dial := func(cf client.ConnFactory) (client.Client, error) {
		c, _, err := client.NewClient(&client.Config{
			ConnFactory: cf, ServerAddr: addr, Auth: "phone:" + pass,
			TLSConfig: client.TLSConfig{ServerName: "hysui.test", InsecureSkipVerify: true},
		})
		return c, err
	}
	c, err := dial(obfsConnFactory{"obfs-password"})
	if err != nil {
		t.Fatalf("obfuscated client: %v", err)
	}
	defer c.Close()
	if body, err := get(c, "http://"+e.inet+"/"); err != nil || !strings.Contains(body, "hello") {
		t.Fatalf("traffic through the obfuscated listener: %q %v", body, err)
	}
	// Plain QUIC must get no answer there, or the port would still look like QUIC.
	for _, cf := range []client.ConnFactory{nil, obfsConnFactory{"wrong-password"}} {
		if c, err := dial(cf); err == nil {
			c.Close()
			t.Fatalf("client %T connected without the right obfuscation", cf)
		}
	}
}

func TestShareLink(t *testing.T) {
	u := store.User{Name: "iphone", Password: "abc-DEF_123.xyz"}
	got := ShareLink(LinkOptions{Host: "vpn.example.com", Port: 443}, u)
	want := "hysteria2://iphone:abc-DEF_123.xyz@vpn.example.com:443/?sni=vpn.example.com#iphone"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	got = ShareLink(LinkOptions{Host: "h", Port: 8443, Pin: "ab12"}, u)
	if !strings.Contains(got, "insecure=1") || !strings.Contains(got, "pinSHA256=ab12") {
		t.Fatalf("self-signed link missing pin: %s", got)
	}
	got = ShareLink(LinkOptions{Host: "vpn.example.com", Port: 8443, Obfs: "s3cret pw"}, u)
	want = "hysteria2://iphone:abc-DEF_123.xyz@vpn.example.com:8443/?obfs=salamander&obfs-password=s3cret+pw&sni=vpn.example.com#iphone%20(obfuscated)"
	if got != want {
		t.Fatalf("obfuscated link:\ngot  %s\nwant %s", got, want)
	}
}

func testACME(t *testing.T) *acmeCert {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	src, err := NewACME(ACMEOptions{
		CA: "https://127.0.0.1:1/directory", Challenge: "http", AltPort: 1, Dir: t.TempDir(),
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	a := src.(*acmeCert)
	t.Cleanup(func() { a.SetDomains("", nil) }) // stop the retry loops
	return a
}

func TestACMEStatusReportsFailure(t *testing.T) {
	src := testACME(t)
	src.SetDomains("hysui.invalid", []string{"hysui.invalid"})
	if s := src.Status("hysui.invalid"); s.State != "pending" || s.Mode != "acme-http" {
		t.Fatalf("initial status = %+v", s)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		s := src.Status("hysui.invalid")
		if s.State == "error" && s.Error != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status never reported the failure: %+v", s)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if src.PinSHA256() != "" {
		t.Fatal("ACME certificates must not be pinned")
	}
}

// servedName does a TLS handshake with the given SNI and returns the name on the
// certificate the server picked.
func servedName(t *testing.T, src CertSource, sni string) string {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() { _ = tls.Server(s, &tls.Config{GetCertificate: src.GetCertificate}).Handshake() }()
	cl := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err := cl.Handshake(); err != nil {
		t.Fatalf("handshake for %q: %v", sni, err)
	}
	return cl.ConnectionState().PeerCertificates[0].Subject.CommonName
}

func TestACMEDomains(t *testing.T) {
	src := testACME(t)
	dir := t.TempDir()
	for _, name := range []string{"a.test", "b.test"} {
		certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
		if err := writeSelfSigned(certPath, keyPath, name); err != nil {
			t.Fatal(err)
		}
		c, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := src.cfg.CacheUnmanagedTLSCertificate(context.Background(), c, nil); err != nil {
			t.Fatal(err)
		}
	}

	src.SetDomains("a.test", []string{"a.test", "b.test"})
	for sni, want := range map[string]string{"a.test": "a.test", "B.test": "b.test", "other.test": "a.test", "": "a.test"} {
		if got := servedName(t, src, sni); got != want {
			t.Errorf("SNI %q got the certificate for %s, want %s", sni, got, want)
		}
	}
	if s := src.Status("b.test"); s.State != "ok" || s.NotAfter.IsZero() {
		t.Fatalf("status of b.test = %+v", s)
	}

	// Switch the active domain, then drop a.test.
	src.SetDomains("b.test", []string{"a.test", "b.test"})
	if got := servedName(t, src, "other.test"); got != "b.test" {
		t.Fatalf("unknown SNI after switching got %s", got)
	}
	src.SetDomains("b.test", []string{"b.test"})
	if got := servedName(t, src, "a.test"); got != "b.test" {
		t.Fatalf("removed domain still served its own certificate: %s", got)
	}
	src.mu.Lock()
	_, stillManaged := src.domains["a.test"]
	src.mu.Unlock()
	if stillManaged {
		t.Fatal("removed domain is still managed")
	}
}

// Renewal looks up each certificate's config through configForCert, and certmagic
// refuses to renew with a config that isn't bound to the cache.
func TestACMEMaintenanceConfig(t *testing.T) {
	src := testACME(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := writeSelfSigned(certPath, keyPath, "renew.test"); err != nil {
		t.Fatal(err)
	}
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := src.configForCert(certmagic.Certificate{})
	if err != nil || cfg == nil {
		t.Fatalf("configForCert: %v %v", cfg, err)
	}
	// Caching through the returned config only lands in our cache if it is bound to it
	// (an unbound config has no cache at all).
	if _, err := cfg.CacheUnmanagedTLSCertificate(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	if len(src.cache.AllMatchingCertificates("renew.test")) != 1 {
		t.Fatal("maintenance config is not bound to the certificate cache; renewals would fail")
	}
}

func TestFileCertCoverage(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := writeSelfSigned(certPath, keyPath, "vpn.example.com"); err != nil {
		t.Fatal(err)
	}
	src, err := NewFileCert(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if s := src.Status("vpn.example.com"); s.State != "ok" {
		t.Fatalf("covered domain: %+v", s)
	}
	if s := src.Status("other.example.com"); s.State != "error" || !strings.Contains(s.Error, "does not cover") {
		t.Fatalf("uncovered domain: %+v", s)
	}
}
