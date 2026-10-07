// Package web serves the admin panel and its JSON API.
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"

	"github.com/revocx35/hysui/internal/netpolicy"
	"github.com/revocx35/hysui/internal/store"
	"github.com/revocx35/hysui/internal/vpn"
)

//go:embed static
var staticFS embed.FS

const cookieName = "hysui_session"

// Options configures the panel.
type Options struct {
	Version        string
	Store          *store.Store
	Manager        *vpn.Manager
	Certs          vpn.CertSource
	Policy         *netpolicy.Policy
	PublicPort     int    // UDP port in share links
	Listen         string // VPN UDP listen address, for display
	TrustedProxies []netip.Prefix
	SecureCookies  string // auto, true, false
	Log            *slog.Logger
	Now            func() time.Time
	LookupHost     func(ctx context.Context, host string) ([]string, error) // DNS, replaced by tests
}

// Server is the panel's HTTP handler.
type Server struct {
	o        Options
	sessions *Sessions
	throttle *Throttle
	started  time.Time
	mux      *http.ServeMux
}

// New builds the panel.
func New(o Options) *Server {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.LookupHost == nil {
		o.LookupHost = net.DefaultResolver.LookupHost
	}
	s := &Server{o: o, sessions: NewSessions(o.Now), throttle: NewThrottle(o.Now), started: o.Now(), mux: http.NewServeMux()}
	static, _ := fs.Sub(staticFS, "static")
	files := http.FileServerFS(static)

	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	s.mux.Handle("GET /assets/", files)
	s.mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, static, "login.html")
	})
	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.ServeFileFS(w, r, static, "index.html")
	})

	s.mux.HandleFunc("POST /api/login", s.login)
	s.mux.HandleFunc("POST /api/logout", s.logout)
	api := func(pattern string, h http.HandlerFunc) { s.mux.Handle(pattern, s.requireAuth(h)) }
	api("GET /api/status", s.status)
	api("GET /api/users", s.listUsers)
	api("POST /api/users", s.createUser)
	api("PUT /api/users/{name}", s.updateUser)
	api("DELETE /api/users/{name}", s.deleteUser)
	api("POST /api/users/{name}/kick", s.kickUser)
	api("POST /api/users/{name}/reset-usage", s.resetUsage)
	api("GET /api/users/{name}/link", s.userLink)
	api("GET /api/domains", s.listDomains)
	api("POST /api/domains", s.addDomain)
	api("POST /api/domains/{name}/activate", s.activateDomain)
	api("DELETE /api/domains/{name}", s.deleteDomain)
	api("POST /api/admin/password", s.changePassword)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "+
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		h.Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && !sameOrigin(r) {
			writeErr(w, http.StatusForbidden, "cross-site request refused")
			return
		}
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	return err == nil && s.sessions.Valid(c.Value)
}

func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeErr(w, http.StatusUnauthorized, "not logged in")
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) secure(r *http.Request) bool {
	switch s.o.SecureCookies {
	case "true":
		return true
	case "false":
		return false
	}
	return isHTTPS(r, s.o.TrustedProxies)
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.secure(r),
	})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "expected application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// RandomPassword returns n random characters from [A-Za-z0-9].
func RandomPassword(n int) string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, n)
	for i := range b {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			panic(err)
		}
		b[i] = chars[k.Int64()]
	}
	return string(b)
}

// bcryptCost is lowered by tests.
var bcryptCost = 12

// HashPassword hashes an admin password.
func HashPassword(p string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(p), bcryptCost)
	return string(h), err
}

// dummyHash is compared against when the user name is wrong, so both failure
// paths take the same time.
var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("hysui-dummy-password"), bcryptCost)
	return h
})

// ---- auth endpoints ----

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ip := clientIP(r, s.o.TrustedProxies).String()
	account := strings.ToLower(in.Username)
	if wait := s.throttle.Wait(ip, account); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+0.999)))
		writeErr(w, http.StatusTooManyRequests, "too many failed logins, try again in "+wait.Round(time.Second).String())
		return
	}
	admin := s.o.Store.Admin()
	hash := []byte(admin.PasswordHash)
	nameOK := admin.Username != "" && strings.EqualFold(in.Username, admin.Username)
	if !nameOK {
		hash = dummyHash()
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(in.Password)); err != nil || !nameOK {
		s.throttle.Fail(ip, account)
		s.o.Log.Warn("failed panel login", "ip", ip, "user", in.Username)
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	s.throttle.Succeed(ip)
	s.setSession(w, r, s.sessions.New(), int(sessionTTL.Seconds()))
	s.o.Log.Info("panel login", "ip", ip, "user", admin.Username)
	writeJSON(w, http.StatusOK, map[string]string{"username": admin.Username})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sessions.Delete(c.Value)
	}
	s.setSession(w, r, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current  string `json:"current"`
		New      string `json:"new"`
		Username string `json:"username"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	admin := s.o.Store.Admin()
	if bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(in.Current)) != nil {
		writeErr(w, http.StatusForbidden, "current password is wrong")
		return
	}
	if len(in.New) < 10 || len(in.New) > 72 {
		writeErr(w, http.StatusBadRequest, "new password must be 10-72 characters")
		return
	}
	if in.Username = strings.TrimSpace(in.Username); in.Username == "" {
		in.Username = admin.Username
	}
	if len(in.Username) > 64 {
		writeErr(w, http.StatusBadRequest, "username too long")
		return
	}
	hash, err := HashPassword(in.New)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.o.Store.SetAdmin(store.Admin{Username: in.Username, PasswordHash: hash}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Log out every other browser; keep this one logged in.
	s.sessions.DeleteAll()
	s.setSession(w, r, s.sessions.New(), int(sessionTTL.Seconds()))
	s.o.Log.Info("admin credentials changed", "user", in.Username)
	writeJSON(w, http.StatusOK, map[string]string{"username": in.Username})
}

// ---- status ----

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	stats := s.o.Manager.Stats()
	online, users := 0, s.o.Store.Users()
	for _, st := range stats {
		online += st.Online
	}
	var local []string
	for _, p := range s.o.Policy.Local() {
		local = append(local, p.String())
	}
	domain := s.o.Store.Domains().Active
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    s.o.Version,
		"domain":     domain,
		"port":       s.o.PublicPort,
		"listen":     s.o.Listen,
		"cert":       s.o.Certs.Status(domain),
		"uptimeSec":  int(s.o.Now().Sub(s.started).Seconds()),
		"users":      len(users),
		"online":     online,
		"admin":      s.o.Store.Admin().Username,
		"homeRanges": s.o.Policy.Home(),
		"homeLocal":  local,
	})
}

// ---- users ----

type userView struct {
	store.User
	vpn.Stats
}

func (s *Server) view(u store.User, stats map[string]vpn.Stats) userView {
	st, ok := stats[u.Name]
	if !ok {
		st = vpn.Stats{Tx: u.UsedTx, Rx: u.UsedRx}
	}
	return userView{User: u, Stats: st}
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	stats := s.o.Manager.Stats()
	out := []userView{}
	for _, u := range s.o.Store.Users() {
		out = append(out, s.view(u, stats))
	}
	writeJSON(w, http.StatusOK, out)
}

type userInput struct {
	Name       *string  `json:"name"`
	Password   *string  `json:"password"`
	Enabled    *bool    `json:"enabled"`
	HomeAccess *bool    `json:"homeAccess"`
	DownMbps   *float64 `json:"downMbps"`
	UpMbps     *float64 `json:"upMbps"`
	QuotaBytes *int64   `json:"quotaBytes"`
	Note       *string  `json:"note"`
}

func (in *userInput) apply(u *store.User) {
	if in.Password != nil && *in.Password != "" {
		u.Password = *in.Password
	}
	if in.Enabled != nil {
		u.Enabled = *in.Enabled
	}
	if in.HomeAccess != nil {
		u.HomeAccess = *in.HomeAccess
	}
	if in.DownMbps != nil {
		u.DownMbps = *in.DownMbps
	}
	if in.UpMbps != nil {
		u.UpMbps = *in.UpMbps
	}
	if in.QuotaBytes != nil {
		u.QuotaBytes = *in.QuotaBytes
	}
	if in.Note != nil {
		u.Note = strings.TrimSpace(*in.Note)
	}
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in userInput
	if !readJSON(w, r, &in) {
		return
	}
	u := store.User{Enabled: true, Password: RandomPassword(24)}
	if in.Name != nil {
		u.Name = strings.TrimSpace(*in.Name)
	}
	in.apply(&u)
	if err := s.o.Store.Add(u); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, store.ErrExists) {
			code = http.StatusConflict
		}
		writeErr(w, code, err.Error())
		return
	}
	s.o.Manager.Sync()
	s.o.Log.Info("user created", "user", u.Name)
	writeJSON(w, http.StatusCreated, s.view(u, s.o.Manager.Stats()))
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in userInput
	if !readJSON(w, r, &in) {
		return
	}
	var passwordChanged bool
	u, err := s.o.Store.Update(name, func(u *store.User) error {
		old := u.Password
		in.apply(u)
		passwordChanged = u.Password != old
		return nil
	})
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, store.ErrNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	s.o.Manager.Sync()
	if passwordChanged {
		s.o.Manager.Kick(name) // connected clients must log in again with the new password
	}
	s.o.Log.Info("user updated", "user", name)
	writeJSON(w, http.StatusOK, s.view(u, s.o.Manager.Stats()))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.o.Store.Delete(name); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	s.o.Manager.Sync()
	s.o.Log.Info("user deleted", "user", name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) kickUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.o.Store.User(name); !ok {
		writeErr(w, http.StatusNotFound, store.ErrNotFound.Error())
		return
	}
	s.o.Manager.Kick(name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) resetUsage(w http.ResponseWriter, r *http.Request) {
	if err := s.o.Manager.ResetUsage(r.PathValue("name")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) userLink(w http.ResponseWriter, r *http.Request) {
	u, ok := s.o.Store.User(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, store.ErrNotFound.Error())
		return
	}
	link := vpn.LinkOptions{Host: s.o.Store.Domains().Active, Port: s.o.PublicPort, Pin: s.o.Certs.PinSHA256()}
	uri := vpn.ShareLink(link, u)
	png, err := qrcode.Encode(uri, qrcode.Medium, 320)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"uri": uri,
		"qr":  "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

// ---- domains ----

type domainView struct {
	Name     string         `json:"name"`
	Active   bool           `json:"active"`
	Cert     vpn.CertStatus `json:"cert"`
	Addrs    []string       `json:"addrs"`
	DNSError string         `json:"dnsError,omitempty"`
}

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	d := s.o.Store.Domains()
	out := make([]domainView, len(d.List))
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i, name := range d.List {
		out[i] = domainView{Name: name, Active: name == d.Active, Cert: s.o.Certs.Status(name), Addrs: []string{}}
		wg.Go(func() {
			host := name
			if _, err := netip.ParseAddr(name); err != nil {
				host += "." // fully qualified, so a search domain with a wildcard can't answer instead
			}
			addrs, err := s.o.LookupHost(ctx, host)
			if err != nil {
				out[i].DNSError = dnsError(err)
				return
			}
			out[i].Addrs = addrs
		})
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{
		"active":  d.Active,
		"port":    s.o.PublicPort,
		"mode":    s.o.Certs.Status(d.Active).Mode,
		"domains": out,
	})
}

func dnsError(err error) string {
	var de *net.DNSError
	switch {
	case !errors.As(err, &de):
		return err.Error()
	case de.IsNotFound:
		return "no DNS record"
	case de.IsTimeout:
		return "DNS lookup timed out"
	}
	return de.Err
}

// syncDomains hands the domain list to the certificate source, which starts getting
// certificates for new domains and stops renewing removed ones.
func (s *Server) syncDomains() {
	d := s.o.Store.Domains()
	s.o.Certs.SetDomains(d.Active, d.List)
}

func (s *Server) addDomain(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	name, err := s.o.Store.AddDomain(in.Name)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, store.ErrDomainExists) {
			code = http.StatusConflict
		}
		writeErr(w, code, err.Error())
		return
	}
	s.syncDomains()
	s.o.Log.Info("domain added", "domain", name)
	writeJSON(w, http.StatusCreated, map[string]string{"name": name})
}

func (s *Server) activateDomain(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.o.Store.SetActiveDomain(name); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	s.syncDomains()
	s.o.Log.Info("active domain changed", "domain", name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.o.Store.DeleteDomain(name); err != nil {
		code := http.StatusNotFound
		if errors.Is(err, store.ErrDomainActive) {
			code = http.StatusConflict
		}
		writeErr(w, code, err.Error())
		return
	}
	s.syncDomains()
	s.o.Log.Info("domain removed", "domain", name)
	w.WriteHeader(http.StatusNoContent)
}
