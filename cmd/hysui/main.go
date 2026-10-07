// Command hysui runs a Hysteria 2 VPN server with a web panel for managing users.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"go.yaml.in/yaml/v3"

	"github.com/revocx35/hysui/internal/config"
	"github.com/revocx35/hysui/internal/netpolicy"
	"github.com/revocx35/hysui/internal/store"
	"github.com/revocx35/hysui/internal/vpn"
	"github.com/revocx35/hysui/internal/web"
)

var version = "dev"

const usage = `hysui - Hysteria 2 server with a web panel

Usage:
  hysui [serve]                         run the VPN and the panel (configured by HYSUI_* variables)
  hysui reset-admin [username]          set a new random panel password (stop the server first)
  hysui import-hysteria [-home] FILE    import users from a Hysteria server config (auth.userpass)
  hysui healthcheck                     exit 0 if the panel answers (for Docker)
  hysui version
`

func main() {
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "reset-admin":
		err = resetAdmin(args)
	case "import-hysteria":
		err = importHysteria(args)
	case "healthcheck":
		err = healthcheck()
	case "version", "-v", "--version":
		fmt.Println("hysui", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hysui:", err)
		os.Exit(1)
	}
}

func dataDir() string {
	if d := os.Getenv("HYSUI_DATA_DIR"); d != "" {
		return d
	}
	return "/data"
}

func openStore() (*store.Store, error) {
	return store.Open(filepath.Join(dataDir(), "hysui.json"))
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func serve() error {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	st, err := store.Open(filepath.Join(cfg.DataDir, "hysui.json"))
	if err != nil {
		return err
	}
	if err := bootstrapAdmin(st, cfg); err != nil {
		return err
	}
	domains, err := initDomains(st, cfg.Domain, log)
	if err != nil {
		return err
	}

	policy := netpolicy.NewDefault(cfg.HomeExtra)
	if cfg.DetectLocal {
		detect := func() {
			if p, err := netpolicy.DetectLocal(); err == nil {
				policy.SetLocal(p)
			} else {
				log.Warn("detecting local addresses", "err", err)
			}
		}
		detect()
		go func() {
			for range time.Tick(5 * time.Minute) { // the ISP's IPv6 prefix can change
				detect()
			}
		}()
	}

	certs, err := newCertSource(cfg, domains.Active, log)
	if err != nil {
		return err
	}
	certs.SetDomains(domains.Active, domains.List)
	masq, err := vpn.Masquerade(cfg.Masquerade)
	if err != nil {
		return err
	}
	mgr := vpn.NewManager(st, policy, log)
	hy, err := vpn.NewServer(cfg.Listen, "", mgr, certs, masq)
	if err != nil {
		return err
	}
	var hyObfs server.Server
	obfsPassword := cfg.ObfsPassword
	if cfg.ObfsListen != "" {
		if obfsPassword == "" {
			if obfsPassword, err = st.ObfsPassword(func() string { return web.RandomPassword(24) }); err != nil {
				return err
			}
		}
		if hyObfs, err = vpn.NewServer(cfg.ObfsListen, obfsPassword, mgr, certs, masq); err != nil {
			return err
		}
	}

	panel := web.New(web.Options{
		Version: version, Store: st, Manager: mgr, Certs: certs, Policy: policy,
		PublicPort: cfg.PublicPort, Listen: cfg.Listen, ObfsPort: cfg.ObfsPublicPort, ObfsPassword: obfsPassword,
		TrustedProxies: cfg.TrustedProxies, SecureCookies: cfg.SecureCookies, Log: log,
	})
	httpSrv := &http.Server{Addr: cfg.WebListen, Handler: panel, ReadHeaderTimeout: 10 * time.Second}

	stop := make(chan struct{})
	flushed := make(chan struct{})
	go func() { mgr.Run(stop); close(flushed) }()

	errc := make(chan error, 3)
	go func() { errc <- fmt.Errorf("vpn: %w", hy.Serve()) }()
	if hyObfs != nil {
		go func() { errc <- fmt.Errorf("obfuscated vpn: %w", hyObfs.Serve()) }()
	}
	go func() { errc <- fmt.Errorf("panel: %w", httpSrv.ListenAndServe()) }()
	log.Info("hysui started", "version", version, "vpn", cfg.Listen+"/udp", "panel", cfg.WebListen,
		"domain", domains.Active, "tls", cfg.TLSMode, "users", len(st.Users()), "obfuscated", cfg.ObfsListen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Info("shutting down", "signal", s.String())
		err = nil
	case err = <-errc:
		log.Error("stopped", "err", err)
	}
	close(stop)
	<-flushed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	_ = hy.Close()
	if hyObfs != nil {
		_ = hyObfs.Close()
	}
	return err
}

// newCertSource creates the certificate source; domain names a self-signed certificate.
func newCertSource(cfg *config.Config, domain string, log *slog.Logger) (vpn.CertSource, error) {
	switch cfg.TLSMode {
	case config.TLSFile:
		return vpn.NewFileCert(cfg.TLSCert, cfg.TLSKey)
	case config.TLSSelfSigned:
		return vpn.NewSelfSigned(filepath.Join(cfg.DataDir, "tls"), domain)
	default:
		challenge := strings.TrimPrefix(cfg.TLSMode, "acme-")
		return vpn.NewACME(vpn.ACMEOptions{
			Email: cfg.ACMEEmail, CA: cfg.ACMECA, Challenge: challenge,
			AltPort: cfg.ACMEAltPort, Dir: filepath.Join(cfg.DataDir, "acme"),
		}, log)
	}
}

// initDomains adds HYSUI_DOMAIN as the first domain on first start. After that the
// panel manages domains and HYSUI_DOMAIN is ignored.
func initDomains(st *store.Store, env string, log *slog.Logger) (store.Domains, error) {
	d := st.Domains()
	if d.Active != "" {
		if n, _ := store.NormalizeDomain(env); env != "" && n != d.Active {
			log.Warn("HYSUI_DOMAIN only sets the first domain; change domains in the panel (Domains)",
				"HYSUI_DOMAIN", env, "active", d.Active)
		}
		return d, nil
	}
	if env == "" {
		return d, errors.New("HYSUI_DOMAIN is required on first start (the public hostname clients connect to)")
	}
	if _, err := st.AddDomain(env); err != nil {
		return d, fmt.Errorf("HYSUI_DOMAIN: %w", err)
	}
	return st.Domains(), nil
}

// bootstrapAdmin creates the panel login on first start.
func bootstrapAdmin(st *store.Store, cfg *config.Config) error {
	if st.Admin().Username != "" {
		return nil
	}
	pass, generated := cfg.AdminPassword, false
	if pass == "" {
		pass, generated = web.RandomPassword(16), true
	}
	hash, err := web.HashPassword(pass)
	if err != nil {
		return err
	}
	if err := st.SetAdmin(store.Admin{Username: cfg.AdminUser, PasswordHash: hash}); err != nil {
		return err
	}
	if generated {
		printCredentials("First start: panel login created", cfg.AdminUser, pass)
	}
	return nil
}

func printCredentials(title, user, pass string) {
	fmt.Fprintf(os.Stderr, "\n==================================================\n %s\n   username: %s\n   password: %s\n Change it in the panel: Admin > Change login\n==================================================\n\n", title, user, pass)
}

func resetAdmin(args []string) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	user := st.Admin().Username
	if len(args) > 0 {
		user = args[0]
	}
	if user == "" {
		user = "admin"
	}
	pass := web.RandomPassword(16)
	hash, err := web.HashPassword(pass)
	if err != nil {
		return err
	}
	if err := st.SetAdmin(store.Admin{Username: user, PasswordHash: hash}); err != nil {
		return err
	}
	printCredentials("Panel login reset", user, pass)
	return nil
}

func importHysteria(args []string) error {
	fs := flag.NewFlagSet("import-hysteria", flag.ContinueOnError)
	home := fs.Bool("home", false, "give imported users home-network access")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hysui import-hysteria [-home] /etc/hysteria/config.yaml")
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var hc struct {
		Auth struct {
			Type     string            `yaml:"type"`
			UserPass map[string]string `yaml:"userpass"`
		} `yaml:"auth"`
	}
	if err := yaml.Unmarshal(b, &hc); err != nil {
		return err
	}
	if !strings.EqualFold(hc.Auth.Type, "userpass") || len(hc.Auth.UserPass) == 0 {
		return errors.New("no auth.userpass users in that file")
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	var failed int
	for name, pass := range hc.Auth.UserPass {
		err := st.Add(store.User{Name: name, Password: pass, Enabled: true, HomeAccess: *home, Note: "imported from Hysteria"})
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", name, err)
			continue
		}
		fmt.Printf("imported %s (home network: %v)\n", name, *home)
	}
	if failed > 0 {
		return fmt.Errorf("%d user(s) not imported", failed)
	}
	return nil
}

func healthcheck() error {
	listen := os.Getenv("HYSUI_WEB_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
