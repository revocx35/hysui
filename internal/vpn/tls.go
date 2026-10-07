package vpn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// CertSource provides the server certificate for each domain and reports its state.
type CertSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// SetDomains sets the domains clients connect to. Handshakes for any other name
	// (or none, or an IP) get the active domain's certificate.
	SetDomains(active string, all []string)
	// Status describes the certificate served for domain.
	Status(domain string) CertStatus
	// PinSHA256 is the hex SHA-256 of the certificate for clients to pin, or "" when
	// the certificate is publicly trusted.
	PinSHA256() string
}

// CertStatus describes the current certificate.
type CertStatus struct {
	Mode     string    `json:"mode"`
	State    string    `json:"state"` // "ok", "pending" or "error"
	Error    string    `json:"error,omitempty"`
	NotAfter time.Time `json:"notAfter,omitzero"`
}

// ---- files ----

type fileCert struct {
	certPath, keyPath string

	mu      sync.Mutex
	cert    *tls.Certificate
	mtime   time.Time
	checked time.Time
	err     error
}

// NewFileCert serves a certificate from PEM files and reloads them when they change,
// so certificates renewed by another tool are picked up without a restart.
func NewFileCert(certPath, keyPath string) (CertSource, error) {
	f := &fileCert{certPath: certPath, keyPath: keyPath}
	if _, err := f.load(true); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *fileCert) load(force bool) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !force && time.Since(f.checked) < 30*time.Second {
		return f.cert, f.err
	}
	f.checked = time.Now()
	fi, err := os.Stat(f.certPath)
	if err != nil {
		f.err = err
		return f.cert, err
	}
	if f.cert != nil && fi.ModTime().Equal(f.mtime) {
		return f.cert, nil
	}
	c, err := tls.LoadX509KeyPair(f.certPath, f.keyPath)
	if err != nil {
		f.err = err
		return f.cert, err
	}
	f.cert, f.mtime, f.err = &c, fi.ModTime(), nil
	return f.cert, nil
}

func (f *fileCert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c, err := f.load(false)
	if c == nil {
		return nil, err
	}
	return c, nil
}

// SetDomains does nothing: the files decide which names are covered.
func (f *fileCert) SetDomains(string, []string) {}

func (f *fileCert) Status(domain string) CertStatus {
	c, err := f.load(false)
	s := statusOf("file", c, err)
	if s.State == "ok" && c.Leaf != nil && c.Leaf.VerifyHostname(domain) != nil {
		s.State, s.Error = "error", "the certificate does not cover "+domain
	}
	return s
}

func (f *fileCert) PinSHA256() string { return "" }

func statusOf(mode string, c *tls.Certificate, err error) CertStatus {
	s := CertStatus{Mode: mode, State: "ok"}
	if c != nil && c.Leaf != nil {
		s.NotAfter = c.Leaf.NotAfter
	}
	switch {
	case err != nil:
		s.State, s.Error = "error", err.Error()
	case c == nil:
		s.State = "pending"
	}
	return s
}

// ---- self-signed ----

type selfSigned struct {
	cert tls.Certificate
	pin  string
}

// NewSelfSigned loads or creates a self-signed certificate for domain in dir.
// Clients must pin it (share links include pinSHA256 and insecure=1).
func NewSelfSigned(dir, domain string) (CertSource, error) {
	certPath, keyPath := filepath.Join(dir, "self-signed.crt"), filepath.Join(dir, "self-signed.key")
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		if err := writeSelfSigned(certPath, keyPath, domain); err != nil {
			return nil, err
		}
	}
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c.Certificate[0])
	return &selfSigned{cert: c, pin: hex.EncodeToString(sum[:])}, nil
}

func writeSelfSigned(certPath, keyPath, domain string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func (s *selfSigned) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &s.cert, nil
}

// SetDomains does nothing: clients pin the certificate, so its names don't matter.
func (s *selfSigned) SetDomains(string, []string) {}

func (s *selfSigned) Status(string) CertStatus { return statusOf("self-signed", &s.cert, nil) }
func (s *selfSigned) PinSHA256() string        { return s.pin }

// ---- ACME ----

// ACMEOptions configures Let's Encrypt (or another ACME CA).
type ACMEOptions struct {
	Email     string
	CA        string // "letsencrypt", "letsencrypt-staging" or a directory URL
	Challenge string // "http" or "tls"
	AltPort   int    // local port for the challenge listener (0 = 80 / 443)
	Dir       string // certificate storage
}

type acmeCert struct {
	cfg   *certmagic.Config
	cache *certmagic.Cache
	mode  string
	log   *slog.Logger
	// obtain lets one domain at a time talk to the CA. Concurrent first-time account
	// registrations race inside certmagic (its email prompt writes package globals).
	obtain chan struct{}

	mu      sync.Mutex
	active  string
	domains map[string]*acmeDomain
}

// acmeDomain is the background job that obtains one domain's certificate.
type acmeDomain struct {
	stop context.CancelFunc
	err  error // last failure; guarded by acmeCert.mu
}

// NewACME obtains and renews certificates in the background for the domains passed
// to SetDomains. The VPN can start right away; handshakes for a domain fail until
// its first certificate arrives.
// The storage layout is certmagic's, the same as Hysteria's built-in ACME, so an
// existing Hysteria ACME directory can be reused without requesting a new certificate.
func NewACME(o ACMEOptions, log *slog.Logger) (CertSource, error) {
	zl := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()), zapcore.Lock(os.Stderr), zap.InfoLevel,
	)).Named("acme")
	cfg := &certmagic.Config{
		RenewalWindowRatio: certmagic.DefaultRenewalWindowRatio,
		KeySource:          certmagic.DefaultKeyGenerator,
		Storage:            &certmagic.FileStorage{Path: o.Dir},
		Logger:             zl,
	}
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{Email: o.Email, Agreed: true, Logger: zl})
	switch strings.ToLower(o.CA) {
	case "", "letsencrypt", "le":
		issuer.CA = certmagic.LetsEncryptProductionCA
	case "letsencrypt-staging", "staging":
		issuer.CA = certmagic.LetsEncryptStagingCA
	default:
		if !strings.HasPrefix(o.CA, "https://") {
			return nil, fmt.Errorf("unsupported ACME CA %q", o.CA)
		}
		issuer.CA = o.CA
	}
	switch o.Challenge {
	case "http":
		issuer.DisableTLSALPNChallenge = true
		issuer.AltHTTPPort = o.AltPort
	case "tls":
		issuer.DisableHTTPChallenge = true
		issuer.AltTLSALPNPort = o.AltPort
	default:
		return nil, fmt.Errorf("unsupported ACME challenge %q", o.Challenge)
	}
	cfg.Issuers = []certmagic.Issuer{issuer}
	a := &acmeCert{
		mode: "acme-" + o.Challenge, log: log, obtain: make(chan struct{}, 1), domains: map[string]*acmeDomain{},
	}
	a.cache = certmagic.NewCache(certmagic.CacheOptions{GetConfigForCert: a.configForCert, Logger: zl})
	a.cfg = certmagic.New(a.cache, *cfg)
	return a, nil
}

// configForCert gives certmagic's maintenance (renewals, OCSP) the config bound to
// our cache. It rejects any other config, and certificates then never renew.
func (a *acmeCert) configForCert(certmagic.Certificate) (*certmagic.Config, error) {
	return a.cfg, nil
}

// SetDomains starts obtaining certificates for new domains and stops renewing the
// certificates of removed ones. Their files stay on disk, so adding a domain back
// is instant.
func (a *acmeCert) SetDomains(active string, all []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active = active
	keep := map[string]bool{}
	for _, d := range all {
		keep[d] = true
		if a.domains[d] == nil {
			ctx, cancel := context.WithCancel(context.Background())
			ad := &acmeDomain{stop: cancel}
			a.domains[d] = ad
			go a.manage(ctx, d, ad)
		}
	}
	for d, ad := range a.domains {
		if !keep[d] {
			ad.stop()
			delete(a.domains, d)
			a.cache.RemoveManaged([]certmagic.SubjectIssuer{{Subject: d}})
		}
	}
}

func (a *acmeCert) manage(ctx context.Context, domain string, ad *acmeDomain) {
	for delay := time.Minute; ; delay = min(delay*2, time.Hour) {
		select {
		case a.obtain <- struct{}{}:
		case <-ctx.Done():
			return
		}
		err := a.cfg.ManageSync(ctx, []string{domain})
		<-a.obtain
		a.mu.Lock()
		if cur := a.domains[domain]; cur != ad {
			// Removed while we were busy. Don't leave its certificate in maintenance,
			// unless it has been added back and a new job owns it.
			if cur == nil {
				a.cache.RemoveManaged([]certmagic.SubjectIssuer{{Subject: domain}})
			}
			a.mu.Unlock()
			return
		}
		ad.err = err
		a.mu.Unlock()
		if err == nil {
			a.log.Info("certificate ready", "domain", domain)
			return // certmagic renews from here on
		}
		a.log.Error("obtaining certificate failed, will retry", "domain", domain, "in", delay, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (a *acmeCert) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Clients may connect by IP or with an unknown SNI; serve the active domain's cert then.
	name := strings.ToLower(hello.ServerName)
	a.mu.Lock()
	if a.domains[name] == nil {
		name = a.active
	}
	a.mu.Unlock()
	h := *hello
	h.ServerName = name
	return a.cfg.GetCertificate(&h)
}

func (a *acmeCert) Status(domain string) CertStatus {
	var err error
	a.mu.Lock()
	if ad := a.domains[domain]; ad != nil {
		err = ad.err
	}
	a.mu.Unlock()
	// Read the cache directly: GetCertificate needs a live handshake (it dereferences
	// the connection) and may start network activity.
	var c *tls.Certificate
	for _, mc := range a.cache.AllMatchingCertificates(domain) {
		if c == nil || mc.Leaf.NotAfter.After(c.Leaf.NotAfter) {
			c = &mc.Certificate
		}
	}
	if c != nil {
		err = nil // a usable certificate beats an old error
	}
	return statusOf(a.mode, c, err)
}

func (a *acmeCert) PinSHA256() string { return "" }
