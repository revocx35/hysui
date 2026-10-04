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

// CertSource provides the server certificate and reports its state.
type CertSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Status() CertStatus
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

func (f *fileCert) Status() CertStatus {
	c, err := f.load(false)
	return statusOf("file", c, err)
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

func (s *selfSigned) Status() CertStatus { return statusOf("self-signed", &s.cert, nil) }
func (s *selfSigned) PinSHA256() string  { return s.pin }

// ---- ACME ----

// ACMEOptions configures Let's Encrypt (or another ACME CA).
type ACMEOptions struct {
	Domain    string
	Email     string
	CA        string // "letsencrypt", "letsencrypt-staging" or a directory URL
	Challenge string // "http" or "tls"
	AltPort   int    // local port for the challenge listener (0 = 80 / 443)
	Dir       string // certificate storage
}

type acmeCert struct {
	cfg    *certmagic.Config
	cache  *certmagic.Cache
	domain string
	mode   string

	mu  sync.Mutex
	err error
}

// NewACME obtains and renews a certificate in the background. The VPN can start
// right away; handshakes fail until the first certificate arrives.
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
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return cfg, nil },
		Logger:           zl,
	})
	a := &acmeCert{cfg: certmagic.New(cache, *cfg), cache: cache, domain: o.Domain, mode: "acme-" + o.Challenge}
	go a.manage(log)
	return a, nil
}

func (a *acmeCert) manage(log *slog.Logger) {
	for delay := time.Minute; ; delay = min(delay*2, time.Hour) {
		err := a.cfg.ManageSync(context.Background(), []string{a.domain})
		a.mu.Lock()
		a.err = err
		a.mu.Unlock()
		if err == nil {
			log.Info("certificate ready", "domain", a.domain)
			return // certmagic renews from here on
		}
		log.Error("obtaining certificate failed, will retry", "domain", a.domain, "in", delay, "err", err)
		time.Sleep(delay)
	}
}

func (a *acmeCert) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Clients may connect by IP or with another SNI; always serve our domain's cert.
	h := *hello
	h.ServerName = a.domain
	return a.cfg.GetCertificate(&h)
}

func (a *acmeCert) Status() CertStatus {
	a.mu.Lock()
	err := a.err
	a.mu.Unlock()
	// Read the cache directly: GetCertificate needs a live handshake (it dereferences
	// the connection) and may start network activity.
	var c *tls.Certificate
	for _, mc := range a.cache.AllMatchingCertificates(a.domain) {
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
