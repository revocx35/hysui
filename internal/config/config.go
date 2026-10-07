// Package config reads hysui's settings from environment variables.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/revocx35/hysui/internal/netpolicy"
)

// TLS modes.
const (
	TLSACMEHTTP   = "acme-http"
	TLSACMETLS    = "acme-tls"
	TLSFile       = "file"
	TLSSelfSigned = "self-signed"
)

// Config holds all settings.
type Config struct {
	Domain     string // first domain on first start; the panel manages domains after that
	Listen     string // UDP address of the VPN
	PublicPort int    // UDP port in share links (if the router maps a different port)

	TLSMode     string
	ACMEEmail   string
	ACMECA      string
	ACMEAltPort int
	TLSCert     string
	TLSKey      string
	Masquerade  string
	HomeExtra   []netip.Prefix
	DetectLocal bool

	WebListen      string
	TrustedProxies []netip.Prefix
	SecureCookies  string // "auto", "true" or "false"

	DataDir       string
	AdminUser     string
	AdminPassword string
	LogLevel      string
}

// FromEnv reads the configuration using getenv (usually os.Getenv).
func FromEnv(getenv func(string) string) (*Config, error) {
	env := func(key, def string) string {
		if v := strings.TrimSpace(getenv("HYSUI_" + key)); v != "" {
			return v
		}
		return def
	}
	c := &Config{
		Domain:        env("DOMAIN", ""),
		Listen:        env("LISTEN", ":443"),
		TLSMode:       strings.ToLower(env("TLS_MODE", TLSACMEHTTP)),
		ACMEEmail:     env("ACME_EMAIL", ""),
		ACMECA:        env("ACME_CA", "letsencrypt"),
		TLSCert:       env("TLS_CERT", ""),
		TLSKey:        env("TLS_KEY", ""),
		Masquerade:    env("MASQUERADE_URL", ""),
		WebListen:     env("WEB_LISTEN", ":8080"),
		SecureCookies: strings.ToLower(env("SECURE_COOKIES", "auto")),
		DataDir:       env("DATA_DIR", "/data"),
		AdminUser:     env("ADMIN_USER", "admin"),
		AdminPassword: env("ADMIN_PASSWORD", ""),
		LogLevel:      strings.ToLower(env("LOG_LEVEL", "info")),
	}
	var errs []error
	_, lp, err := net.SplitHostPort(c.Listen)
	if err != nil {
		errs = append(errs, fmt.Errorf("HYSUI_LISTEN: %w", err))
	}
	c.PublicPort, err = strconv.Atoi(env("PUBLIC_PORT", lp))
	if err != nil || c.PublicPort < 1 || c.PublicPort > 65535 {
		errs = append(errs, errors.New("HYSUI_PUBLIC_PORT must be a port number"))
	}
	switch c.TLSMode {
	case TLSACMEHTTP, TLSACMETLS, TLSSelfSigned:
	case TLSFile:
		if c.TLSCert == "" || c.TLSKey == "" {
			errs = append(errs, errors.New("HYSUI_TLS_MODE=file needs HYSUI_TLS_CERT and HYSUI_TLS_KEY"))
		}
	default:
		errs = append(errs, fmt.Errorf("HYSUI_TLS_MODE %q: use acme-http, acme-tls, file or self-signed", c.TLSMode))
	}
	if v := env("ACME_ALT_PORT", ""); v != "" {
		if c.ACMEAltPort, err = strconv.Atoi(v); err != nil {
			errs = append(errs, errors.New("HYSUI_ACME_ALT_PORT must be a port number"))
		}
	}
	if c.HomeExtra, err = netpolicy.ParsePrefixes(splitList(env("HOME_EXTRA", ""))); err != nil {
		errs = append(errs, fmt.Errorf("HYSUI_HOME_EXTRA: %w", err))
	}
	c.DetectLocal = env("DETECT_LOCAL", "true") != "false"
	if c.TrustedProxies, err = parseProxies(env("TRUSTED_PROXIES", "")); err != nil {
		errs = append(errs, fmt.Errorf("HYSUI_TRUSTED_PROXIES: %w", err))
	}
	switch c.SecureCookies {
	case "auto", "true", "false":
	default:
		errs = append(errs, errors.New("HYSUI_SECURE_COOKIES must be auto, true or false"))
	}
	if c.AdminPassword != "" && len(c.AdminPassword) < 10 {
		errs = append(errs, errors.New("HYSUI_ADMIN_PASSWORD must be at least 10 characters"))
	}
	return c, errors.Join(errs...)
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}

// parseProxies accepts CIDRs/IPs and the keyword "private" (all private ranges).
func parseProxies(s string) ([]netip.Prefix, error) {
	var items []string
	for _, it := range splitList(s) {
		if strings.EqualFold(it, "private") {
			items = append(items, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "127.0.0.0/8", "::1/128")
			continue
		}
		items = append(items, it)
	}
	return netpolicy.ParsePrefixes(items)
}
