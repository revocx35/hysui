package config

import (
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := FromEnv(envMap(map[string]string{"HYSUI_DOMAIN": "vpn.example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":443" || c.PublicPort != 443 || c.TLSMode != TLSACMEHTTP || c.WebListen != ":8080" ||
		c.DataDir != "/data" || c.AdminUser != "admin" || !c.DetectLocal || len(c.TrustedProxies) != 0 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestOverrides(t *testing.T) {
	c, err := FromEnv(envMap(map[string]string{
		"HYSUI_DOMAIN":          "vpn.example.com",
		"HYSUI_LISTEN":          ":8443",
		"HYSUI_PUBLIC_PORT":     "443",
		"HYSUI_TLS_MODE":        "self-signed",
		"HYSUI_HOME_EXTRA":      "203.0.113.0/24, 198.51.100.7",
		"HYSUI_TRUSTED_PROXIES": "192.168.1.20",
		"HYSUI_DETECT_LOCAL":    "false",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicPort != 443 || len(c.HomeExtra) != 2 || c.DetectLocal || len(c.TrustedProxies) != 1 {
		t.Fatalf("unexpected: %+v", c)
	}
	c, err = FromEnv(envMap(map[string]string{"HYSUI_DOMAIN": "x", "HYSUI_TRUSTED_PROXIES": "private"}))
	if err != nil || len(c.TrustedProxies) != 6 {
		t.Fatalf("private keyword: %v %v", c.TrustedProxies, err)
	}
}

func TestErrors(t *testing.T) {
	_, err := FromEnv(envMap(map[string]string{
		"HYSUI_TLS_MODE":       "file",
		"HYSUI_LISTEN":         "nope",
		"HYSUI_HOME_EXTRA":     "bogus",
		"HYSUI_ADMIN_PASSWORD": "short",
	}))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"HYSUI_DOMAIN", "HYSUI_LISTEN", "HYSUI_TLS_CERT", "HYSUI_HOME_EXTRA", "HYSUI_ADMIN_PASSWORD"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing error about %s in: %v", want, err)
		}
	}
}
