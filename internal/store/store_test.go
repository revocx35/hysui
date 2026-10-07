package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "hysui.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("store file not created with 0600: %v %v", fi, err)
	}

	u := User{Name: "iphone", Password: "secretpassword", Enabled: true, DownMbps: 20}
	if err := s.Add(u); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(u); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate add: %v", err)
	}
	if err := s.Add(User{Name: "bad name", Password: "secretpassword"}); err == nil {
		t.Fatal("invalid name accepted")
	}
	if err := s.Add(User{Name: "short", Password: "short"}); err == nil {
		t.Fatal("short password accepted")
	}

	if _, err := s.Update("iphone", func(u *User) error { u.HomeAccess = true; u.Name = "renamed"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUsage(map[string]Usage{"iphone": {Tx: 10, Rx: 20}, "ghost": {Tx: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAdmin(Admin{Username: "admin", PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.User("iphone")
	if !ok || !got.HomeAccess || got.UsedTx != 10 || got.UsedRx != 20 || got.CreatedAt.IsZero() {
		t.Fatalf("reloaded user = %+v", got)
	}
	if _, ok := s2.User("renamed"); ok {
		t.Fatal("update must not rename")
	}
	if s2.Admin().Username != "admin" {
		t.Fatal("admin not persisted")
	}

	if err := s2.Delete("iphone"); err != nil {
		t.Fatal(err)
	}
	if err := s2.Delete("iphone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if len(s2.Users()) != 0 {
		t.Fatal("user not deleted")
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".hysui-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}

func TestUpdateValidationKeepsOldValue(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "hysui.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(User{Name: "a", Password: "secretpassword"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update("a", func(u *User) error { u.DownMbps = -1; return nil }); err == nil {
		t.Fatal("negative limit accepted")
	}
	if u, _ := s.User("a"); u.DownMbps != 0 {
		t.Fatal("failed update changed the user")
	}
}

func TestDomains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hysui.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		" VPN.Example.com. ": "vpn.example.com",
		"bücher.example":     "xn--bcher-kva.example",
		"203.0.113.7":        "203.0.113.7",
		"2001:DB8::1":        "2001:db8::1",
	} {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "https://vpn.example.com", "vpn.example.com/x", "bad_name.com", "-a.com", "a..com", "a b.com", "fe80::1%eth0"} {
		if got, err := NormalizeDomain(bad); err == nil {
			t.Errorf("NormalizeDomain(%q) accepted as %q", bad, got)
		}
	}

	if name, err := s.AddDomain("VPN.example.com"); err != nil || name != "vpn.example.com" {
		t.Fatalf("add: %q %v", name, err)
	}
	if d := s.Domains(); d.Active != "vpn.example.com" {
		t.Fatalf("first domain did not become active: %+v", d)
	}
	if _, err := s.AddDomain("vpn.example.com"); !errors.Is(err, ErrDomainExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.AddDomain("backup.example.net"); err != nil {
		t.Fatal(err)
	}
	if d := s.Domains(); d.Active != "vpn.example.com" || len(d.List) != 2 {
		t.Fatalf("second domain changed the active one: %+v", d)
	}
	if err := s.DeleteDomain("vpn.example.com"); !errors.Is(err, ErrDomainActive) {
		t.Fatalf("delete active: %v", err)
	}
	if err := s.SetActiveDomain("ghost.example.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("activate unknown: %v", err)
	}
	if err := s.SetActiveDomain("backup.example.net"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDomain("vpn.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDomain("vpn.example.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("second delete: %v", err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if d := s2.Domains(); d.Active != "backup.example.net" || len(d.List) != 1 || d.List[0] != "backup.example.net" {
		t.Fatalf("reloaded domains = %+v", d)
	}
	for i := len(s2.Domains().List); i < MaxDomains; i++ {
		if _, err := s2.AddDomain(fmt.Sprintf("d%d.example.com", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s2.AddDomain("one-too-many.example.com"); err == nil {
		t.Fatal("domain limit not enforced")
	}
}

func TestObfsPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hysui.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	gen := func() string { calls++; return "generated-password" }
	if p, err := s.ObfsPassword(gen); err != nil || p != "generated-password" {
		t.Fatalf("first: %q %v", p, err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := s2.ObfsPassword(gen); p != "generated-password" || calls != 1 {
		t.Fatalf("not persisted: %q, generated %d times", p, calls)
	}
}
