package store

import (
	"errors"
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
