// Package store persists the admin account and VPN users in a JSON file.
//
// Writes go to a temporary file that is renamed over the old one, so a crash never
// leaves a half-written file behind.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

var (
	ErrNotFound = errors.New("user not found")
	ErrExists   = errors.New("user already exists")

	ErrDomainNotFound = errors.New("domain not found")
	ErrDomainExists   = errors.New("domain already added")
	ErrDomainActive   = errors.New("the active domain cannot be removed; make another domain active first")
)

// MaxDomains limits the domain list (each one is a certificate to obtain and renew).
const MaxDomains = 20

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)
	passRe = regexp.MustCompile(`^[A-Za-z0-9_.~-]{8,128}$`)
)

// User is a VPN user. A client authenticates with "Name:Password", the same format
// as Hysteria's own userpass auth, so existing client links keep working after import.
type User struct {
	Name       string    `json:"name"`
	Password   string    `json:"password"`
	Enabled    bool      `json:"enabled"`
	HomeAccess bool      `json:"homeAccess"`
	DownMbps   float64   `json:"downMbps"`   // server -> client; 0 = unlimited
	UpMbps     float64   `json:"upMbps"`     // client -> server; 0 = unlimited
	QuotaBytes int64     `json:"quotaBytes"` // tx+rx; 0 = unlimited
	UsedTx     int64     `json:"usedTx"`     // bytes uploaded by the client
	UsedRx     int64     `json:"usedRx"`     // bytes downloaded by the client
	Note       string    `json:"note,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}

// Validate checks the user's fields.
func (u *User) Validate() error {
	if !nameRe.MatchString(u.Name) {
		return errors.New("name must be 1-32 characters: letters, digits, _ . -")
	}
	// Restricted to URL-safe characters so share links never need escaping, which
	// some client apps decode inconsistently.
	if !passRe.MatchString(u.Password) {
		return errors.New("password must be 8-128 characters: letters, digits, _ . ~ -")
	}
	if u.DownMbps < 0 || u.UpMbps < 0 || u.DownMbps > 100000 || u.UpMbps > 100000 {
		return errors.New("speed limits must be between 0 and 100000 Mbps")
	}
	if u.QuotaBytes < 0 {
		return errors.New("quota must not be negative")
	}
	if len(u.Note) > 200 {
		return errors.New("note must be at most 200 characters")
	}
	return nil
}

// Admin is the panel login.
type Admin struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
}

// Domains are the hostnames clients connect to. Active is the one written into share
// links. The others keep their certificates, so devices set up with them still work.
type Domains struct {
	Active string   `json:"active"`
	List   []string `json:"list"` // includes Active
}

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomain lower-cases a hostname, converts an international name to its
// xn-- form and checks it. IP addresses are accepted as they are.
func NormalizeDomain(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.String(), nil
	}
	const msg = "enter a hostname such as vpn.example.com"
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", errors.New(msg)
	}
	for _, l := range strings.Split(ascii, ".") {
		if !labelRe.MatchString(l) {
			return "", errors.New(msg)
		}
	}
	return ascii, nil
}

type data struct {
	Version int     `json:"version"`
	Admin   Admin   `json:"admin"`
	Domains Domains `json:"domains,omitzero"`
	Obfs    string  `json:"obfsPassword,omitempty"`
	Users   []User  `json:"users"`
}

// Store is a concurrency-safe, file-backed user database.
type Store struct {
	path string
	mu   sync.RWMutex
	d    data
}

// Open loads the store at path, creating an empty one if it does not exist.
func Open(path string) (*Store, error) {
	s := &Store{path: path, d: data{Version: 1}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".hysui-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// Admin returns the admin account.
func (s *Store) Admin() Admin {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.d.Admin
}

// SetAdmin replaces the admin account.
func (s *Store) SetAdmin(a Admin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.d.Admin
	s.d.Admin = a
	if err := s.saveLocked(); err != nil {
		s.d.Admin = old
		return err
	}
	return nil
}

// ObfsPassword returns the Salamander obfuscation password, generating and saving
// one with gen on first use.
func (s *Store) ObfsPassword(gen func() string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.Obfs != "" {
		return s.d.Obfs, nil
	}
	s.d.Obfs = gen()
	if err := s.saveLocked(); err != nil {
		s.d.Obfs = ""
		return "", err
	}
	return s.d.Obfs, nil
}

// Domains returns the domain list.
func (s *Store) Domains() Domains {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Domains{Active: s.d.Domains.Active, List: slices.Clone(s.d.Domains.List)}
}

// AddDomain adds a domain and returns its normalized name. The first domain added
// becomes the active one.
func (s *Store) AddDomain(name string) (string, error) {
	name, err := NormalizeDomain(name)
	if err != nil {
		return "", err
	}
	return name, s.updateDomains(func(d *Domains) error {
		if slices.Contains(d.List, name) {
			return ErrDomainExists
		}
		if len(d.List) >= MaxDomains {
			return fmt.Errorf("at most %d domains", MaxDomains)
		}
		d.List = append(d.List, name)
		if d.Active == "" {
			d.Active = name
		}
		return nil
	})
}

// SetActiveDomain makes name the domain written into share links.
func (s *Store) SetActiveDomain(name string) error {
	return s.updateDomains(func(d *Domains) error {
		if !slices.Contains(d.List, name) {
			return ErrDomainNotFound
		}
		d.Active = name
		return nil
	})
}

// DeleteDomain removes a domain other than the active one.
func (s *Store) DeleteDomain(name string) error {
	return s.updateDomains(func(d *Domains) error {
		i := slices.Index(d.List, name)
		switch {
		case i < 0:
			return ErrDomainNotFound
		case name == d.Active:
			return ErrDomainActive
		}
		d.List = slices.Delete(d.List, i, i+1)
		return nil
	})
}

func (s *Store) updateDomains(fn func(d *Domains) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.d.Domains
	d := Domains{Active: old.Active, List: slices.Clone(old.List)}
	if err := fn(&d); err != nil {
		return err
	}
	s.d.Domains = d
	if err := s.saveLocked(); err != nil {
		s.d.Domains = old
		return err
	}
	return nil
}

// Users returns a copy of all users, sorted by name.
func (s *Store) Users() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := slices.Clone(s.d.Users)
	slices.SortFunc(out, func(a, b User) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out
}

// User returns the named user.
func (s *Store) User(name string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i := s.indexLocked(name)
	if i < 0 {
		return User{}, false
	}
	return s.d.Users[i], true
}

func (s *Store) indexLocked(name string) int {
	return slices.IndexFunc(s.d.Users, func(u User) bool { return u.Name == name })
}

// Add inserts a new user.
func (s *Store) Add(u User) error {
	if err := u.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.indexLocked(u.Name) >= 0 {
		return ErrExists
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	s.d.Users = append(s.d.Users, u)
	if err := s.saveLocked(); err != nil {
		s.d.Users = s.d.Users[:len(s.d.Users)-1]
		return err
	}
	return nil
}

// Update applies fn to the named user and saves. The name cannot be changed.
func (s *Store) Update(name string, fn func(u *User) error) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.indexLocked(name)
	if i < 0 {
		return User{}, ErrNotFound
	}
	u := s.d.Users[i]
	if err := fn(&u); err != nil {
		return User{}, err
	}
	u.Name = name
	if err := u.Validate(); err != nil {
		return User{}, err
	}
	old := s.d.Users[i]
	s.d.Users[i] = u
	if err := s.saveLocked(); err != nil {
		s.d.Users[i] = old
		return User{}, err
	}
	return u, nil
}

// Delete removes the named user.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.indexLocked(name)
	if i < 0 {
		return ErrNotFound
	}
	old := slices.Clone(s.d.Users)
	s.d.Users = slices.Delete(s.d.Users, i, i+1)
	if err := s.saveLocked(); err != nil {
		s.d.Users = old
		return err
	}
	return nil
}

// Usage is a user's traffic totals.
type Usage struct{ Tx, Rx int64 }

// SetUsage stores traffic totals for many users in one write. Unknown users are skipped.
func (s *Store) SetUsage(usage map[string]Usage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for i := range s.d.Users {
		u, ok := usage[s.d.Users[i].Name]
		if !ok || (u.Tx == s.d.Users[i].UsedTx && u.Rx == s.d.Users[i].UsedRx) {
			continue
		}
		s.d.Users[i].UsedTx, s.d.Users[i].UsedRx = u.Tx, u.Rx
		changed = true
	}
	if !changed {
		return nil
	}
	return s.saveLocked()
}
