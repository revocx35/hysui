// Package netpolicy decides which destinations count as the "home network".
//
// Every destination falls into one of three classes:
//   - Forbidden: never reachable through the VPN (loopback, unspecified, multicast).
//   - Home: private/LAN ranges, the server's own addresses and the IPv6 prefixes it sits in.
//     Only users with home-network access may reach these.
//   - Internet: everything else.
package netpolicy

import (
	"net"
	"net/netip"
	"slices"
	"sync"
)

type Class int

const (
	Internet Class = iota
	Home
	Forbidden
)

func (c Class) String() string {
	switch c {
	case Home:
		return "home"
	case Forbidden:
		return "forbidden"
	default:
		return "internet"
	}
}

// DefaultForbidden are ranges no VPN user may reach. Loopback is here (not in Home)
// because it would expose services bound to the server's localhost, such as the panel.
var DefaultForbidden = mustPrefixes(
	"0.0.0.0/8",
	"127.0.0.0/8",
	"224.0.0.0/4",
	"255.255.255.255/32",
	"::/128",
	"::1/128",
	"ff00::/8",
)

// DefaultHome are the standard private and link-local ranges.
var DefaultHome = mustPrefixes(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"100.64.0.0/10",
	"fc00::/7",
	"fe80::/10",
)

// Policy classifies destination addresses. It is safe for concurrent use.
type Policy struct {
	forbidden []netip.Prefix
	home      []netip.Prefix // static home ranges (defaults + user extras)

	mu    sync.RWMutex
	local []netip.Prefix // detected from the server's interfaces, refreshed periodically
}

// New returns a policy with the given forbidden and home ranges.
func New(forbidden, home []netip.Prefix) *Policy {
	return &Policy{forbidden: slices.Clone(forbidden), home: slices.Clone(home)}
}

// NewDefault returns the production policy: default ranges plus extra home ranges.
func NewDefault(extraHome []netip.Prefix) *Policy {
	return New(DefaultForbidden, append(slices.Clone(DefaultHome), extraHome...))
}

// Classify returns the class of addr.
func (p *Policy) Classify(addr netip.Addr) Class {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return Forbidden
	}
	for _, pr := range p.forbidden {
		if pr.Contains(addr) {
			return Forbidden
		}
	}
	for _, pr := range p.home {
		if pr.Contains(addr) {
			return Home
		}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, pr := range p.local {
		if pr.Contains(addr) {
			return Home
		}
	}
	return Internet
}

// Home returns the static home ranges (defaults plus configured extras).
func (p *Policy) Home() []netip.Prefix { return slices.Clone(p.home) }

// SetLocal replaces the detected local prefixes.
func (p *Policy) SetLocal(prefixes []netip.Prefix) {
	p.mu.Lock()
	p.local = slices.Clone(prefixes)
	p.mu.Unlock()
}

// Local returns the detected local prefixes.
func (p *Policy) Local() []netip.Prefix {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return slices.Clone(p.local)
}

// DetectLocal lists the server's own addresses (as /32 or /128) and, for global IPv6
// addresses, the /64 they live in. Home LANs usually get a public IPv6 prefix from
// the ISP, so private-range rules alone would let users reach home devices over IPv6.
func DetectLocal() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	return localPrefixes(addrs), nil
}

func localPrefixes(addrs []net.Addr) []netip.Prefix {
	var out []netip.Prefix
	add := func(p netip.Prefix) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		add(netip.PrefixFrom(ip, ip.BitLen()))
		if ip.Is6() && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			if p, err := ip.Prefix(64); err == nil {
				add(p)
			}
		}
	}
	return out
}

// ParsePrefixes parses CIDRs or bare IPs (treated as single-host prefixes).
func ParsePrefixes(items []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range items {
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func mustPrefixes(items ...string) []netip.Prefix {
	p, err := ParsePrefixes(items)
	if err != nil {
		panic(err)
	}
	return p
}
