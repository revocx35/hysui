package netpolicy

import (
	"net"
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	p := NewDefault(mustPrefixes("203.0.113.7/32"))
	p.SetLocal(mustPrefixes("2001:db8:1:2::/64", "192.168.1.40/32"))

	cases := map[string]Class{
		"1.1.1.1":              Internet,
		"2606:4700::1111":      Internet,
		"192.168.1.1":          Home,
		"10.1.2.3":             Home,
		"172.20.0.1":           Home,
		"100.100.1.1":          Home,
		"fd00::1":              Home,
		"fe80::1":              Home,
		"2001:db8:1:2::abcd":   Home,     // detected local /64
		"2001:db8:1:3::abcd":   Internet, // neighbouring /64 is not ours
		"203.0.113.7":          Home,     // extra home range
		"127.0.0.1":            Forbidden,
		"::1":                  Forbidden,
		"0.0.0.0":              Forbidden,
		"::":                   Forbidden,
		"224.0.0.251":          Forbidden,
		"::ffff:192.168.1.1":   Home, // IPv4-mapped is unmapped first
		"::ffff:127.0.0.1":     Forbidden,
		"255.255.255.255":      Forbidden,
		"ff02::1":              Forbidden,
		"8.8.8.8":              Internet,
		"2001:4860:4860::8888": Internet,
	}
	for s, want := range cases {
		if got := p.Classify(netip.MustParseAddr(s)); got != want {
			t.Errorf("Classify(%s) = %v, want %v", s, got, want)
		}
	}
	if got := p.Classify(netip.Addr{}); got != Forbidden {
		t.Errorf("invalid addr = %v, want forbidden", got)
	}
}

func TestLocalPrefixes(t *testing.T) {
	mk := func(cidr string) net.Addr {
		ip, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	got := localPrefixes([]net.Addr{
		mk("127.0.0.1/8"),
		mk("::1/128"),
		mk("192.168.1.40/24"),
		mk("2001:db8:3d08:3d66:1234:56ff:fe78:9abc/64"),
		mk("fe80::1234:56ff:fe78:9abc/64"),
	})
	want := mustPrefixes(
		"192.168.1.40/32",
		"2001:db8:3d08:3d66:1234:56ff:fe78:9abc/128",
		"2001:db8:3d08:3d66::/64",
		"fe80::1234:56ff:fe78:9abc/128",
	)
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParsePrefixes(t *testing.T) {
	got, err := ParsePrefixes([]string{"10.0.0.5/8", "192.168.1.1", "", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	want := mustPrefixes("10.0.0.0/8", "192.168.1.1/32", "2001:db8::1/128")
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if _, err := ParsePrefixes([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error")
	}
}
