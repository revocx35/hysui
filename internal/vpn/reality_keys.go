package vpn

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"

	"github.com/revocx35/hysui/internal/store"
)

// RealityOptions configures the VLESS Reality listener.
type RealityOptions struct {
	Listen      string
	Dest        string   // host:port of the real website to look like
	ServerNames []string // SNIs clients may use; must be names Dest serves
	PrivateKey  []byte   // X25519
	ShortID     [8]byte
}

// NewRealityKeys returns a new X25519 private key and short ID, encoded as stored
// (base64url key, hex short ID, the formats Xray and sing-box use).
func NewRealityKeys() (privateKey, shortID string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	sid := make([]byte, 8)
	if _, err := rand.Read(sid); err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), hex.EncodeToString(sid), nil
}

// ParseRealityKeys decodes stored keys and returns the public key for client links.
func ParseRealityKeys(privateKey, shortID string) (priv []byte, sid [8]byte, public string, err error) {
	priv, err = base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, sid, "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, sid, "", err
	}
	b, err := hex.DecodeString(shortID)
	if err != nil || len(b) > 8 {
		return nil, sid, "", errors.New("reality short ID must be up to 16 hex characters")
	}
	copy(sid[:], b)
	return priv, sid, base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// RealityLinkOptions describe how clients reach the Reality listener.
type RealityLinkOptions struct {
	Host       string // public domain (or IP) of this server
	Port       int    // public TCP port
	ServerName string // SNI of the impersonated site
	PublicKey  string
	ShortID    string
}

// RealityLink returns the vless:// URI for u.
func RealityLink(o RealityLinkOptions, u store.User) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("flow", flowVision)
	q.Set("security", "reality")
	q.Set("sni", o.ServerName)
	q.Set("fp", "chrome")
	q.Set("pbk", o.PublicKey)
	q.Set("sid", o.ShortID)
	q.Set("type", "tcp")
	return (&url.URL{
		Scheme:   "vless",
		User:     url.User(VLESSUUID(u)),
		Host:     net.JoinHostPort(o.Host, strconv.Itoa(o.Port)),
		RawQuery: q.Encode(),
		Fragment: u.Name + " (Reality)",
	}).String()
}
