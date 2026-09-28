// Package conf defines and validates the JSON configuration for the client
// and the server.
package conf

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mirage/internal/proto"
)

// ClientConfig configures the machine that wants to reach the internet.
type ClientConfig struct {
	// Operational mode: "tun" (default, IP-level VPN) or "socks"
	// (userspace SOCKS5 proxy, no driver needed).
	Mode string `json:"mode"`

	// The only host the client ever talks to, e.g. "203.0.113.10:443". This is
	// the address the DPI sees; the server behind it is the VPN endpoint.
	ServerAddr string `json:"server_addr"`

	// SNI sent in the TLS ClientHello. Must match the domain on the server's
	// certificate.
	ServerDomain string `json:"server_domain"`

	// Pre-shared key and its id (base64, 32 bytes) used for the inner
	// authenticated handshake.
	PSK   string `json:"psk"`
	PSKID string `json:"psk_id"`

	// Pinned X25519 static public key of the server (base64, 32 bytes).
	ServerX25519Pub string `json:"server_x25519_pub"`

	// SHA-256 of the DER certificate presented by the server (hex).
	// Replaces the normal CA chain: no public CA is involved.
	ServerCertSHA256 string `json:"server_cert_sha256"`

	// TUN settings.
	TunName      string   `json:"tun_name"`
	MTU          int      `json:"mtu"`
	Routes       []string `json:"routes"`        // CIDRs routed into the tunnel
	DefaultRoute bool     `json:"default_route"` // route 0.0.0.0/0 via TUN
	DNSViaTunnel bool     `json:"dns_via_tunnel"`

	// SOCKS mode only.
	SOCKSListen string `json:"socks_listen"`

	// Traffic-shape knobs.
	IdlePingSec  int `json:"idle_ping_sec"` // keepalive, 0 disables
	PadMin       int `json:"pad_min"`       // minimum record size (0 = off)
	RekeyRecords int `json:"rekey_records"` // rekey every N records, 0 = never
}

// ServerConfig configures the VPN server. It is the single public endpoint:
// every connection does a real TLS handshake, then either the inner tunnel
// handshake or, for anyone else, the cover website.
type ServerConfig struct {
	// Public listener, e.g. ":443".
	Listen string `json:"listen"`

	// TLS certificate for the server domain and its private key, PEM files.
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`

	// Address pool handed out to clients, inside TunnelCIDR.
	TunnelCIDR string `json:"tunnel_cidr"` // e.g. "10.7.0.0/24"
	IPStart    string `json:"ip_start"`    // e.g. "10.7.0.2"
	IPEnd      string `json:"ip_end"`      // e.g. "10.7.0.254"

	// Optional built-in DNS relay so clients can resolve through the tunnel
	// without leaking. Empty disables it.
	DNSListen   string `json:"dns_listen"`   // e.g. "10.7.0.1:53"
	DNSUpstream string `json:"dns_upstream"` // e.g. "1.1.1.1:53"

	TunName string `json:"tun_name"`
	MTU     int    `json:"mtu"`

	// Traffic-shape knobs, should mirror the client.
	PadMin       int `json:"pad_min"`
	RekeyRecords int `json:"rekey_records"`
	IdlePingSec  int `json:"idle_ping_sec"`

	// psk_id -> base64 PSK.
	PSKs map[string]string `json:"psks"`

	// Static X25519 private key of the server (base64, 32 bytes).
	X25519Priv string `json:"x25519_priv"`

	// Directory served as a cover website to anything that is not an
	// authenticated client (probes, scanners). Optional.
	CoverDir string `json:"cover_dir"`

	// Optional upstream to reverse-proxy as the cover site.
	CoverProxy string `json:"cover_proxy"`
}

// Load reads and validates a JSON config file. Relative paths inside the config
// are resolved against the config file's directory, so a config can be loaded
// from any working directory.
func Load(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	switch c := v.(type) {
	case *ClientConfig:
		return c.Validate()
	case *ServerConfig:
		c.TLSCert = resolvePath(dir, c.TLSCert)
		c.TLSKey = resolvePath(dir, c.TLSKey)
		c.CoverDir = resolvePath(dir, c.CoverDir)
		return c.Validate()
	}
	return errors.New("conf: unknown config type")
}

func resolvePath(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

// Validate checks the client config.
func (c *ClientConfig) Validate() error {
	if c.Mode == "" {
		c.Mode = "tun"
	}
	switch c.Mode {
	case "tun", "socks":
	default:
		return fmt.Errorf("mode must be tun or socks, got %q", c.Mode)
	}
	if c.ServerAddr == "" {
		return errors.New("server_addr is required")
	}
	if c.ServerDomain == "" {
		return errors.New("server_domain is required")
	}
	if _, err := DecodePSK(c.PSK); err != nil {
		return fmt.Errorf("psk: %w", err)
	}
	if _, err := DecodePSK(c.ServerX25519Pub); err != nil {
		return fmt.Errorf("server_x25519_pub: %w", err)
	}
	if c.ServerCertSHA256 == "" {
		return errors.New("server_cert_sha256 is required (cert pinning)")
	}
	if c.MTU == 0 {
		c.MTU = proto.DefaultMTU
	}
	if c.TunName == "" {
		c.TunName = "mirage0"
	}
	if c.Mode == "socks" && c.SOCKSListen == "" {
		c.SOCKSListen = "127.0.0.1:1080"
	}
	if c.Mode == "tun" && c.IdlePingSec == 0 {
		c.IdlePingSec = 30
	}
	return nil
}

// Validate checks the server config.
func (c *ServerConfig) Validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if c.TLSCert == "" || c.TLSKey == "" {
		return errors.New("tls_cert and tls_key are required")
	}
	if c.TunnelCIDR == "" {
		return errors.New("tunnel_cidr is required")
	}
	if c.IPStart == "" || c.IPEnd == "" {
		return errors.New("ip_start and ip_end are required")
	}
	if len(c.PSKs) == 0 {
		return errors.New("at least one psk entry is required")
	}
	for id, b64 := range c.PSKs {
		if _, err := DecodePSK(b64); err != nil {
			return fmt.Errorf("psks[%s]: %w", id, err)
		}
	}
	if _, err := DecodePSK(c.X25519Priv); err != nil {
		return fmt.Errorf("x25519_priv: %w", err)
	}
	if c.MTU == 0 {
		c.MTU = proto.DefaultMTU
	}
	if c.TunName == "" {
		c.TunName = "mirage-srv"
	}
	return nil
}

// DecodePSK decodes a base64 32-byte secret.
func DecodePSK(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("invalid base64")
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return b, nil
}
