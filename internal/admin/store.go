// Package admin manages a running server's state: the client list (PSKs) and
// the inbound listeners. It backs the terminal UI.
package admin

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mirage/internal/certs"
	"mirage/internal/conf"
	"mirage/internal/keygen"
	"mirage/internal/tlscam"
)

// Store wraps the server config file with edit operations.
type Store struct {
	path string
	dir  string
	cfg  *conf.ServerConfig
}

// Load reads server.json, migrating the legacy single-inbound layout to the
// "inbounds" list. Paths inside the file stay relative.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &conf.ServerConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(cfg.Inbounds) == 0 {
		cfg.Inbounds = cfg.InboundsOrDefault()
		// Drop the legacy copies so the file we save back is canonical.
		cfg.Listen, cfg.Domain = "", ""
		cfg.TLSCert, cfg.TLSKey = "", ""
		cfg.CoverDir, cfg.CoverProxy = "", ""
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Store{path: path, dir: filepath.Dir(path), cfg: cfg}, nil
}

// Init generates fresh material (CA, certificate, PSK, static key) and writes
// a ready server config plus a template client config into dir.
func Init(dir, host, domain string) error {
	if host == "" || domain == "" {
		return errors.New("admin: host and domain are required")
	}
	return keygen.Generate(keygen.Options{
		Dir:          dir,
		Domain:       domain,
		ServerAddr:   net.JoinHostPort(host, "443"),
		ServerListen: ":443",
		TunnelCIDR:   "10.7.0.0/24",
		DNSUpstream:  "1.1.1.1:53",
	})
}

// Path returns the config file path.
func (s *Store) Path() string { return s.path }

// Config returns the editable config.
func (s *Store) Config() *conf.ServerConfig { return s.cfg }

// Save validates and writes the config back to disk.
func (s *Store) Save() error {
	if err := s.cfg.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(s.path, b, 0o600)
}

// ---------- clients ----------

// ClientIDs returns the sorted psk ids.
func (s *Store) ClientIDs() []string {
	ids := make([]string, 0, len(s.cfg.PSKs))
	for id := range s.cfg.PSKs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// AddClient creates a new psk entry. The id must not exist.
func (s *Store) AddClient(id string) error {
	if id == "" {
		return errors.New("admin: empty client id")
	}
	if _, ok := s.cfg.PSKs[id]; ok {
		return fmt.Errorf("admin: client %q already exists", id)
	}
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return err
	}
	s.cfg.PSKs[id] = base64.StdEncoding.EncodeToString(psk)
	return nil
}

// RemoveClient deletes a psk entry. Existing sessions are not dropped.
func (s *Store) RemoveClient(id string) bool {
	if _, ok := s.cfg.PSKs[id]; !ok {
		return false
	}
	delete(s.cfg.PSKs, id)
	return true
}

// PSK returns the base64 PSK of a client.
func (s *Store) PSK(id string) (string, bool) {
	psk, ok := s.cfg.PSKs[id]
	return psk, ok
}

// ---------- inbounds ----------

// Inbounds returns the configured listeners.
func (s *Store) Inbounds() []conf.InboundConfig { return s.cfg.Inbounds }

// AddInbound adds a listener and issues a self-signed certificate for the
// domain, written next to the config file.
func (s *Store) AddInbound(id, domain, listen string) error {
	if id == "" {
		return errors.New("admin: empty inbound id")
	}
	if domain == "" {
		return errors.New("admin: empty domain")
	}
	if listen == "" {
		listen = ":443"
	}
	for _, in := range s.cfg.Inbounds {
		if in.ID == id {
			return fmt.Errorf("admin: inbound %q already exists", id)
		}
	}
	cert, err := certs.SelfSigned(domain, []string{domain})
	if err != nil {
		return err
	}
	certPath := filepath.Join(s.dir, id+".pem")
	keyPath := filepath.Join(s.dir, id+"-key.pem")
	if err := certs.Write(certPath, keyPath, cert); err != nil {
		return err
	}
	s.cfg.Inbounds = append(s.cfg.Inbounds, conf.InboundConfig{
		ID:      id,
		Listen:  listen,
		Domain:  domain,
		TLSCert: id + ".pem",
		TLSKey:  id + "-key.pem",
	})
	return nil
}

// RemoveInbound drops a listener. Its certificate files are left in place.
func (s *Store) RemoveInbound(id string) bool {
	for i, in := range s.cfg.Inbounds {
		if in.ID == id {
			s.cfg.Inbounds = append(s.cfg.Inbounds[:i], s.cfg.Inbounds[i+1:]...)
			return true
		}
	}
	return false
}

// ---------- client config export ----------

// ExportClient writes a ready-to-use client config for one client connecting
// through one inbound, into <dir>/clients/<id>.json. Returns the written path.
func (s *Store) ExportClient(clientID, inboundID string) (string, error) {
	pskB64, ok := s.cfg.PSKs[clientID]
	if !ok {
		return "", fmt.Errorf("admin: unknown client %q", clientID)
	}
	var ib conf.InboundConfig
	found := false
	for _, in := range s.cfg.Inbounds {
		if in.ID == inboundID {
			ib, found = in, true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("admin: unknown inbound %q", inboundID)
	}

	privBytes, err := base64.StdEncoding.DecodeString(s.cfg.X25519Priv)
	if err != nil {
		return "", fmt.Errorf("admin: x25519_priv: %w", err)
	}
	staticPriv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return "", fmt.Errorf("admin: x25519_priv: %w", err)
	}

	pin, err := tlscam.CertFingerprint(filepath.Join(s.dir, ib.TLSCert))
	if err != nil {
		return "", fmt.Errorf("admin: cert of inbound %q: %w", ib.ID, err)
	}

	client := conf.ClientConfig{
		Mode:             "tun",
		ServerAddr:       inboundAddr(s.cfg.Host, ib),
		ServerDomain:     ib.Domain,
		PSK:              pskB64,
		PSKID:            clientID,
		ServerX25519Pub:  base64.StdEncoding.EncodeToString(staticPriv.PublicKey().Bytes()),
		ServerCertSHA256: pin,
		TunName:          "mirage0",
		MTU:              s.cfg.MTU,
		SOCKSListen:      "127.0.0.1:1080",
		Routes:           []string{},
		IdlePingSec:      s.cfg.IdlePingSec,
		PadMin:           s.cfg.PadMin,
		RekeyRecords:     s.cfg.RekeyRecords,
	}
	if err := client.Validate(); err != nil {
		return "", err
	}

	outDir := filepath.Join(s.dir, "clients")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(client, "", "  ")
	if err != nil {
		return "", err
	}
	out := filepath.Join(outDir, clientID+".json")
	if err := os.WriteFile(out, append(b, '\n'), 0o600); err != nil {
		return "", err
	}
	return out, nil
}

// inboundAddr resolves the client-facing "host:port" for an inbound: the
// configured host, else the inbound's domain, else the listen address.
func inboundAddr(host string, ib conf.InboundConfig) string {
	port := "443"
	if _, p, err := net.SplitHostPort(ib.Listen); err == nil && p != "" {
		port = p
	}
	h := strings.TrimSpace(host)
	if h == "" {
		h = strings.TrimSpace(ib.Domain)
	}
	if h == "" {
		if lhost, _, err := net.SplitHostPort(ib.Listen); err == nil {
			h = lhost
		}
	}
	return net.JoinHostPort(h, port)
}
