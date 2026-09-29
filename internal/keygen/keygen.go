// Package keygen produces everything a deployment needs: an internal CA, the
// server certificate for the domain, the PSK, the server's static X25519 key,
// and ready-to-edit JSON configs for the client and the server.
package keygen

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"mirage/internal/certs"
	"mirage/internal/conf"
	"mirage/internal/tlscam"
	"mirage/internal/transport"
)

// Options tweaks the generated material.
type Options struct {
	Dir          string // output directory
	Domain       string // server domain (tunnel SNI + certificate name)
	ServerAddr   string // where the client connects, "host:443"
	ServerListen string // where the server listens, e.g. ":443"
	TunnelCIDR   string
	DNSUpstream  string
}

// Generate writes the material and the three config files.
func Generate(o Options) error {
	if o.Domain == "" {
		return fmt.Errorf("keygen: domain is required")
	}
	if o.Dir == "" {
		o.Dir = "keys"
	}
	if o.ServerAddr == "" {
		o.ServerAddr = "YOUR_SERVER_IP:443"
	}
	if o.ServerListen == "" {
		o.ServerListen = ":443"
	}
	if o.TunnelCIDR == "" {
		o.TunnelCIDR = "10.7.0.0/24"
	}
	if o.DNSUpstream == "" {
		o.DNSUpstream = "1.1.1.1:53"
	}

	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return err
	}

	ca, err := certs.NewCA("Mirage Root CA")
	if err != nil {
		return err
	}
	if err := certs.Write(filepath.Join(o.Dir, "ca.pem"), filepath.Join(o.Dir, "ca-key.pem"),
		certs.Combine(ca.DER, ca.Key)); err != nil {
		return err
	}

	serverCert, err := ca.Issue(o.Domain, []string{o.Domain})
	if err != nil {
		return err
	}
	serverCertPath := filepath.Join(o.Dir, "server.pem")
	serverKeyPath := filepath.Join(o.Dir, "server-key.pem")
	if err := certs.Write(serverCertPath, serverKeyPath, serverCert); err != nil {
		return err
	}

	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return err
	}
	pskID := make([]byte, 8)
	if _, err := rand.Read(pskID); err != nil {
		return err
	}
	id := hex.EncodeToString(pskID)

	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	pin, err := tlscam.CertFingerprint(serverCertPath)
	if err != nil {
		return err
	}

	clientConf := conf.ClientConfig{
		Mode:             "tun",
		ServerAddr:       o.ServerAddr,
		ServerDomain:     o.Domain,
		Transport:        string(transport.Raw),
		Path:             transport.DefaultPath,
		PSK:              base64.StdEncoding.EncodeToString(psk),
		PSKID:            id,
		ServerX25519Pub:  base64.StdEncoding.EncodeToString(static.PublicKey().Bytes()),
		ServerCertSHA256: pin,
		TunName:          "mirage0",
		MTU:              1400,
		SOCKSListen:      "127.0.0.1:1080",
		Routes:           []string{},
		DefaultRoute:     false,
		DNSViaTunnel:     false,
		IdlePingSec:      30,
		PadMin:           0,
		RekeyRecords:     1 << 20,
	}
	serverConf := conf.ServerConfig{
		Host: hostOf(o.ServerAddr),
		Inbounds: []conf.InboundConfig{{
			ID:        "main",
			Listen:    o.ServerListen,
			Domain:    o.Domain,
			Transport: string(transport.Raw),
			Path:      transport.DefaultPath,
			TLSCert:   "server.pem",
			TLSKey:    "server-key.pem",
		}},
		TunnelCIDR:   o.TunnelCIDR,
		IPStart:      "10.7.0.2",
		IPEnd:        "10.7.0.254",
		DNSListen:    "10.7.0.1:53",
		DNSUpstream:  o.DNSUpstream,
		TunName:      "mirage-srv",
		MTU:          1400,
		PadMin:       0,
		RekeyRecords: 1 << 20,
		IdlePingSec:  30,
		PSKs:         map[string]string{id: base64.StdEncoding.EncodeToString(psk)},
		X25519Priv:   base64.StdEncoding.EncodeToString(static.Bytes()),
	}

	for name, v := range map[string]interface{}{
		"client.json": clientConf,
		"server.json": serverConf,
	} {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		b = append(b, '\n')
		if err := os.WriteFile(filepath.Join(o.Dir, name), b, 0o600); err != nil {
			return err
		}
	}

	if err := os.WriteFile(filepath.Join(o.Dir, "psk.txt"),
		[]byte(fmt.Sprintf("psk_id: %s\npsk:     %s\n", id, base64.StdEncoding.EncodeToString(psk))), 0o600); err != nil {
		return err
	}

	log.Printf("keygen: wrote %s", o.Dir)
	log.Printf("keygen: certificate for %q pinned by %s", o.Domain, pin)
	log.Printf("keygen: set server_addr (%s) to the real host before running the client",
		o.ServerAddr)
	return nil
}

// hostOf strips the port from a "host:port" address.
func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
