// Package relay is the decoy: the only endpoint the DPI ever sees. It inspects
// the TLS ClientHello of every incoming connection and either
//
//   - relays the raw byte stream to the hidden VPN server when the SNI is the
//     configured tunnel domain (the connection stays encrypted end to end, the
//     relay learns nothing), or
//   - serves the cover website for every other client, exactly like an ordinary
//     small HTTPS host.
//
// Because the tunnel SNI is the decoy's own domain, a censor that actively
// connects with the same SNI gets byte-identical traffic and a normal website.
package relay

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"strings"

	"mirage/internal/certs"
	"mirage/internal/conf"
	"mirage/internal/cover"
	"mirage/internal/tlscam"
)

// Relay is the running decoy.
type Relay struct {
	cfg   *conf.DecoyConfig
	cover *cover.Site
}

// New prepares the decoy. When no cover certificate is configured an ephemeral
// self-signed one is generated so the site still speaks HTTPS.
func New(cfg *conf.DecoyConfig) (*Relay, error) {
	var tlsConf *tls.Config
	if cfg.CoverCert != "" && cfg.CoverKey != "" {
		c, err := tlscam.CoverConfig(cfg.CoverCert, cfg.CoverKey)
		if err != nil {
			return nil, err
		}
		tlsConf = c
	} else {
		c, err := certs.SelfSigned(cfg.TunnelDomain, []string{cfg.TunnelDomain})
		if err != nil {
			return nil, err
		}
		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{c},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}
	}
	site, err := cover.New(tlsConf, cfg.CoverDir, cfg.CoverProxy)
	if err != nil {
		return nil, err
	}
	return &Relay{cfg: cfg, cover: site}, nil
}

// ListenAndServe accepts connections on the configured address.
func (r *Relay) ListenAndServe() error {
	ln, err := net.Listen("tcp", r.cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("decoy: listening on %s | tunnel SNI %q -> hidden %s",
		r.cfg.Listen, r.cfg.TunnelDomain, r.cfg.ServerAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.handle(c)
	}
}

func (r *Relay) handle(conn net.Conn) {
	defer conn.Close()

	sni, replay, _ := tlscam.SniffSNI(conn)
	if strings.EqualFold(sni, r.cfg.TunnelDomain) {
		r.relayToHidden(conn, replay)
		return
	}
	r.cover.ServeWithReplay(conn, replay)
}

// relayToHidden pipes the whole stream, including the already-read ClientHello,
// to the real VPN server. The relay never sees plaintext.
func (r *Relay) relayToHidden(conn net.Conn, replay []byte) {
	up, err := net.Dial("tcp", r.cfg.ServerAddr)
	if err != nil {
		log.Printf("decoy: cannot reach hidden server %s: %v", r.cfg.ServerAddr, err)
		return
	}
	defer up.Close()

	if len(replay) > 0 {
		if _, err := up.Write(replay); err != nil {
			return
		}
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, up)
		done <- struct{}{}
	}()
	<-done
}
