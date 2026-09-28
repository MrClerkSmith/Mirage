// Package client connects to the decoy and runs the tunnel, reconnecting with
// backoff when the link drops.
package client

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"mirage/internal/conf"
	"mirage/internal/handshake"
	"mirage/internal/mux"
	"mirage/internal/session"
	"mirage/internal/tlscam"
	"mirage/internal/tunmgr"
)

const (
	connectTimeout   = 15 * time.Second
	reconnectBase    = 2 * time.Second
	reconnectMax     = 60 * time.Second
)

// Client owns one configured tunnel.
type Client struct {
	cfg *conf.ClientConfig
}

// New creates the client.
func New(cfg *conf.ClientConfig) *Client {
	return &Client{cfg: cfg}
}

// Run blocks until the context is cancelled, reconnecting as needed.
func (c *Client) Run(ctx context.Context) error {
	delay := reconnectBase
	first := true
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !first {
			log.Printf("client: reconnecting in %s", delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
			delay *= 2
			if delay > reconnectMax {
				delay = reconnectMax
			}
		}
		first = false

		err := c.connect(ctx)
		if err != nil {
			log.Printf("client: tunnel down: %v", err)
			if ctx.Err() != nil {
				return ctx.Err()
			}
		} else {
			delay = reconnectBase
		}
	}
}

// connect establishes one full session and pumps it until it ends.
func (c *Client) connect(ctx context.Context) error {
	d := net.Dialer{Timeout: connectTimeout}
	tcp, err := d.DialContext(ctx, "tcp", c.cfg.DecoyAddr)
	if err != nil {
		return fmt.Errorf("dial decoy: %w", err)
	}

	tlsConn := tls.Client(tcp, tlscam.ClientConfig(c.cfg.DecoyDomain, c.cfg.ServerCertSHA256))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcp.Close()
		return fmt.Errorf("tls handshake with decoy: %w", err)
	}

	psk, err := conf.DecodePSK(c.cfg.PSK)
	if err != nil {
		tcp.Close()
		return err
	}
	pubBytes, err := conf.DecodePSK(c.cfg.ServerX25519Pub)
	if err != nil {
		tcp.Close()
		return err
	}
	serverPub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		tcp.Close()
		return err
	}

	fc, info, err := handshake.Client(tlsConn, handshake.ClientParams{
		PSK:            psk,
		PSKID:          c.cfg.PSKID,
		ServerX25519Pub: serverPub,
	}, c.cfg.PadMin, c.cfg.RekeyRecords)
	if err != nil {
		tcp.Close()
		return fmt.Errorf("inner handshake: %w", err)
	}
	log.Printf("client: tunneled via %s as %s (dns %s, mtu %d)",
		c.cfg.DecoyAddr, info.AssignedIP, info.DNS, info.MTU)

	var dev *tunmgr.Device
	var socksAddr string
	mtu := info.MTU
	if mtu <= 0 {
		mtu = c.cfg.MTU
	}

	switch c.cfg.Mode {
	case "tun":
		var dns []string
		if c.cfg.DNSViaTunnel && info.DNS != "" {
			dns = []string{info.DNS}
		}
		preserveHost, _, perr := net.SplitHostPort(c.cfg.DecoyAddr)
		if perr != nil {
			preserveHost = c.cfg.DecoyAddr
		}
		dev, err = tunmgr.Create(c.cfg.TunName, mtu, info.AssignedIP, dns,
			c.cfg.Routes, c.cfg.DefaultRoute, preserveHost)
		if err != nil {
			fc.Close()
			tcp.Close()
			return fmt.Errorf("tun: %w", err)
		}
		log.Printf("client: interface %s ready", dev.Name())
	case "socks":
		socksAddr = c.cfg.SOCKSListen
	}

	m := mux.NewClient(fc)
	idle := time.Duration(c.cfg.IdlePingSec) * time.Second
	sess := session.NewClient(fc, dev, m, socksAddr, idle)

	go func() {
		<-ctx.Done()
		sess.Close()
	}()

	runErr := sess.Run()
	sess.Close() // make sure the interface and the socket always come down
	return runErr
}
