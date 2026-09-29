// Package client connects to the server and runs the tunnel, reconnecting with
// backoff when the link drops.
package client

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"mirage/internal/conf"
	"mirage/internal/handshake"
	"mirage/internal/mux"
	"mirage/internal/session"
	"mirage/internal/tlscam"
	"mirage/internal/transport"
	"mirage/internal/tunmgr"
)

const (
	connectTimeout = 15 * time.Second
	reconnectBase  = 2 * time.Second
	reconnectMax   = 60 * time.Second
)

// Client owns one configured tunnel.
type Client struct {
	cfg  *conf.ClientConfig
	kind transport.Kind
	sni  string // overrides cfg.ServerDomain when set
}

// New creates the client.
func New(cfg *conf.ClientConfig) *Client {
	kind, _ := transport.Parse(cfg.Transport) // validated when the config loaded
	return &Client{cfg: cfg, kind: kind}
}

// SetSNI overrides the SNI sent in the TLS ClientHello (and the HTTP Host
// header of the ws/grpc transports). An empty value keeps the config's domain.
func (c *Client) SetSNI(domain string) {
	if domain != "" {
		c.sni = domain
	}
}

// SetTransport overrides the outer transport ("raw", "ws" or "grpc").
func (c *Client) SetTransport(kind string) error {
	k, err := transport.Parse(kind)
	if err != nil {
		return err
	}
	c.kind = k
	return nil
}

// Domain returns the SNI that will be used for the next connection.
func (c *Client) Domain() string {
	if c.sni != "" {
		return c.sni
	}
	return c.cfg.ServerDomain
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
	tcp, err := d.DialContext(ctx, "tcp", c.cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}

	tlsConn := tls.Client(tcp, tlscam.ClientConfigALPN(c.Domain(), c.cfg.ServerCertSHA256, c.kind.ClientALPN()))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcp.Close()
		return fmt.Errorf("tls handshake with server: %w", err)
	}

	stream, err := transport.Dial(c.kind, tlsConn, c.Domain(), c.cfg.Path)
	if err != nil {
		tcp.Close()
		return fmt.Errorf("transport %s: %w", c.kind, err)
	}

	log.Printf("client: connected to %s (transport=%s, sni=%s, psk_id=%s)",
		c.cfg.ServerAddr, c.kind, c.Domain(), c.cfg.PSKID)

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

	fc, info, err := handshake.Client(stream, handshake.ClientParams{
		PSK:             psk,
		PSKID:           c.cfg.PSKID,
		ServerX25519Pub: serverPub,
	}, c.cfg.PadMin, c.cfg.RekeyRecords)
	if err != nil {
		tcp.Close()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// TLS worked but the server never answered the inner handshake:
			// the client is talking to a TLS endpoint that is not running the
			// tunnel on this transport, or the PSK does not match.
			return fmt.Errorf("inner handshake: the server accepted TLS but sent no answer "+
				"(transport=%s, sni=%s, psk_id=%s): check that the client's transport matches "+
				"the server's inbound and that the PSK/psk_id are correct: %w",
				c.kind, c.Domain(), c.cfg.PSKID, err)
		}
		return fmt.Errorf("inner handshake: %w", err)
	}
	log.Printf("client: tunneled via %s as %s (dns %s, mtu %d)",
		c.cfg.ServerAddr, info.AssignedIP, info.DNS, info.MTU)

	var dev *tunmgr.Device
	var socksAddr string
	mtu := info.MTU
	if mtu <= 0 {
		mtu = c.cfg.MTU
	}

	switch c.cfg.Mode {
	case "", "tun":
		var dns []string
		if c.cfg.DNSViaTunnel && info.DNS != "" {
			dns = []string{info.DNS}
		}
		preserveHost, _, perr := net.SplitHostPort(c.cfg.ServerAddr)
		if perr != nil {
			preserveHost = c.cfg.ServerAddr
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
