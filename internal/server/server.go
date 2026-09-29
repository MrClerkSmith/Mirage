// Package server is the public VPN endpoint and the only host a client or the
// DPI ever sees. Every connection does a real TLS handshake with the server
// domain certificate, then either completes the inner tunnel handshake and is
// bridged to the internet through a shared TUN interface, or — for anything
// that does not authenticate (browsers, scanners, active probes) — is served
// the cover website, so the port looks like an ordinary web host.
package server

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/base64"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"mirage/internal/conf"
	"mirage/internal/control"
	"mirage/internal/cover"
	"mirage/internal/dns"
	"mirage/internal/handshake"
	"mirage/internal/mux"
	"mirage/internal/proto"
	"mirage/internal/record"
	"mirage/internal/session"
	"mirage/internal/tlscam"
	"mirage/internal/transport"
	"mirage/internal/tunmgr"
)

// Server is the running public endpoint.
type Server struct {
	cfg        *conf.ServerConfig
	staticPriv *ecdh.PrivateKey
	psks       map[string][]byte
	tun        *tunmgr.Device
	serverAddr string // address of the server itself on the virtual link
	prefix     int
	inbounds   []inbound

	mu       sync.Mutex
	sessions map[string]*session.Server
	pool     *ipPool
}

// inbound is one listening endpoint with its own certificate and cover site.
type inbound struct {
	cfg   conf.InboundConfig
	kind  transport.Kind
	tls   *tls.Config
	cover *cover.Site
}

// New prepares the server but does not touch the network yet.
func New(cfg *conf.ServerConfig) (*Server, error) {
	psks := make(map[string][]byte, len(cfg.PSKs))
	for id, b64 := range cfg.PSKs {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, err
		}
		psks[id] = raw
	}
	privBytes, err := base64.StdEncoding.DecodeString(cfg.X25519Priv)
	if err != nil {
		return nil, err
	}
	staticPriv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	_, ipnet, err := net.ParseCIDR(cfg.TunnelCIDR)
	if err != nil {
		return nil, err
	}
	prefix, _ := ipnet.Mask.Size()

	// The server takes the first address of the tunnel subnet, clients get the
	// rest from the pool.
	serverIP := make(net.IP, len(ipnet.IP))
	copy(serverIP, ipnet.IP)
	for i := len(serverIP) - 1; i >= 0; i-- {
		serverIP[i]++
		if serverIP[i] != 0 {
			break
		}
	}

	pool, err := newPool(cfg.IPStart, cfg.IPEnd)
	if err != nil {
		return nil, err
	}

	inbounds := make([]inbound, 0, len(cfg.InboundsOrDefault()))
	for _, ic := range cfg.InboundsOrDefault() {
		kind, err := transport.Parse(ic.Transport)
		if err != nil {
			return nil, err
		}
		tlsConf, err := tlscam.ServerConfigALPN(ic.TLSCert, ic.TLSKey, kind.ServerALPN())
		if err != nil {
			return nil, err
		}
		site, err := cover.New(ic.CoverDir, ic.CoverProxy)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, inbound{cfg: ic, kind: kind, tls: tlsConf, cover: site})
	}

	return &Server{
		cfg:        cfg,
		staticPriv: staticPriv,
		psks:       psks,
		inbounds:   inbounds,
		serverAddr: serverIP.String(),
		prefix:     prefix,
		sessions:   make(map[string]*session.Server),
		pool:       pool,
	}, nil
}

// ListenAndServe creates the TUN, starts the DNS relay and serves tunnel
// connections until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	dev, err := tunmgr.Create(s.cfg.TunName, s.cfg.MTU, s.serverAddr+"/"+strconv.Itoa(s.prefix), nil, nil, false, "")
	if err != nil {
		return err
	}
	s.tun = dev
	log.Printf("server: tun %s up as %s/%d", dev.Name(), s.serverAddr, s.prefix)

	go s.tunReadLoop()

	if s.cfg.DNSListen != "" && s.cfg.DNSUpstream != "" {
		go func() {
			if err := dns.Serve(ctx, s.cfg.DNSListen, s.cfg.DNSUpstream); err != nil {
				log.Printf("server: dns relay: %v", err)
			}
		}()
	}

	// One listener per inbound; they all feed the same tunnel.
	errs := make(chan error, len(s.inbounds))
	for _, ib := range s.inbounds {
		go func(ib inbound) { errs <- s.serve(ctx, ib) }(ib)
	}
	return <-errs
}

// serve listens on one inbound and hands connections to handle until the
// context is cancelled.
func (s *Server) serve(ctx context.Context, ib inbound) error {
	ln, err := net.Listen("tcp", ib.cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("server: inbound %q on %s (domain %s)", ib.cfg.ID, ib.cfg.Listen, ib.cfg.Domain)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.handle(c, ib)
	}
}

func (s *Server) handle(conn net.Conn, ib inbound) {
	defer conn.Close()

	tlsConn := tls.Server(conn, ib.tls)
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	if ib.kind.IsHTTP() {
		// The transport dispatches its own requests: the ones on the tunnel
		// path are handed to serveStream, everything else gets the cover
		// website.
		_ = transport.ServeHTTP(ib.kind, tlsConn, ib.cfg.Path, ib.cover, func(stream net.Conn) {
			s.serveStream(stream, ib)
		})
		return
	}

	fc, info, peeked, err := handshake.Server(tlsConn, handshake.ServerParams{
		PSKs:       s.psks,
		StaticPriv: s.staticPriv,
	}, s.cfg.PadMin, s.cfg.RekeyRecords)
	if err == handshake.ErrNotTunnel {
		// An ordinary TLS client or an active probe: serve the website.
		ib.cover.ServeExisting(tlsConn, peeked)
		return
	}
	if err != nil {
		log.Printf("server: handshake: %v", err)
		return
	}
	s.serveSession(fc, info)
}

// serveStream runs the inner handshake over an already-upgraded transport
// stream (WebSocket or gRPC).
func (s *Server) serveStream(stream net.Conn, ib inbound) {
	fc, info, _, err := handshake.Server(stream, handshake.ServerParams{
		PSKs:       s.psks,
		StaticPriv: s.staticPriv,
	}, s.cfg.PadMin, s.cfg.RekeyRecords)
	if err != nil {
		log.Printf("server: handshake: %v", err)
		return
	}
	s.serveSession(fc, info)
}

// serveSession admits one authenticated client and runs it to completion.
func (s *Server) serveSession(fc *record.FramedConn, info *handshake.ClientInfo) {
	ip, err := s.pool.Acquire()
	if err != nil {
		log.Printf("server: address pool exhausted")
		_ = fc.WriteRecord(proto.RecControl, control.Encode(control.Field{
			Tag: proto.CtrlError, Val: []byte("address pool exhausted"),
		}))
		fc.Close()
		return
	}

	sess := session.NewServer(fc, s.tun, mux.NewServer(fc), ip, info.PSKID,
		time.Duration(s.cfg.IdlePingSec)*time.Second)

	if err := handshake.SendWelcome(fc, ip.String()+"/"+strconv.Itoa(s.prefix), s.serverAddr, s.cfg.MTU); err != nil {
		fc.Close()
		s.pool.Release(ip)
		return
	}

	key := ip.String()
	s.mu.Lock()
	s.sessions[key] = sess
	s.mu.Unlock()
	log.Printf("server: client %s online (psk_id=%s)", key, info.PSKID)

	// Runs in this goroutine: when it returns the peer is gone and the
	// deferred conn.Close() above can finally fire.
	runErr := sess.Run()

	s.mu.Lock()
	delete(s.sessions, key)
	s.mu.Unlock()
	s.pool.Release(ip)
	sess.Close()
	log.Printf("server: client %s offline: %v", key, runErr)
}

// tunReadLoop routes packets the kernel handed to the TUN back to the client
// that owns the destination address.
func (s *Server) tunReadLoop() {
	buf := make([]byte, s.tun.MTU()+32)
	for {
		n, err := s.tun.ReadPacket(buf)
		if err != nil {
			log.Printf("server: tun read: %v", err)
			return
		}
		if n < 20 {
			continue
		}
		dst := dstIP(buf[:n])
		if dst == nil {
			continue
		}
		s.mu.Lock()
		sess := s.sessions[dst.String()]
		s.mu.Unlock()
		if sess == nil {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		_ = sess.Send(pkt)
	}
}

// dstIP returns the destination address of an IPv4 or IPv6 packet.
func dstIP(pkt []byte) net.IP {
	if len(pkt) == 0 {
		return nil
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) >= 20 {
			return net.IP(pkt[16:20])
		}
	case 6:
		if len(pkt) >= 40 {
			return net.IP(pkt[24:40])
		}
	}
	return nil
}
