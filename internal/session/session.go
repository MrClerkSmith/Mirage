// Package session pumps packets between the encrypted record stream and either
// a TUN device (IP-level VPN) or a SOCKS5 listener (driver-free mode). Exactly
// one goroutine reads the record stream and dispatches by record type; TUN
// writes and the keepalive run in their own goroutines.
package session

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"mirage/internal/control"
	"mirage/internal/mux"
	"mirage/internal/proto"
	"mirage/internal/record"
	"mirage/internal/socks"
	"mirage/internal/tunmgr"
)

// ipVer returns 4 or 6 for a raw IP packet (0 if it cannot tell).
func ipVer(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	return int(b[0] >> 4)
}

// ---------- client side ----------

// Client is one established client session.
type Client struct {
	FC        *record.FramedConn
	TUN       *tunmgr.Device // nil in socks-only mode
	Mux       *mux.ClientMux
	SOCKSAddr string // empty: no socks listener
	IdlePing  time.Duration

	failOnce  sync.Once // sets the terminal error and closes done
	closeOnce sync.Once // tears FC / mux / TUN down
	done      chan struct{}
	err       error
}

// NewClient assembles a client session.
func NewClient(fc *record.FramedConn, dev *tunmgr.Device, m *mux.ClientMux, socksAddr string, idlePing time.Duration) *Client {
	return &Client{
		FC:        fc,
		TUN:       dev,
		Mux:       m,
		SOCKSAddr: socksAddr,
		IdlePing:  idlePing,
		done:      make(chan struct{}),
	}
}

// Run blocks until the session ends and returns the first error encountered.
func (c *Client) Run() error {
	go c.readLoop()
	if c.TUN != nil {
		go c.tunWriteLoop()
	}
	if c.SOCKSAddr != "" && c.Mux != nil {
		go func() {
			srv := socks.New(c.SOCKSAddr, socks.DialFunc(c.Mux.Dial))
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("socks5: %v", err)
			}
		}()
	}
	if c.IdlePing > 0 {
		go c.pingLoop()
	}
	<-c.done
	return c.err
}

func (c *Client) readLoop() {
	for {
		rtype, payload, err := c.FC.ReadRecord()
		if err != nil {
			c.fail(err)
			return
		}
		switch rtype {
		case proto.RecIPv4, proto.RecIPv6:
			if c.TUN != nil {
				if err := c.TUN.WritePacket(payload); err != nil {
					c.fail(err)
					return
				}
			}
		case proto.RecSConnect, proto.RecSConnectOK, proto.RecSConnectFail, proto.RecSData, proto.RecSClose:
			if c.Mux != nil {
				c.Mux.HandleFrame(rtype, payload)
			}
		case proto.RecControl:
			if control.IsPing(payload) {
				_ = c.FC.WriteRecord(proto.RecControl, control.Pong(time.Now().Unix()))
			}
		}
	}
}

func (c *Client) tunWriteLoop() {
	buf := make([]byte, c.TUN.MTU()+32)
	for {
		n, err := c.TUN.ReadPacket(buf)
		if err != nil {
			c.fail(err)
			return
		}
		if n == 0 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		rtype := proto.RecIPv4
		if ipVer(pkt) == 6 {
			rtype = proto.RecIPv6
		}
		if err := c.FC.WriteRecord(rtype, pkt); err != nil {
			c.fail(err)
			return
		}
	}
}

func (c *Client) pingLoop() {
	t := time.NewTicker(c.IdlePing)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := c.FC.WriteRecord(proto.RecControl, control.Ping(time.Now().Unix())); err != nil {
				c.fail(err)
				return
			}
		case <-c.done:
			return
		}
	}
}

// Close ends the session and releases the interface. Idempotent.
func (c *Client) Close() {
	c.fail(net.ErrClosed)
	c.closeOnce.Do(func() {
		c.FC.Close()
		if c.Mux != nil {
			c.Mux.Close()
		}
		if c.TUN != nil {
			c.TUN.Close()
		}
	})
}

// Done is closed when the session ends.
func (c *Client) Done() <-chan struct{} { return c.done }

func (c *Client) fail(err error) {
	c.failOnce.Do(func() {
		c.err = err
		close(c.done)
	})
}

// ---------- server side ----------

// Server is one tunneled client on the VPN server. Packets it sends are injected
// into the shared TUN; packets routed back to it are delivered with Send.
type Server struct {
	FC        *record.FramedConn
	TUN       *tunmgr.Device
	Mux       *mux.ServerMux
	VirtualIP net.IP
	PSKID     string
	IdlePing  time.Duration

	failOnce  sync.Once
	closeOnce sync.Once
	done      chan struct{}
	err       error
}

// NewServer assembles a server-side session.
func NewServer(fc *record.FramedConn, dev *tunmgr.Device, m *mux.ServerMux, virtualIP net.IP, pskID string, idlePing time.Duration) *Server {
	return &Server{
		FC:        fc,
		TUN:       dev,
		Mux:       m,
		VirtualIP: virtualIP,
		PSKID:     pskID,
		IdlePing:  idlePing,
		done:      make(chan struct{}),
	}
}

// Run reads the tunnel until it ends.
func (s *Server) Run() error {
	go s.readLoop()
	if s.IdlePing > 0 {
		go s.pingLoop()
	}
	<-s.done
	return s.err
}

// Send pushes an IP packet from the server's TUN back through the tunnel.
func (s *Server) Send(pkt []byte) error {
	rtype := proto.RecIPv4
	if ipVer(pkt) == 6 {
		rtype = proto.RecIPv6
	}
	return s.FC.WriteRecord(rtype, pkt)
}

func (s *Server) pingLoop() {
	t := time.NewTicker(s.IdlePing)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := s.FC.WriteRecord(proto.RecControl, control.Ping(time.Now().Unix())); err != nil {
				s.fail(err)
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *Server) readLoop() {
	for {
		rtype, payload, err := s.FC.ReadRecord()
		if err != nil {
			s.fail(err)
			return
		}
		switch rtype {
		case proto.RecIPv4, proto.RecIPv6:
			if s.TUN != nil {
				if err := s.TUN.WritePacket(payload); err != nil {
					s.fail(err)
					return
				}
			}
		case proto.RecSConnect, proto.RecSData, proto.RecSClose:
			if s.Mux != nil {
				s.Mux.HandleFrame(rtype, payload)
			}
		case proto.RecControl:
			if control.IsPing(payload) {
				_ = s.FC.WriteRecord(proto.RecControl, control.Pong(time.Now().Unix()))
			}
		}
	}
}

// Done is closed when the session ends.
func (s *Server) Done() <-chan struct{} { return s.done }

// Close ends the session. Idempotent.
func (s *Server) Close() {
	s.fail(net.ErrClosed)
	s.closeOnce.Do(func() {
		s.FC.Close()
		if s.Mux != nil {
			s.Mux.Close()
		}
	})
}

func (s *Server) fail(err error) {
	s.failOnce.Do(func() {
		s.err = err
		close(s.done)
	})
}
