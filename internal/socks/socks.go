// Package socks implements a minimal SOCKS5 server whose dialer is a callback,
// so connections can be carried through the encrypted tunnel without a TUN
// driver.
package socks

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
)

// DialFunc opens a connection to address (host:port). The network is always tcp.
type DialFunc func(network, address string) (net.Conn, error)

// Server is a SOCKS5 listener.
type Server struct {
	addr string
	dial DialFunc
	ln   net.Listener
}

// New creates the server; call ListenAndServe to run it.
func New(addr string, dial DialFunc) *Server {
	return &Server{addr: addr, dial: dial}
}

// ListenAndServe accepts connections until the listener is closed.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	log.Printf("socks5: listening on %s", s.addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

// Close stops accepting connections.
func (s *Server) Close() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()

	br := make([]byte, 2)
	if _, err := io.ReadFull(c, br); err != nil {
		return
	}
	if br[0] != 0x05 {
		return // not SOCKS5
	}
	nMethods := int(br[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// "no authentication required"
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	if hdr[1] != 0x01 { // only CONNECT
		reply(c, 0x07, nil, 0)
		return
	}

	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		reply(c, 0x08, nil, 0)
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(c, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	remote, err := s.dial("tcp", target)
	if err != nil {
		log.Printf("socks5: dial %s: %v", target, err)
		reply(c, 0x05, nil, 0) // connection refused
		return
	}
	defer remote.Close()

	// Bound address: report the remote's address back to the client.
	bndHost, bndPortStr, _ := net.SplitHostPort(remote.LocalAddr().String())
	bndIP := net.ParseIP(bndHost)
	var bndAddr []byte
	if ip4 := bndIP.To4(); ip4 != nil {
		bndAddr = ip4
	} else {
		bndAddr = bndIP.To16()
	}
	bp, _ := strconv.Atoi(bndPortStr)
	reply(c, 0x00, bndAddr, bp)

	pipe(c, remote)
}

func reply(c net.Conn, code byte, addr net.IP, port int) {
	msg := []byte{0x05, code, 0x00}
	if addr == nil {
		msg = append(msg, 0x01, 0, 0, 0, 0, 0, 0)
	} else {
		if ip4 := addr.To4(); ip4 != nil {
			msg = append(msg, 0x01)
			msg = append(msg, ip4...)
		} else {
			msg = append(msg, 0x04)
			msg = append(msg, addr.To16()...)
		}
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	msg = append(msg, p[:]...)
	_, _ = c.Write(msg)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
	// One direction ended: close both so the surviving copy unblocks and the
	// peer does not wait for data that will never come.
	a.Close()
	b.Close()
	<-done
}
