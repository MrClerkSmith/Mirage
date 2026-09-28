// Package mux multiplexes TCP connections over the encrypted record stream, so
// the client can expose a plain SOCKS5 proxy that does not need a TUN driver.
//
// Frame payloads inside RecS* records:
//
//	SConnect     [id(4)] [addr_len(2)] [addr]
//	SConnectOK   [id(4)]
//	SConnectFail [id(4)] [reason_len(2)] [reason]
//	SData        [id(4)] [data]
//	SClose       [id(4)] [flags(1)]   1 = remote closed, 2 = full close
package mux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"mirage/internal/proto"
	"mirage/internal/record"
)

const (
	closeFlagRemote = 1
	closeFlagFull   = 2

	dialTimeout   = 15 * time.Second
	connectWait   = 30 * time.Second
	inboundBuffer = 1024
)

// ---------- shared frame helpers ----------

func encU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func encodeConnect(id uint32, addr string) []byte {
	b := make([]byte, 4+2+len(addr))
	binary.BigEndian.PutUint32(b[0:4], id)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(addr)))
	copy(b[6:], addr)
	return b
}

func encodeOK(id uint32) []byte { return encU32(id) }

func encodeFail(id uint32, reason string) []byte {
	b := make([]byte, 4+2+len(reason))
	binary.BigEndian.PutUint32(b[0:4], id)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(reason)))
	copy(b[6:], reason)
	return b
}

func encodeData(id uint32, data []byte) []byte {
	b := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(b[0:4], id)
	copy(b[4:], data)
	return b
}

func encodeClose(id uint32, flags byte) []byte {
	b := make([]byte, 5)
	binary.BigEndian.PutUint32(b[0:4], id)
	b[4] = flags
	return b
}

// ---------- client side ----------

// ClientMux turns record-stream frames into virtual net.Conns.
type ClientMux struct {
	fc     *record.FramedConn
	mu     sync.Mutex
	conns  map[uint32]*Conn
	nextID uint32
	closed bool
}

// NewClient wraps the record stream in a client-side multiplexer.
func NewClient(fc *record.FramedConn) *ClientMux {
	return &ClientMux{fc: fc, conns: make(map[uint32]*Conn)}
}

// Conn is one tunneled TCP connection.
type Conn struct {
	mux   *ClientMux
	id    uint32
	in    chan []byte
	ready chan error
	once  sync.Once
	done  chan struct{}
}

func (m *ClientMux) register(id uint32, c *Conn) {
	m.mu.Lock()
	m.conns[id] = c
	m.mu.Unlock()
}

func (m *ClientMux) unregister(id uint32) {
	m.mu.Lock()
	delete(m.conns, id)
	m.mu.Unlock()
}

func (m *ClientMux) lookup(id uint32) *Conn {
	m.mu.Lock()
	c := m.conns[id]
	m.mu.Unlock()
	return c
}

// Dial asks the server to open a TCP connection and returns a virtual Conn.
func (m *ClientMux) Dial(network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("mux: unsupported network %q", network)
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("mux: session closed")
	}
	m.nextID++
	id := m.nextID
	m.mu.Unlock()

	c := &Conn{
		mux:   m,
		id:    id,
		in:    make(chan []byte, inboundBuffer),
		ready: make(chan error, 1),
		done:  make(chan struct{}),
	}
	m.register(id, c)

	if err := m.fc.WriteRecord(proto.RecSConnect, encodeConnect(id, address)); err != nil {
		m.unregister(id)
		return nil, err
	}
	select {
	case err := <-c.ready:
		if err != nil {
			m.unregister(id)
			return nil, err
		}
		return c, nil
	case <-time.After(connectWait):
		m.unregister(id)
		return nil, errors.New("mux: connect timeout")
	}
}

// HandleFrame dispatches one record received from the tunnel. It is called by
// the session's single read loop, so it must not block on the network.
func (m *ClientMux) HandleFrame(rtype byte, payload []byte) {
	if len(payload) < 4 {
		return
	}
	id := binary.BigEndian.Uint32(payload[0:4])
	switch rtype {
	case proto.RecSConnectOK:
		if c := m.lookup(id); c != nil {
			select {
			case c.ready <- nil:
			default:
			}
		}
	case proto.RecSConnectFail:
		if c := m.lookup(id); c != nil {
			reason := "connect failed"
			if len(payload) >= 6 {
				rl := int(binary.BigEndian.Uint16(payload[4:6]))
				if 6+rl <= len(payload) {
					reason = string(payload[6 : 6+rl])
				}
			}
			select {
			case c.ready <- errors.New(reason):
			default:
			}
			m.unregister(id)
		}
	case proto.RecSData:
		if c := m.lookup(id); c != nil {
			c.deliver(payload[4:])
		}
	case proto.RecSClose:
		if c := m.lookup(id); c != nil {
			c.shutdown()
			m.unregister(id)
		}
	}
}

// Close tears down every virtual connection. Safe to call once, at stream end.
func (m *ClientMux) Close() {
	m.mu.Lock()
	m.closed = true
	conns := m.conns
	m.conns = make(map[uint32]*Conn)
	m.mu.Unlock()
	for _, c := range conns {
		c.shutdown()
	}
}

func (c *Conn) deliver(data []byte) {
	select {
	case c.in <- data:
	case <-c.done:
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	// Prefer already-buffered data so a shutdown cannot discard it.
	select {
	case data := <-c.in:
		return copy(b, data), nil
	default:
	}
	select {
	case data := <-c.in:
		return copy(b, data), nil
	case <-c.done:
		return 0, io.EOF
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, errors.New("mux: connection closed")
	default:
	}
	if len(b) == 0 {
		return 0, nil
	}
	if err := c.mux.fc.WriteRecord(proto.RecSData, encodeData(c.id, b)); err != nil {
		c.shutdown()
		return 0, err
	}
	return len(b), nil
}

func (c *Conn) Close() error {
	c.shutdown()
	c.mux.unregister(c.id)
	// best effort: tell the server we are done
	_ = c.mux.fc.WriteRecord(proto.RecSClose, encodeClose(c.id, closeFlagFull))
	return nil
}

func (c *Conn) shutdown() {
	c.once.Do(func() { close(c.done) })
}

func (c *Conn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *Conn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "mirage-mux" }
func (dummyAddr) String() string  { return "mirage-mux" }

// ---------- server side ----------

// ServerMux dials real connections on behalf of the client.
type ServerMux struct {
	fc    *record.FramedConn
	mu    sync.Mutex
	conns map[uint32]*serverConn
}

type serverConn struct {
	rc  net.Conn
	mux *ServerMux
	id  uint32
}

// NewServer wraps the record stream in a server-side multiplexer.
func NewServer(fc *record.FramedConn) *ServerMux {
	return &ServerMux{fc: fc, conns: make(map[uint32]*serverConn)}
}

// HandleFrame dispatches one client record received from the tunnel. Called by
// the session's single read loop; never blocks on the network for long.
func (m *ServerMux) HandleFrame(rtype byte, payload []byte) {
	if len(payload) < 4 {
		return
	}
	id := binary.BigEndian.Uint32(payload[0:4])
	switch rtype {
	case proto.RecSConnect:
		if len(payload) < 6 {
			return
		}
		al := int(binary.BigEndian.Uint16(payload[4:6]))
		if 6+al > len(payload) {
			return
		}
		addr := string(payload[6 : 6+al])
		m.handleConnect(id, addr)
	case proto.RecSData:
		if sc := m.lookup(id); sc != nil {
			if _, err := sc.rc.Write(payload[4:]); err != nil {
				m.kill(id)
			}
		}
	case proto.RecSClose:
		m.kill(id)
	}
}

// Close drops every tunneled connection.
func (m *ServerMux) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, sc := range m.conns {
		sc.rc.Close()
		delete(m.conns, id)
	}
}

func (m *ServerMux) handleConnect(id uint32, addr string) {
	rc, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		m.fc.WriteRecord(proto.RecSConnectFail, encodeFail(id, err.Error()))
		return
	}
	sc := &serverConn{rc: rc, mux: m, id: id}
	m.mu.Lock()
	m.conns[id] = sc
	m.mu.Unlock()
	if err := m.fc.WriteRecord(proto.RecSConnectOK, encodeOK(id)); err != nil {
		m.kill(id)
		return
	}
	go sc.pump()
}

func (m *ServerMux) lookup(id uint32) *serverConn {
	m.mu.Lock()
	sc := m.conns[id]
	m.mu.Unlock()
	return sc
}

func (m *ServerMux) kill(id uint32) {
	m.mu.Lock()
	sc := m.conns[id]
	delete(m.conns, id)
	m.mu.Unlock()
	if sc != nil {
		sc.rc.Close()
		m.fc.WriteRecord(proto.RecSClose, encodeClose(id, closeFlagRemote))
	}
}

// pump copies the real connection back into the tunnel.
func (sc *serverConn) pump() {
	buf := make([]byte, 32*1024)
	for {
		n, err := sc.rc.Read(buf)
		if n > 0 {
			if werr := sc.mux.fc.WriteRecord(proto.RecSData, encodeData(sc.id, buf[:n])); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	sc.mux.kill(sc.id)
}
