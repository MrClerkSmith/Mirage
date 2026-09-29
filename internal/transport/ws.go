package transport

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// handshakeTimeout bounds how long a connection may take to send its request
// line and headers before it is treated as slow.
const handshakeTimeout = 15 * time.Second

// idleTimeout bounds how long an idle keep-alive connection is kept open before
// it is closed. Tunnel connections are hijacked, so this only affects the cover
// requests.
const idleTimeout = 60 * time.Second

// wsGUID is the magic string the WebSocket handshake appends to the key, per
// RFC 6455 section 1.3.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsAccept computes the Sec-WebSocket-Accept value for a client key.
func wsAccept(clientKey string) string {
	sum := sha1.Sum([]byte(clientKey + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// headerHasToken reports whether a header value contains a comma-separated
// token (used for Upgrade/Connection).
func headerHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// isWSUpgrade tells whether a request is a WebSocket upgrade request.
func isWSUpgrade(r *http.Request) bool {
	return headerHasToken(r.Header.Get("Upgrade"), "websocket") &&
		headerHasToken(r.Header.Get("Connection"), "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != ""
}

// wsDial performs the client side of the WebSocket handshake on an established
// TLS connection and returns a framed stream.
func wsDial(conn net.Conn, host, path string) (net.Conn, error) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	clientKey := base64.StdEncoding.EncodeToString(key)

	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + clientKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(line, "101") {
		return nil, errors.New("ws: server did not upgrade: " + strings.TrimSpace(line))
	}
	accepted := false
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-accept:") {
			got := strings.TrimSpace(line[len("sec-websocket-accept:"):])
			if got != wsAccept(clientKey) {
				return nil, errors.New("ws: bad handshake accept value")
			}
			accepted = true
		}
	}
	if !accepted {
		return nil, errors.New("ws: no Sec-WebSocket-Accept in the response")
	}
	return newWSConn(conn, br, true), nil
}

// serveWS runs a one-connection HTTP/1.1 server: requests that upgrade on
// path become tunnel streams, everything else is served by cover.
func serveWS(conn net.Conn, path string, cover http.Handler, tunnel func(net.Conn)) error {
	ln := newSingleConnListener(conn)
	srv := &http.Server{
		ReadHeaderTimeout: handshakeTimeout,
		IdleTimeout:       idleTimeout,
		ConnState: func(_ net.Conn, state http.ConnState) {
			// The cover path: net/http closes the connection once the response
			// is flushed, which is when it is safe for us to unwind.
			if state == http.StateClosed {
				ln.markDone()
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isWSUpgrade(r) && r.URL.Path == path {
				hj, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "websocket: hijacking unsupported", http.StatusInternalServerError)
					return
				}
				c, buf, err := hj.Hijack()
				if err != nil {
					return
				}
				defer c.Close()
				resp := "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + wsAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\n" +
					"\r\n"
				if _, err := buf.WriteString(resp); err != nil {
					return
				}
				if err := buf.Flush(); err != nil {
					return
				}
				tunnel(newWSConn(c, buf.Reader, false))
				// Hijacked connections never report StateClosed, so signal the
				// listener ourselves once the tunnel is done.
				ln.markDone()
				return
			}
			cover.ServeHTTP(w, r)
		}),
	}
	srv.SetKeepAlivesEnabled(false)
	if err := http2.ConfigureServer(srv, &http2.Server{
		MaxConcurrentStreams: 256,
	}); err != nil {
		return err
	}
	return srv.Serve(ln)
}

// ---------- framing ----------

const (
	opBinary  = 0x2
	opClose   = 0x8
	opPing    = 0x9
	opPong    = 0xa
	maskBit   = 0x80
	frameMask = 0x0f
)

// wsReader pulls binary-frame payloads out of a WebSocket stream.
type wsReader struct {
	r         *bufio.Reader
	masked    bool
	mask      [4]byte
	pos       int // payload bytes consumed so far, for the mask
	remaining int // payload bytes left in the current frame
}

// nextFrame skips control frames and positions the reader at the payload of
// the next data frame.
func (w *wsReader) nextFrame() error {
	for {
		var head [2]byte
		if _, err := io.ReadFull(w.r, head[:]); err != nil {
			return err
		}
		opcode := head[0] & frameMask
		w.masked = head[1]&maskBit != 0
		length := int64(head[1] & 0x7f)
		switch length {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(w.r, ext[:]); err != nil {
				return err
			}
			length = int64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(w.r, ext[:]); err != nil {
				return err
			}
			length = int64(binary.BigEndian.Uint64(ext[:]))
		}
		w.mask = [4]byte{}
		if w.masked {
			if _, err := io.ReadFull(w.r, w.mask[:]); err != nil {
				return err
			}
		}
		switch opcode {
		case opClose:
			return io.EOF
		case opPing:
			// Pings are answered by the connection writer; here we just drop
			// the payload to keep the stream moving.
			if _, err := io.CopyN(io.Discard, w.r, length); err != nil {
				return err
			}
		case opPong:
			if _, err := io.CopyN(io.Discard, w.r, length); err != nil {
				return err
			}
		default:
			w.remaining = int(length)
			w.pos = 0
			return nil
		}
	}
}

func (w *wsReader) Read(p []byte) (int, error) {
	if w.remaining == 0 {
		if err := w.nextFrame(); err != nil {
			return 0, err
		}
	}
	if len(p) > w.remaining {
		p = p[:w.remaining]
	}
	n, err := w.r.Read(p)
	w.remaining -= n
	if w.masked {
		for i := 0; i < n; i++ {
			p[i] ^= w.mask[(w.pos+i)&3]
		}
	}
	w.pos += n
	return n, err
}

// wsConn is a net.Conn over a WebSocket. Each Write sends one binary frame;
// each Read returns payload bytes, spanning frames as needed.
type wsConn struct {
	conn    net.Conn
	reader  *wsReader
	client  bool // client->server frames must be masked
	writeMu sync.Mutex
}

func newWSConn(conn net.Conn, br *bufio.Reader, client bool) *wsConn {
	return &wsConn{
		conn:   conn,
		reader: &wsReader{r: br},
		client: client,
	}
}

func (c *wsConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *wsConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	const maskFlag = 0x80
	var mask [4]byte
	if c.client {
		if _, err := rand.Read(mask[:]); err != nil {
			return 0, err
		}
	}

	n := len(p)
	var hdr []byte
	switch {
	case n < 126:
		hdr = []byte{opBinary | 0x80, byte(n)}
	case n < 1<<16:
		hdr = []byte{opBinary | 0x80, 126, 0, 0}
		binary.BigEndian.PutUint16(hdr[2:], uint16(n))
	default:
		hdr = []byte{opBinary | 0x80, 127, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	if c.client {
		hdr[1] |= maskFlag
		hdr = append(hdr, mask[:]...)
	}
	if _, err := c.conn.Write(hdr); err != nil {
		return 0, err
	}
	if !c.client {
		return c.conn.Write(p)
	}
	masked := make([]byte, n)
	for i, b := range p {
		masked[i] = b ^ mask[i&3]
	}
	return c.conn.Write(masked)
}

func (c *wsConn) Close() error         { return c.conn.Close() }
func (c *wsConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *wsConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *wsConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *wsConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
