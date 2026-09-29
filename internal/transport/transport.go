// Package transport wraps the inner tunnel protocol in different outer
// transports: a raw TLS stream, WebSocket frames over TLS, or a gRPC-style
// stream over HTTP/2. All three carry the same encrypted records; the choice
// only changes what the connection looks like to an observer.
package transport

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Kind selects the outer transport.
type Kind string

const (
	// Raw sends records directly over the TLS connection. Looks like ordinary
	// HTTPS to a passive observer.
	Raw Kind = "raw"
	// WS carries records inside WebSocket frames. Looks like a wss connection
	// and works through reverse proxies and CDNs.
	WS Kind = "ws"
	// GRPC carries records inside gRPC messages over HTTP/2. Looks like an API
	// call to the SNI domain.
	GRPC Kind = "grpc"
)

// DefaultPath is the tunnel endpoint used when a config has no "path".
const DefaultPath = "/mirage"

// Parse converts a config string into a Kind.
func Parse(s string) (Kind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(Raw):
		return Raw, nil
	case string(WS), "websocket":
		return WS, nil
	case string(GRPC):
		return GRPC, nil
	}
	return "", errors.New("transport: unknown " + s + " (want raw, ws or grpc)")
}

// ClientALPN is the ALPN list the client must offer for this transport so the
// negotiated protocol is the one the transport needs.
func (k Kind) ClientALPN() []string {
	switch k {
	case WS:
		return []string{"http/1.1"}
	case GRPC:
		return []string{"h2"}
	default:
		return []string{"h2", "http/1.1"}
	}
}

// ServerALPN is the ALPN list the server should advertise. Raw inbounds offer
// only HTTP/1.1 because their cover site replays buffered request bytes, which
// the HTTP/2 framer cannot parse.
func (k Kind) ServerALPN() []string {
	switch k {
	case Raw:
		return []string{"http/1.1"}
	default:
		return []string{"h2", "http/1.1"}
	}
}

// IsHTTP reports whether the transport rides on HTTP and therefore dispatches
// requests itself instead of handing the raw stream to the caller.
func (k Kind) IsHTTP() bool {
	return k == WS || k == GRPC
}

// Dial wraps an established TLS connection into a client stream.
func Dial(kind Kind, conn net.Conn, host, path string) (net.Conn, error) {
	if path == "" {
		path = DefaultPath
	}
	switch kind {
	case Raw, "":
		return conn, nil
	case WS:
		return wsDial(conn, host, path)
	case GRPC:
		return grpcDial(conn, host, path)
	}
	return nil, errors.New("transport: unknown kind " + string(kind))
}

// ServeHTTP dispatches one TLS connection of an HTTP-based transport: a
// request on path is upgraded into a tunnel stream and handed to tunnel,
// everything else is served by cover.
func ServeHTTP(kind Kind, conn net.Conn, path string, cover http.Handler, tunnel func(net.Conn)) error {
	if path == "" {
		path = DefaultPath
	}
	switch kind {
	case WS:
		return serveWS(conn, path, cover, tunnel)
	case GRPC:
		return serveGRPC(conn, path, cover, tunnel)
	}
	return errors.New("transport: not an http transport: " + string(kind))
}

// singleConnListener lets http.Serve serve exactly one already-accepted
// connection. Accept hands the connection out once (unwrapped, so net/http's
// *tls.Conn assertions and ALPN dispatch still work) and then blocks until
// markDone, which the caller fires when the connection's work is over. Without
// the block, http.Serve would return as soon as Accept failed a second time and
// close the connection before its response had been flushed.
type singleConnListener struct {
	conn   net.Conn
	handed bool
	once   sync.Once
	done   chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.handed {
		l.handed = true
		return l.conn, nil
	}
	<-l.done
	return nil, errors.New("transport: listener closed")
}

// markDone lets a blocked Accept return. Idempotent.
func (l *singleConnListener) markDone() {
	l.once.Do(func() { close(l.done) })
}

func (l *singleConnListener) Close() error {
	l.markDone()
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
