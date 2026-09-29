package transport

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// grpcHeaderTimeout bounds how long the client waits for the server to send
// the response headers that open the downlink.
const grpcHeaderTimeout = 15 * time.Second

// grpcIdleTimeout bounds how long an idle HTTP/2 connection is kept open. It
// must stay comfortably above the client's idle ping interval: record traffic
// keeps the connection alive, so only truly idle peers (cover requests) are
// closed.
const grpcIdleTimeout = 5 * time.Minute

// grpcDial opens a gRPC-style bidirectional stream over an established HTTP/2
// connection: the uplink records travel as messages in the request body, the
// downlink as messages in the response body.
func grpcDial(conn net.Conn, host, path string) (net.Conn, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("grpc: connection is not a *tls.Conn")
	}

	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			return tlsConn, nil
		},
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, "https://"+host+path, pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	type roundTrip struct {
		resp *http.Response
		err  error
	}
	ch := make(chan roundTrip, 1)
	go func() {
		resp, err := tr.RoundTrip(req)
		ch <- roundTrip{resp, err}
	}()

	var resp *http.Response
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		resp = r.resp
	case <-time.After(grpcHeaderTimeout):
		pw.Close()
		return nil, errors.New("grpc: no response headers in time")
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, errors.New("grpc: server returned " + resp.Status)
	}

	return &grpcStream{
		reader: &grpcReader{r: resp.Body},
		body:   resp.Body,
		pipe:   pw,
		conn:   tlsConn,
	}, nil
}

// serveGRPC runs a one-connection HTTP/2 server: a POST on path with the gRPC
// content type becomes a tunnel stream, everything else is served by cover.
func serveGRPC(conn net.Conn, path string, cover http.Handler, tunnel func(net.Conn)) error {
	ln := newSingleConnListener(conn)
	srv := &http.Server{
		ReadHeaderTimeout: handshakeTimeout,
		IdleTimeout:       grpcIdleTimeout,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				ln.markDone()
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == path {
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Grpc-Status", "0")
				w.WriteHeader(http.StatusOK)
				fl, _ := w.(http.Flusher)
				if fl != nil {
					fl.Flush()
				}
				tunnel(&grpcServerStream{
					reader: &grpcReader{r: r.Body},
					body:   r.Body,
					w:      &grpcResponseWriter{w: w, fl: fl},
				})
				if fl != nil {
					fl.Flush()
				}
				ln.markDone()
				return
			}
			cover.ServeHTTP(w, r)
		}),
	}
	if err := http2.ConfigureServer(srv, &http2.Server{
		MaxConcurrentStreams: 256,
	}); err != nil {
		return err
	}
	return srv.Serve(ln)
}

// ---------- framing: length-prefixed gRPC messages ----------

// grpcReader strips the 5-byte gRPC message header (compression flag + length)
// and yields message payloads back to back.
type grpcReader struct {
	r         io.Reader
	remaining int
}

func (g *grpcReader) Read(p []byte) (int, error) {
	if g.remaining == 0 {
		var head [5]byte
		if _, err := io.ReadFull(g.r, head[:]); err != nil {
			return 0, err
		}
		if head[0] != 0 {
			return 0, errors.New("grpc: compressed messages are not supported")
		}
		g.remaining = int(binary.BigEndian.Uint32(head[1:]))
	}
	if len(p) > g.remaining {
		p = p[:g.remaining]
	}
	n, err := g.r.Read(p)
	g.remaining -= n
	return n, err
}

// grpcResponseWriter writes gRPC messages through the HTTP/2 response writer.
type grpcResponseWriter struct {
	w  http.ResponseWriter
	fl http.Flusher
}

func (g *grpcResponseWriter) Write(p []byte) (int, error) {
	var head [5]byte
	binary.BigEndian.PutUint32(head[1:], uint32(len(p)))
	if _, err := g.w.Write(head[:]); err != nil {
		return 0, err
	}
	n, err := g.w.Write(p)
	if g.fl != nil {
		g.fl.Flush()
	}
	return n, err
}

// grpcStream is the client side: records go into the request body pipe and
// come back from the response body.
type grpcStream struct {
	reader *grpcReader
	body   io.ReadCloser
	pipe   *io.PipeWriter
	conn   net.Conn // underlying connection, closed when the stream ends
}

func (s *grpcStream) Read(p []byte) (int, error) { return s.reader.Read(p) }

func (s *grpcStream) Write(p []byte) (int, error) {
	var head [5]byte
	binary.BigEndian.PutUint32(head[1:], uint32(len(p)))
	if _, err := s.pipe.Write(head[:]); err != nil {
		return 0, err
	}
	return s.pipe.Write(p)
}

func (s *grpcStream) Close() error {
	s.pipe.Close()
	err := s.body.Close()
	s.conn.Close()
	return err
}

func (s *grpcStream) LocalAddr() net.Addr  { return nil }
func (s *grpcStream) RemoteAddr() net.Addr { return nil }

func (s *grpcStream) SetDeadline(t time.Time) error      { return nil }
func (s *grpcStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *grpcStream) SetWriteDeadline(t time.Time) error { return nil }

// grpcServerStream is the server side: records come from the request body and
// go back through the response writer.
type grpcServerStream struct {
	reader *grpcReader
	body   io.ReadCloser
	w      *grpcResponseWriter
}

func (s *grpcServerStream) Read(p []byte) (int, error) { return s.reader.Read(p) }

func (s *grpcServerStream) Write(p []byte) (int, error) { return s.w.Write(p) }

func (s *grpcServerStream) Close() error { return s.body.Close() }

func (s *grpcServerStream) LocalAddr() net.Addr  { return nil }
func (s *grpcServerStream) RemoteAddr() net.Addr { return nil }

func (s *grpcServerStream) SetDeadline(t time.Time) error      { return nil }
func (s *grpcServerStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *grpcServerStream) SetWriteDeadline(t time.Time) error { return nil }
