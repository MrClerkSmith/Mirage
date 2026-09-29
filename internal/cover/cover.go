// Package cover serves the ordinary-looking website that any non-client sees
// when it connects to the server without a valid tunnel handshake. To an
// active DPI probe the service behaves exactly like a small HTTPS host.
package cover

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

const defaultPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mirage Networks</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; color: #1b2733; background: #f4f7fa; }
  main { max-width: 40rem; margin: 12vh auto; padding: 2rem; }
  h1 { font-size: 1.6rem; margin-bottom: .5rem; }
  p { line-height: 1.6; color: #41525f; }
  code { background: #e6edf3; padding: .1rem .35rem; border-radius: .25rem; }
</style>
</head>
<body>
<main>
  <h1>Mirage Networks</h1>
  <p>Edge acceleration and delivery services for growing applications.</p>
  <p>Status: <strong>operational</strong> &middot; Region: eu-central-1</p>
  <p>Need help? Open a ticket from your dashboard or email support@mirage-networks.example.</p>
</main>
</body>
</html>
`

// Site is the cover website.
type Site struct {
	handler http.Handler
}

// New builds a site: a reverse proxy, a static directory, or the built-in page.
func New(dir string, proxyTarget string) (*Site, error) {
	var h http.Handler
	switch {
	case proxyTarget != "":
		u, err := url.Parse(proxyTarget)
		if err != nil {
			return nil, fmt.Errorf("cover: bad proxy target: %w", err)
		}
		rp := httputil.NewSingleHostReverseProxy(u)
		h = rp
	case dir != "":
		h = http.FileServer(http.Dir(dir))
	default:
		h = http.HandlerFunc(serveDefault)
	}
	return &Site{handler: h}, nil
}

func serveDefault(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	fmt.Fprint(w, defaultPage)
}

// ServeHTTP serves the cover website to an ordinary HTTP request.
func (s *Site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// ServeExisting serves the website over a connection whose TLS handshake has
// already completed, replaying the bytes the inner handshake peeked. Used by
// the server for anything that fails to authenticate as a tunnel client.
func (s *Site) ServeExisting(conn net.Conn, replay []byte) {
	var c net.Conn = conn
	if len(replay) > 0 {
		c = &peekConn{r: io.MultiReader(bytes.NewReader(replay), conn), Conn: conn}
	}
	ln := newSingleConnListener(c)
	srv := &http.Server{
		Handler:     s.handler,
		IdleTimeout: idleTimeout,
		// Closing the connection once the response is flushed lets the single
		// connection listener above unwind.
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				ln.markDone()
			}
		},
	}
	srv.SetKeepAlivesEnabled(false)
	_ = srv.Serve(ln)
}

// idleTimeout bounds how long a probe connection may linger.
const idleTimeout = 60 * time.Second

// singleConnListener serves exactly one already-accepted connection: Accept
// hands it out once, then blocks until the connection is closed. Without the
// block, http.Serve returns as soon as Accept fails a second time and closes
// the connection before the response has been flushed.
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
	return nil, errors.New("cover: listener closed")
}

func (l *singleConnListener) markDone() {
	l.once.Do(func() { close(l.done) })
}

func (l *singleConnListener) Close() error {
	l.markDone()
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// peekConn overrides Read so already-buffered bytes are served first.
type peekConn struct {
	r io.Reader
	net.Conn
}

func (c *peekConn) Read(b []byte) (int, error) { return c.r.Read(b) }
