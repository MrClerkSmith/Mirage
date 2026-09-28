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

// ServeExisting serves the website over a connection whose TLS handshake has
// already completed, replaying the bytes the inner handshake peeked. Used by
// the server for anything that fails to authenticate as a tunnel client.
func (s *Site) ServeExisting(conn net.Conn, replay []byte) {
	var c net.Conn = conn
	if len(replay) > 0 {
		c = &peekConn{r: io.MultiReader(bytes.NewReader(replay), conn), Conn: conn}
	}
	http.Serve(&singleConnListener{conn: c}, s.handler)
}

// peekConn overrides Read so already-buffered bytes are served first.
type peekConn struct {
	r io.Reader
	net.Conn
}

func (c *peekConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// singleConnListener lets http.Serve serve exactly one already-accepted
// connection: Accept hands it out once, then reports the listener as closed.
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, errors.New("cover: listener closed")
	}
	l.done = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error   { return l.conn.Close() }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
