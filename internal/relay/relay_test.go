package relay

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"testing"

	"mirage/internal/certs"
	"mirage/internal/conf"
	"mirage/internal/handshake"
	"mirage/internal/proto"
	"mirage/internal/tlscam"
)

const testDomain = "decoy.test"

// testMaterial builds a self-signed certificate for the decoy domain plus the
// static X25519 key and PSK used by the hidden server.
type testMaterial struct {
	cert         tls.Certificate
	fingerprint  string
	staticPriv   *ecdh.PrivateKey
	staticPub    *ecdh.PublicKey
	psk          []byte
}

func newMaterial(t *testing.T) *testMaterial {
	t.Helper()
	cert, err := certs.SelfSigned(testDomain, []string{testDomain})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	psk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		t.Fatal(err)
	}
	return &testMaterial{
		cert:        cert,
		fingerprint: hex.EncodeToString(sum[:]),
		staticPriv:  priv,
		staticPub:   priv.PublicKey(),
		psk:         psk,
	}
}

// startHidden runs a fake hidden server: TLS handshake, inner handshake,
// welcome message, then an echo of every record the client sends.
func startHidden(t *testing.T, m *testMaterial) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn := tls.Server(conn, &tls.Config{
					Certificates: []tls.Certificate{m.cert},
					MinVersion:   tls.VersionTLS13,
					NextProtos:   []string{"h2", "http/1.1"},
				})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				fc, _, _, err := handshake.Server(tlsConn, handshake.ServerParams{
					PSKs:       map[string][]byte{"client1": m.psk},
					StaticPriv: m.staticPriv,
				}, 0, 0)
				if err != nil {
					return
				}
				if err := handshake.SendWelcome(fc, "10.7.0.2/24", "10.7.0.1", 1400); err != nil {
					return
				}
				for {
					rtype, payload, err := fc.ReadRecord()
					if err != nil {
						return
					}
					if err := fc.WriteRecord(rtype, payload); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// startDecoy runs the real decoy relay pointing at the hidden server.
func startDecoy(t *testing.T, hidden string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(&conf.DecoyConfig{
		Listen:       ln.Addr().String(),
		TunnelDomain: testDomain,
		ServerAddr:   hidden,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = r.ListenAndServe()
	}()
	return ln.Addr().String()
}

// TestEndToEndTunnel verifies the whole chain: the client talks TLS to the
// decoy, the decoy relays to the hidden server, the inner handshake
// authenticates, and records flow back encrypted.
func TestEndToEndTunnel(t *testing.T) {
	m := newMaterial(t)
	hidden := startHidden(t, m)
	decoy := startDecoy(t, hidden)

	conn, err := net.Dial("tcp", decoy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, tlscam.ClientConfig(testDomain, m.fingerprint))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls handshake through decoy: %v", err)
	}

	fc, info, err := handshake.Client(tlsConn, handshake.ClientParams{
		PSK:            m.psk,
		PSKID:          "client1",
		ServerX25519Pub: m.staticPub,
	}, 0, 0)
	if err != nil {
		t.Fatalf("inner handshake: %v", err)
	}
	if info.AssignedIP != "10.7.0.2/24" || info.DNS != "10.7.0.1" || info.MTU != 1400 {
		t.Fatalf("unexpected welcome: %+v", info)
	}

	payload := []byte("an IP packet, supposedly")
	if err := fc.WriteRecord(proto.RecIPv4, payload); err != nil {
		t.Fatal(err)
	}
	rtype, got, err := fc.ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	if rtype != proto.RecIPv4 || string(got) != string(payload) {
		t.Fatalf("echo mismatch: %d %x", rtype, got)
	}
}

// TestCoverPath verifies that a connection with a different SNI is served the
// ordinary cover website instead of the tunnel.
func TestCoverPath(t *testing.T) {
	m := newMaterial(t)
	hidden := startHidden(t, m)
	decoy := startDecoy(t, hidden)

	conn, err := net.Dial("tcp", decoy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "something-else.test",
		InsecureSkipVerify: true, // the cover certificate is ephemeral
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("cover tls handshake: %v", err)
	}
	req := "GET / HTTP/1.1\r\nHost: something-else.test\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tlsConn, req); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("Mirage Networks")) {
		t.Fatalf("cover site not served, got %q", string(body[:min(200, len(body))]))
	}
}

// TestWrongPSK verifies that a client with the wrong PSK cannot authenticate.
func TestWrongPSK(t *testing.T) {
	m := newMaterial(t)
	hidden := startHidden(t, m)
	decoy := startDecoy(t, hidden)

	conn, err := net.Dial("tcp", decoy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, tlscam.ClientConfig(testDomain, m.fingerprint))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}

	wrong := make([]byte, 32)
	copy(wrong, m.psk)
	wrong[0] ^= 0xFF
	_, _, err = handshake.Client(tlsConn, handshake.ClientParams{
		PSK:            wrong,
		PSKID:          "client1",
		ServerX25519Pub: m.staticPub,
	}, 0, 0)
	if err == nil {
		t.Fatal("handshake with a wrong PSK must fail")
	}
}
