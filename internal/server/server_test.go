package server

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
	"mirage/internal/handshake"
	"mirage/internal/proto"
	"mirage/internal/tlscam"
)

const testDomain = "mirage.test"

type testMaterial struct {
	cert        tls.Certificate
	fingerprint string
	staticPriv  *ecdh.PrivateKey
	staticPub   *ecdh.PublicKey
	psk         []byte
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

// startServer mimics Server.handle without touching TUN: it performs the same
// TLS handshake, inner handshake and welcome, then echoes every record back.
func startServer(t *testing.T, m *testMaterial) string {
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

// TestEndToEndTunnel drives the whole chain: TLS to the server, the inner
// PSK+X25519 handshake through the pinned certificate, and a record round
// trip.
func TestEndToEndTunnel(t *testing.T) {
	m := newMaterial(t)
	addr := startServer(t, m)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, tlscam.ClientConfig(testDomain, m.fingerprint))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}

	fc, info, err := handshake.Client(tlsConn, handshake.ClientParams{
		PSK:             m.psk,
		PSKID:           "client1",
		ServerX25519Pub: m.staticPub,
	}, 0, 0)
	if err != nil {
		t.Fatalf("inner handshake: %v", err)
	}
	if info.AssignedIP != "10.7.0.2/24" {
		t.Fatalf("assigned ip: got %q, want 10.7.0.2/24", info.AssignedIP)
	}

	msg := []byte("hello through the tunnel")
	if err := fc.WriteRecord(proto.RecControl, msg); err != nil {
		t.Fatal(err)
	}
	rtype, payload, err := fc.ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	if rtype != proto.RecControl {
		t.Fatalf("record type: got %d, want %d", rtype, proto.RecControl)
	}
	if !bytes.Equal(payload, msg) {
		t.Fatalf("payload: got %q, want %q", payload, msg)
	}
	fc.Close()
}

// TestWrongPSK makes sure a stolen client id without the PSK cannot tunnel.
func TestWrongPSK(t *testing.T) {
	m := newMaterial(t)
	addr := startServer(t, m)

	conn, err := net.Dial("tcp", addr)
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
		PSK:             wrong,
		PSKID:           "client1",
		ServerX25519Pub: m.staticPub,
	}, 0, 0)
	if err == nil {
		t.Fatal("handshake with a wrong PSK must fail")
	}
}
