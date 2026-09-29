package server

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"

	"mirage/internal/certs"
	"mirage/internal/control"
	"mirage/internal/cover"
	"mirage/internal/handshake"
	"mirage/internal/proto"
	"mirage/internal/record"
	"mirage/internal/tlscam"
	"mirage/internal/transport"
)

const (
	testDomain = "mirage.test"
	testPath   = "/mirage"
)

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

// startServer mimics Server.handle without touching TUN: TLS handshake, then
// the chosen outer transport, the inner handshake, the welcome, and an echo of
// every record back to the client.
func startServer(t *testing.T, m *testMaterial, kind transport.Kind) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	site, err := cover.New("", "")
	if err != nil {
		t.Fatal(err)
	}

	runTunnel := func(stream net.Conn) {
		fc, _, _, err := handshake.Server(stream, handshake.ServerParams{
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
				if kind.IsHTTP() {
					_ = transport.ServeHTTP(kind, tlsConn, testPath, site, runTunnel)
					return
				}
				runTunnel(tlsConn)
			}()
		}
	}()
	return ln.Addr().String()
}

// connect dials the server and returns an authenticated session.
func connect(t *testing.T, addr string, m *testMaterial, kind transport.Kind) (*record.FramedConn, *control.WelcomeInfo) {
	t.Helper()
	tcp, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(tcp, tlscam.ClientConfigALPN(testDomain, m.fingerprint, kind.ClientALPN()))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	stream, err := transport.Dial(kind, tlsConn, testDomain, testPath)
	if err != nil {
		t.Fatalf("transport %s: %v", kind, err)
	}
	fc, info, err := handshake.Client(stream, handshake.ClientParams{
		PSK:             m.psk,
		PSKID:           "client1",
		ServerX25519Pub: m.staticPub,
	}, 0, 0)
	if err != nil {
		t.Fatalf("inner handshake: %v", err)
	}
	return fc, info
}

// roundTrip sends a record through the tunnel and expects it echoed back.
func roundTrip(t *testing.T, fc *record.FramedConn) {
	t.Helper()
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

func testTransport(t *testing.T, kind transport.Kind) {
	m := newMaterial(t)
	addr := startServer(t, m, kind)
	fc, info := connect(t, addr, m, kind)
	if info.AssignedIP != "10.7.0.2/24" {
		t.Fatalf("assigned ip: got %q, want 10.7.0.2/24", info.AssignedIP)
	}
	roundTrip(t, fc)
}

func TestEndToEndRaw(t *testing.T)  { testTransport(t, transport.Raw) }
func TestEndToEndWS(t *testing.T)   { testTransport(t, transport.WS) }
func TestEndToEndGRPC(t *testing.T) { testTransport(t, transport.GRPC) }

// TestCoverOverWS checks that a plain HTTP request to a ws inbound is served
// the cover website instead of the tunnel.
func TestCoverOverWS(t *testing.T) {
	m := newMaterial(t)
	addr := startServer(t, m, transport.WS)

	status, body := coverProbe(t, addr, "/other")
	if status != "200" {
		t.Fatalf("cover status: %q", status)
	}
	if !bytes.Contains(body, []byte("Mirage Networks")) {
		t.Fatalf("cover body: %q", body)
	}
}

// TestCoverOverGRPC checks that a plain HTTP request to a grpc inbound is
// served the cover website instead of the tunnel.
func TestCoverOverGRPC(t *testing.T) {
	m := newMaterial(t)
	addr := startServer(t, m, transport.GRPC)

	status, body := coverProbe(t, addr, "/other")
	if status != "200" {
		t.Fatalf("cover status: %q", status)
	}
	if !bytes.Contains(body, []byte("Mirage Networks")) {
		t.Fatalf("cover body: %q", body)
	}
}
func coverProbe(t *testing.T, addr, path string) (string, []byte) {
	t.Helper()
	tcp, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	tlsConn := tls.Client(tcp, &tls.Config{
		ServerName:         testDomain,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, testDomain); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tlsConn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(br)
	fields := bytes.SplitN([]byte(line), []byte(" "), 3)
	if len(fields) < 2 {
		t.Fatalf("bad status line: %q", line)
	}
	return string(fields[1]), body
}

// TestWrongPSK makes sure a stolen client id without the PSK cannot tunnel.
func TestWrongPSK(t *testing.T) {
	m := newMaterial(t)
	addr := startServer(t, m, transport.Raw)

	tcp, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()

	tlsConn := tls.Client(tcp, tlscam.ClientConfig(testDomain, m.fingerprint))
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
