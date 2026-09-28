// Package handshake implements Mirage's inner authenticated key exchange that
// runs on top of the TLS transport.
//
// Client -> server (inside TLS):
//
//	[nonce(12)] [AEAD(K0) over: version | timestamp | client X25519 pub | psk_id]
//
// K0 comes from the PSK alone, so this first message authenticates the client
// to the server. The ephemeral key contributes a Diffie-Hellman secret with the
// server's pinned static key, and the session keys are derived from
// HKDF(PSK || ECDH, salt=nonce). The server replies with a Welcome control
// record encrypted under the session keys, which gives the client key
// confirmation.
//
// If the client cannot authenticate, the server signals ErrNotTunnel so the
// caller falls back to serving the cover website: to any probe the port looks
// like an ordinary HTTPS host.
package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"mirage/internal/control"
	"mirage/internal/hkdf"
	"mirage/internal/proto"
	"mirage/internal/record"
)

// Clock skew tolerated on the AuthInit timestamp, to stop replaying captured
// handshakes.
const MaxSkew = 5 * time.Minute

// ErrNotTunnel means the peer did not produce a valid AuthInit; the caller
// should treat the connection as ordinary web traffic.
var ErrNotTunnel = errors.New("handshake: not a tunnel client")

var authInitInfo = []byte("MIRAGE-AUTHINIT")

// ClientParams are the client-side secrets and pinned server material.
type ClientParams struct {
	PSK            []byte
	PSKID          string
	ServerX25519Pub *ecdh.PublicKey // pinned static key of the hidden server
}

// ClientInfo is what the server learns from a valid AuthInit.
type ClientInfo struct {
	PSKID     string
	Ephemeral *ecdh.PublicKey
	Timestamp int64
	Nonce     []byte // 12 bytes, reused as session salt
}

// ServerParams are the server-side secrets.
type ServerParams struct {
	PSKs       map[string][]byte // psk_id -> psk
	StaticPriv *ecdh.PrivateKey  // static X25519 key matching the client's pin
}

// Client performs the handshake over an established TLS connection and returns
// the record stream plus the server's welcome (assigned IP, DNS, MTU).
func Client(conn net.Conn, p ClientParams, padMin, rekeyRecords int) (*record.FramedConn, *control.WelcomeInfo, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	var pt [proto.AuthInitLen]byte
	pt[0] = proto.Version
	binary.BigEndian.PutUint64(pt[proto.AuthInitTimeOff:proto.AuthInitPubOff], uint64(time.Now().Unix()))
	copy(pt[proto.AuthInitPubOff:proto.AuthInitPSKIDOff], eph.PublicKey().Bytes())
	id := []byte(p.PSKID)
	if len(id) > proto.AuthInitPSKIDLen {
		return nil, nil, errors.New("handshake: psk_id too long")
	}
	copy(pt[proto.AuthInitPSKIDOff:], id)

	k0 := hkdf.Derive(nil, p.PSK, authInitInfo, 32)
	aead, err := newAEAD(k0)
	if err != nil {
		return nil, nil, err
	}
	var nonce [proto.AuthInitNonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, nil, err
	}
	ct := aead.Seal(nil, nonce[:], pt[:], proto.AuthInitAAD)

	wire := make([]byte, 0, len(nonce)+len(ct))
	wire = append(wire, nonce[:]...)
	wire = append(wire, ct...)
	if _, err := conn.Write(wire); err != nil {
		return nil, nil, err
	}

	c2s, s2c, err := deriveKeys(p.PSK, eph, p.ServerX25519Pub, nonce[:], padMin, rekeyRecords)
	if err != nil {
		return nil, nil, err
	}
	fc := record.New(conn, c2s, s2c)

	// The first record from the server must be the welcome message.
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	rtype, payload, err := fc.ReadRecord()
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		fc.Close()
		return nil, nil, err
	}
	if rtype != proto.RecControl {
		fc.Close()
		return nil, nil, errors.New("handshake: expected welcome control record")
	}
	info, err := control.ParseWelcome(payload)
	if err != nil {
		fc.Close()
		return nil, nil, err
	}
	return fc, info, nil
}

// Server performs the handshake on an already-TLS-accepted connection.
// If the peer is not an authenticated client it returns ErrNotTunnel together
// with the bytes already consumed, which the caller must replay to whatever
// cover service it runs instead.
func Server(conn net.Conn, p ServerParams, padMin, rekeyRecords int) (*record.FramedConn, *ClientInfo, []byte, error) {
	buf := make([]byte, proto.AuthInitWireLen)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err := io.ReadFull(conn, buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		// Whatever the peer sent (probably an HTTP request) is replayed to the
		// cover website, so only the bytes actually read are handed back.
		return nil, nil, buf[:n], ErrNotTunnel
	}

	nonce := buf[:proto.AuthInitNonceLen]
	ct := buf[proto.AuthInitNonceLen:]

	for id, psk := range p.PSKs {
		k0 := hkdf.Derive(nil, psk, authInitInfo, 32)
		aead, err := newAEAD(k0)
		if err != nil {
			continue
		}
		pt, err := aead.Open(nil, nonce, ct, proto.AuthInitAAD)
		if err != nil || len(pt) != proto.AuthInitLen {
			continue
		}
		if pt[0] != proto.Version {
			continue
		}
		ts := int64(binary.BigEndian.Uint64(pt[proto.AuthInitTimeOff:proto.AuthInitPubOff]))
		if skew(ts) > MaxSkew {
			continue
		}
		gotID := string(trimZero(pt[proto.AuthInitPSKIDOff:]))
		if gotID != id {
			continue
		}
		eph, err := ecdh.X25519().NewPublicKey(pt[proto.AuthInitPubOff:proto.AuthInitPSKIDOff])
		if err != nil {
			continue
		}
		if !replayOK(eph.Bytes(), ts) {
			continue
		}
		shared, err := p.StaticPriv.ECDH(eph)
		if err != nil {
			continue
		}
		c2s, s2c, err := deriveKeysReverse(psk, shared, nonce, padMin, rekeyRecords)
		if err != nil {
			continue
		}
		return record.New(conn, s2c, c2s), &ClientInfo{
			PSKID:     gotID,
			Ephemeral: eph,
			Timestamp: ts,
			Nonce:     append([]byte(nil), nonce...),
		}, buf, nil
	}
	return nil, nil, buf, ErrNotTunnel
}

// SendWelcome is used by the server after it has allocated an IP for the peer.
func SendWelcome(fc *record.FramedConn, assignedIP, dns string, mtu int) error {
	return fc.WriteRecord(proto.RecControl, control.Welcome(assignedIP, dns, mtu))
}

func skew(ts int64) time.Duration {
	d := time.Since(time.Unix(ts, 0))
	if d < 0 {
		d = -d
	}
	return d
}

func trimZero(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

// deriveKeys runs the client-side KDF and returns (client->server, server->client).
func deriveKeys(psk []byte, eph *ecdh.PrivateKey, serverPub *ecdh.PublicKey, nonce []byte, padMin, rekeyRecords int) (*record.Stream, *record.Stream, error) {
	shared, err := eph.ECDH(serverPub)
	if err != nil {
		return nil, nil, err
	}
	return deriveBoth(psk, shared, nonce, padMin, rekeyRecords)
}

// deriveKeysReverse is the server-side counterpart, using the already computed
// shared secret. It returns the same (client->server, server->client) order.
func deriveKeysReverse(psk, shared, nonce []byte, padMin, rekeyRecords int) (*record.Stream, *record.Stream, error) {
	return deriveBoth(psk, shared, nonce, padMin, rekeyRecords)
}

func deriveBoth(psk, shared, nonce []byte, padMin, rekeyRecords int) (*record.Stream, *record.Stream, error) {
	ikm := make([]byte, 0, len(psk)+len(shared))
	ikm = append(ikm, psk...)
	ikm = append(ikm, shared...)

	c2s := hkdf.Derive(nonce, ikm, []byte("MIRAGE-C2S"), 44)
	s2c := hkdf.Derive(nonce, ikm, []byte("MIRAGE-S2C"), 44)

	out1, err := record.NewStream(c2s[:32], c2s[32:44], uint64(rekeyRecords), padMin)
	if err != nil {
		return nil, nil, err
	}
	out2, err := record.NewStream(s2c[:32], s2c[32:44], uint64(rekeyRecords), padMin)
	if err != nil {
		return nil, nil, err
	}
	return out1, out2, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// replayOK records the client's ephemeral public key and refuses duplicates
// inside the replay window. Fresh keys are expected on every session.
var (
	replayMu   sync.Mutex
	replaySeen = make(map[[32]byte]int64) // ephemeral key -> expiry unix seconds
)

func replayOK(pub []byte, ts int64) bool {
	var k [32]byte
	copy(k[:], pub)

	replayMu.Lock()
	defer replayMu.Unlock()

	now := time.Now().Unix()
	for pk, exp := range replaySeen {
		if exp < now {
			delete(replaySeen, pk)
		}
	}
	if _, ok := replaySeen[k]; ok {
		return false
	}
	replaySeen[k] = now + 600
	return true
}

