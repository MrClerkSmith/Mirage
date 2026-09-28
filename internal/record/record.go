// Package record implements Mirage's inner record protocol: length-prefixed
// AEAD-protected frames carrying VPN packets and control messages.
//
// Wire format of one record:
//
//	+-------------------+----------------------------------+
//	| len (2 bytes, BE) |  ciphertext (len bytes)          |
//	+-------------------+----------------------------------+
//
// The plaintext inside the ciphertext is:
//
//	[type(1)] [payload] [padding] [pad_len(1)]
//
// - type is hidden from the DPI (it is encrypted).
// - pad_len mirrors TLS 1.3 record padding so frames can be padded to a
//   minimum size, blunting size-based traffic analysis.
// - The AEAD nonce is base_nonce XOR sequence_number, exactly like TLS 1.3 and
//   QUIC, so no random bytes are spent on the wire.
//
// Both directions keep their own sequence counter; when a counter crosses a
// configured threshold the key and nonce base are rotated through HKDF, which
// limits the amount of data protected by any single key.
package record

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"mirage/internal/hkdf"
	"mirage/internal/proto"
)

// Stream is one AEAD direction (client->server or server->client).
type Stream struct {
	aead       cipher.AEAD
	key        []byte // 32 bytes
	nonceBase  []byte // 12 bytes
	seq        uint64
	rekeyEvery uint64 // 0 = never
	padMin     int
}

// NewStream creates a direction from raw key material.
func NewStream(key, nonce []byte, rekeyEvery uint64, padMin int) (*Stream, error) {
	if len(key) != 32 || len(nonce) != 12 {
		return nil, fmt.Errorf("record: need 32-byte key and 12-byte nonce, got %d/%d", len(key), len(nonce))
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Stream{
		aead:       aead,
		key:        append([]byte(nil), key...),
		nonceBase:  append([]byte(nil), nonce...),
		rekeyEvery: rekeyEvery,
		padMin:     padMin,
	}, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seq returns the number of records sent/received in this direction so far.
func (s *Stream) Seq() uint64 { return s.seq }

// Seal encrypts payload as a full record ciphertext (without the 2-byte length).
func (s *Stream) Seal(rtype byte, payload []byte) []byte {
	padLen := s.padFor(len(payload))

	pt := make([]byte, 1+len(payload)+padLen+1)
	pt[0] = rtype
	copy(pt[1:], payload)
	// padding bytes are already zero
	pt[len(pt)-1] = byte(padLen)

	ct := s.aead.Seal(nil, s.nonce(s.seq), pt, nil)
	s.advance()
	return ct
}

// Open decrypts a record ciphertext produced by Seal on the peer side.
func (s *Stream) Open(ct []byte) (byte, []byte, error) {
	pt, err := s.aead.Open(nil, s.nonce(s.seq), ct, nil)
	s.advance()
	if err != nil {
		return 0, nil, fmt.Errorf("record: aead open: %w", err)
	}
	if len(pt) < 2 {
		return 0, nil, errors.New("record: plaintext too short")
	}
	padLen := int(pt[len(pt)-1])
	if len(pt) < padLen+2 {
		return 0, nil, errors.New("record: bad padding")
	}
	body := pt[:len(pt)-padLen-1]
	return body[0], body[1:], nil
}

func (s *Stream) padFor(payloadLen int) int {
	if s.padMin <= 0 {
		return 0
	}
	base := 1 + payloadLen + 1
	if base >= s.padMin {
		return 0
	}
	target := s.padMin
	if r := target % proto.PadBlock; r != 0 {
		target += proto.PadBlock - r
	}
	pad := target - base
	if pad > 255 {
		pad = 255
	}
	return pad
}

func (s *Stream) advance() {
	s.seq++
	if s.rekeyEvery > 0 && s.seq%s.rekeyEvery == 0 {
		s.rekey()
	}
}

func (s *Stream) rekey() {
	// Derive a fresh 32-byte key and 12-byte nonce base from the previous key,
	// bound to the sequence number at which the rotation happened.
	out := hkdf.Derive(hkdf.U64BE(s.seq), s.key, []byte("MIRAGE-REKEY"), 44)
	s.key = out[:32]
	s.nonceBase = out[32:44]
	aead, err := newAEAD(s.key)
	if err != nil {
		panic(fmt.Sprintf("record: rekey: %v", err))
	}
	s.aead = aead
}

func (s *Stream) nonce(seq uint64) []byte {
	n := make([]byte, 12)
	copy(n, s.nonceBase)
	v := binary.BigEndian.Uint64(n[4:]) ^ seq
	binary.BigEndian.PutUint64(n[4:], v)
	return n
}

// FramedConn is a net.Conn speaking the record protocol.
type FramedConn struct {
	raw    net.Conn
	send   *Stream
	recv   *Stream
	writeMu sync.Mutex // guards WriteRecord against concurrent writers
}

// New wraps an established (already TLS-protected) connection.
func New(raw net.Conn, send, recv *Stream) *FramedConn {
	return &FramedConn{raw: raw, send: send, recv: recv}
}

// Raw returns the underlying connection.
func (f *FramedConn) Raw() net.Conn { return f.raw }

// WriteRecord seals and frames one record. Safe for concurrent use.
func (f *FramedConn) WriteRecord(rtype byte, payload []byte) error {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()

	// Bound the payload *before* sealing: Seal advances the sequence counter
	// (and may rotate the key). Refusing a record after that would desync the
	// sender from the receiver for every following record.
	if 1+len(payload)+1+16 > proto.MaxRecordLen {
		return fmt.Errorf("record: payload %d exceeds max %d", len(payload), proto.MaxRecordLen)
	}

	ct := f.send.Seal(rtype, payload)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(ct)))
	if _, err := f.raw.Write(append(hdr[:], ct...)); err != nil {
		return err
	}
	return nil
}

// ReadRecord reads and decrypts one record.
func (f *FramedConn) ReadRecord() (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(f.raw, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n > proto.MaxRecordLen || n < 16 {
		return 0, nil, fmt.Errorf("record: bad frame length %d", n)
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(f.raw, ct); err != nil {
		return 0, nil, err
	}
	return f.recv.Open(ct)
}

// Close closes the underlying connection.
func (f *FramedConn) Close() error { return f.raw.Close() }
