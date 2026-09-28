package record

import (
	"bytes"
	"testing"

	"mirage/internal/proto"
)

func mkPair(t *testing.T, padMin, rekey int) (*Stream, *Stream) {
	t.Helper()
	key := bytes.Repeat([]byte{0xAB}, 32)
	nonce := bytes.Repeat([]byte{0xCD}, 12)
	send, err := NewStream(key, nonce, uint64(rekey), padMin)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := NewStream(key, nonce, uint64(rekey), padMin)
	if err != nil {
		t.Fatal(err)
	}
	return send, recv
}

func TestRoundTrip(t *testing.T) {
	send, recv := mkPair(t, 0, 0)
	cases := [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte{0x41}, 1400),
		{},
	}
	for i, in := range cases {
		ct := send.Seal(proto.RecIPv4, in)
		rtype, out, err := recv.Open(ct)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if rtype != proto.RecIPv4 || !bytes.Equal(in, out) {
			t.Fatalf("case %d: rtype=%d in=%x out=%x", i, rtype, in, out)
		}
	}
}

func TestTypeIsEncrypted(t *testing.T) {
	send, _ := mkPair(t, 0, 0)
	ct := send.Seal(proto.RecIPv6, []byte("payload"))
	if bytes.Contains(ct, []byte("payload")) {
		t.Fatal("payload leaked into ciphertext")
	}
	// The ciphertext of a small record must not be tiny.
	if len(ct) < 16+2 {
		t.Fatalf("ciphertext suspiciously short: %d", len(ct))
	}
}

func TestPadding(t *testing.T) {
	send, recv := mkPair(t, 64, 0)
	ct := send.Seal(proto.RecControl, []byte("ping"))
	if len(ct)%proto.PadBlock != 0 {
		t.Fatalf("padded ciphertext not a multiple of %d: %d", proto.PadBlock, len(ct))
	}
	if len(ct) < 64 {
		t.Fatalf("padded ciphertext below pad_min: %d", len(ct))
	}
	rtype, out, err := recv.Open(ct)
	if err != nil || rtype != proto.RecControl || string(out) != "ping" {
		t.Fatalf("padding broke round trip: %d %x %v", rtype, out, err)
	}
}

func TestRekey(t *testing.T) {
	send, recv := mkPair(t, 0, 10)
	// Send 12 records: the key must rotate after the 10th and still decrypt.
	for i := 0; i < 12; i++ {
		in := []byte("packet")
		ct := send.Seal(proto.RecIPv4, in)
		rtype, out, err := recv.Open(ct)
		if err != nil || rtype != proto.RecIPv4 || !bytes.Equal(in, out) {
			t.Fatalf("record %d after rekey: %d %x %v", i, rtype, out, err)
		}
	}
	if send.Seq() != 12 || recv.Seq() != 12 {
		t.Fatalf("sequence drift: send=%d recv=%d", send.Seq(), recv.Seq())
	}
}

func TestTamperDetected(t *testing.T) {
	send, recv := mkPair(t, 0, 0)
	ct := send.Seal(proto.RecIPv4, []byte("data"))
	ct[0] ^= 0xFF
	if _, _, err := recv.Open(ct); err == nil {
		t.Fatal("tampered record decrypted without error")
	}
}

func TestNonceUniqueness(t *testing.T) {
	send, _ := mkPair(t, 0, 0)
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		n := string(send.nonce(send.seq))
		if seen[n] {
			t.Fatalf("nonce reused at %d", i)
		}
		seen[n] = true
		send.seq++
	}
}
