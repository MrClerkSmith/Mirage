package hkdf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 5869 A.1: HKDF-SHA256 with the standard first test vector.
func TestRFC5869A1(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")
	want, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a" +
		"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
		"34007208d5b887185865")

	prk := Extract(salt, ikm)
	wantPRK, _ := hex.DecodeString("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	if !bytes.Equal(prk, wantPRK) {
		t.Fatalf("extract: got %x, want %x", prk, wantPRK)
	}
	got := Expand(prk, info, 42)
	if !bytes.Equal(got, want) {
		t.Fatalf("expand: got %x, want %x", got, want)
	}
}

func TestDeriveProperties(t *testing.T) {
	a := Derive(nil, []byte("ikm"), []byte("info"), 64)
	if len(a) != 64 {
		t.Fatalf("length: got %d", len(a))
	}
	b := Derive(nil, []byte("ikm"), []byte("other"), 64)
	if bytes.Equal(a, b) {
		t.Fatal("different info must give different output")
	}
	c := Derive(nil, []byte("different ikm"), []byte("info"), 64)
	if bytes.Equal(a, c) {
		t.Fatal("different ikm must give different output")
	}
	d := Derive([]byte("salt"), []byte("ikm"), []byte("info"), 64)
	if bytes.Equal(a, d) {
		t.Fatal("different salt must give different output")
	}
	// Lengths that span multiple HMAC blocks.
	if got := Derive(nil, []byte("ikm"), []byte("i"), 1); len(got) != 1 {
		t.Fatalf("short length: got %d", len(got))
	}
	if got := Derive(nil, []byte("ikm"), []byte("i"), 200); len(got) != 200 {
		t.Fatalf("long length: got %d", len(got))
	}
}

func TestU64BE(t *testing.T) {
	if got := U64BE(1); !bytes.Equal(got, []byte{0, 0, 0, 0, 0, 0, 0, 1}) {
		t.Fatalf("u64be(1) = %x", got)
	}
}
