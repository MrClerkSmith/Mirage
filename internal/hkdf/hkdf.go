// Package hkdf implements RFC 5869 HKDF with SHA-256 using only the standard
// library, so the project has zero crypto dependencies.
package hkdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

func sha256b(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// Extract returns HKDF-Extract(salt, ikm) as 32 bytes.
func Extract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	return sha256b(salt, ikm)
}

// Expand returns HKDF-Expand(prk, info, L) as L bytes.
func Expand(prk, info []byte, L int) []byte {
	out := make([]byte, 0, L+(L/sha256.Size+1)*len(info))
	var counter byte
	var prev []byte
	for len(out) < L {
		counter++
		block := make([]byte, 0, len(prev)+len(info)+1)
		block = append(block, prev...)
		block = append(block, info...)
		block = append(block, counter)
		prev = sha256b(prk, block)
		out = append(out, prev...)
	}
	return out[:L]
}

// Derive is the convenience wrapper: HKDF(salt, ikm, info) -> L bytes.
func Derive(salt, ikm, info []byte, L int) []byte {
	return Expand(Extract(salt, ikm), info, L)
}

// U64BE encodes an integer as 8 big-endian bytes (used as rekey salt).
func U64BE(n uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return b
}
