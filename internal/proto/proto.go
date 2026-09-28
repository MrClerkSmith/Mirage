// Package proto holds wire-format constants shared by all Mirage components.
package proto

// Protocol version of the inner (post-TLS) handshake.
const Version byte = 1

// Fixed size of the AuthInit plaintext (before AEAD), so the server knows how
// many bytes to read before it can decrypt anything:
//
//	version(1) + timestamp(8) + ephemeral public key(32) + psk_id(64)
const (
	AuthInitVersionOff = 0
	AuthInitTimeOff    = 1
	AuthInitPubOff     = 9
	AuthInitPSKIDOff   = 41
	AuthInitPSKIDLen   = 64
	AuthInitLen        = AuthInitPSKIDOff + AuthInitPSKIDLen // 105
	AuthInitNonceLen   = 12
	AuthInitWireLen    = AuthInitNonceLen + 16 + AuthInitLen // nonce + tag + plaintext = 133
)

// AEAD associated data for the AuthInit message.
var AuthInitAAD = []byte("MIRAGE-AUTHINIT-V1")

// Record types carried inside the AEAD ciphertext (first plaintext byte).
const (
	RecControl byte = iota
	RecIPv4
	RecIPv6
	// SOCKS5 multiplexing frames (driver-free mode).
	RecSConnect     // client -> server: open a connection
	RecSConnectOK   // server -> client: connection established
	RecSConnectFail // server -> client: dial failed
	RecSData        // either direction: payload
	RecSClose       // either direction: half/full close
)

// Control message payload is a tiny TLV stream: tag(1) len(2 BE) value.
const (
	CtrlStatus byte = iota + 1
	CtrlAssignedIP
	CtrlDNS
	CtrlMTU
	CtrlPing
	CtrlPong
	CtrlError
)

// Limits.
const (
	MaxRecordLen = 65535 // 2-byte length field ceiling
	PadBlock     = 16
	DefaultMTU   = 1400
)
