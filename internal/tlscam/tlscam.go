// Package tlscam builds the TLS 1.3 layer that makes Mirage look like ordinary
// HTTPS to a DPI, and sniffs the SNI out of a ClientHello so the decoy can
// route a connection without terminating it.
package tlscam

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var errMalformed = errors.New("tlscam: malformed TLS handshake")

// ClientConfig is the client's TLS configuration: it speaks TLS 1.3 to the
// decoy domain and pins the hidden server's certificate by SHA-256 instead of
// trusting any public CA.
func ClientConfig(decoyDomain, pinHex string) *tls.Config {
	return &tls.Config{
		ServerName:         decoyDomain,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true, // verification is the pin check below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("tlscam: server sent no certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if !strings.EqualFold(got, strings.TrimSpace(pinHex)) {
				return fmt.Errorf("tlscam: certificate pin mismatch (got %s)", got)
			}
			return nil
		},
	}
}

// ServerConfig is the hidden server's TLS configuration. It presents the
// certificate of the decoy domain through the relay.
func ServerConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlscam: load key pair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// CoverConfig is the decoy's TLS configuration for everyone who is not a
// tunnel client. The same certificate is served regardless of the SNI sent.
func CoverConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlscam: load cover key pair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// CertFingerprint returns the SHA-256 of the first certificate in a PEM file,
// hex encoded. This is what the client pins.
func CertFingerprint(certFile string) (string, error) {
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		return "", err
	}
	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			sum := sha256.Sum256(block.Bytes)
			return hex.EncodeToString(sum[:]), nil
		}
	}
	return "", errors.New("tlscam: no certificate found in pem file")
}

// SniffSNI reads the TLS ClientHello from r and returns the requested hostname
// together with every byte consumed, which the caller must replay to whatever
// backend ends up handling the connection. An empty SNI means the client did
// not send one (or the stream is not TLS): treat it as cover traffic.
func SniffSNI(r io.Reader) (sni string, replay []byte, err error) {
	br := bufio.NewReader(r)
	var replayBuf bytes.Buffer

	read := func(b []byte) error {
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		replayBuf.Write(b)
		return nil
	}

	var hdr [5]byte
	if err := read(hdr[:]); err != nil {
		return "", drainBuffered(br, replayBuf), err
	}
	if hdr[0] != 0x16 { // content type must be "handshake"
		return "", drainBuffered(br, replayBuf), nil
	}

	hs := make([]byte, 0, 2048)
	for {
		if hdr[0] != 0x16 {
			return "", drainBuffered(br, replayBuf), nil
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n <= 0 || n > 16384 {
			return "", drainBuffered(br, replayBuf), nil
		}
		body := make([]byte, n)
		if err := read(body); err != nil {
			return "", drainBuffered(br, replayBuf), err
		}
		hs = append(hs, body...)
		if len(hs) > 16384 {
			return "", drainBuffered(br, replayBuf), nil
		}

		if len(hs) >= 4 {
			msgType := hs[0]
			msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if msgType == 0x01 { // ClientHello
				if len(hs) >= 4+msgLen {
					sni, perr := parseClientHello(hs[4 : 4+msgLen])
					if perr != nil {
						return "", drainBuffered(br, replayBuf), nil
					}
					return sni, drainBuffered(br, replayBuf), nil
				}
				// ClientHello spans more records; keep reading.
			} else {
				return "", drainBuffered(br, replayBuf), nil
			}
		}

		if err := read(hdr[:]); err != nil {
			return "", drainBuffered(br, replayBuf), err
		}
	}
}

// drainBuffered appends anything the bufio.Reader has already read past the
// ClientHello so the caller does not lose those bytes when it takes over the
// raw connection.
func drainBuffered(br *bufio.Reader, buf *bytes.Buffer) []byte {
	if n := br.Buffered(); n > 0 {
		if b, err := br.Peek(n); err == nil {
			buf.Write(b)
		}
	}
	return buf.Bytes()
}

// parseClientHello extracts the SNI from a ClientHello body (i.e. starting
// right after the 4-byte handshake header).
func parseClientHello(ch []byte) (string, error) {
	c := &cursor{b: ch}
	c.u16()          // legacy_version
	c.bytes(32)      // random
	c.bytes(int(c.u8())) // legacy_session_id
	c.bytes(int(c.u16())) // cipher_suites
	c.bytes(int(c.u8()))  // legacy_compression_methods
	if c.err != nil {
		return "", c.err
	}
	extLen := int(c.u16())
	if c.err != nil {
		return "", c.err
	}
	end := c.pos + extLen
	if end > len(ch) {
		return "", errMalformed
	}
	for c.pos+4 <= end {
		typ := c.u16()
		elen := int(c.u16())
		if c.err != nil {
			return "", c.err
		}
		if c.pos+elen > end {
			return "", errMalformed
		}
		data := c.bytes(elen)
		if c.err != nil {
			return "", c.err
		}
		if typ == 0x0000 {
			return parseSNIExt(data)
		}
	}
	return "", nil
}

func parseSNIExt(data []byte) (string, error) {
	c := &cursor{b: data}
	c.u16() // server_name_list_length
	nameType := c.u8()
	if nameType != 0 { // 0 = host_name
		return "", nil
	}
	name := c.bytes(int(c.u16()))
	if c.err != nil {
		return "", c.err
	}
	return string(name), nil
}

type cursor struct {
	b   []byte
	pos int
	err error
}

func (c *cursor) u8() byte {
	if c.err != nil || c.pos+1 > len(c.b) {
		c.err = errMalformed
		return 0
	}
	v := c.b[c.pos]
	c.pos++
	return v
}

func (c *cursor) u16() uint16 {
	if c.err != nil || c.pos+2 > len(c.b) {
		c.err = errMalformed
		return 0
	}
	v := uint16(c.b[c.pos])<<8 | uint16(c.b[c.pos+1])
	c.pos += 2
	return v
}

func (c *cursor) bytes(n int) []byte {
	if c.err != nil || n < 0 || c.pos+n > len(c.b) {
		c.err = errMalformed
		return nil
	}
	v := c.b[c.pos : c.pos+n]
	c.pos += n
	return v
}
