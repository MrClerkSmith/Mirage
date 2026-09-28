// Package tlscam makes the tunnel look like ordinary HTTPS: the outer layer is
// a real TLS 1.3 connection to the server domain, and the client pins the
// server's certificate by SHA-256 instead of trusting any public CA.
package tlscam

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ClientConfig is the client's TLS configuration: it speaks TLS 1.3 to the
// server domain and pins the server's certificate by SHA-256 instead of
// trusting any public CA.
func ClientConfig(domain, pinHex string) *tls.Config {
	return &tls.Config{
		ServerName:         domain,
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

// ServerConfig is the server's TLS configuration. It presents the certificate
// of the server domain.
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
