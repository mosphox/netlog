package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// certAuthority is a local MITM CA: one long-lived CA key/cert, and per-host
// leaf certificates minted on demand and signed by the CA so that Firefox
// (which must trust the CA) accepts the intercepted TLS connections.
//
// This is the same mechanism mitmproxy/Charles use. It only affects the leg
// between Firefox and this proxy; the upstream leg carries the real server's
// certificate chain, which this proxy verifies normally.
type certAuthority struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	caPEM      []byte // CA certificate in PEM form (the file to import into Firefox)
	leafKey    *rsa.PrivateKey
	leafKeyDER []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// loadOrCreateCA loads the CA from dataDir, creating it (and a shared leaf key)
// on first run.
func loadOrCreateCA(dataDir string) (*certAuthority, error) {
	caCertPath := filepath.Join(dataDir, "ca-cert.pem")
	caKeyPath := filepath.Join(dataDir, "ca-key.pem")

	if certPEM, err := os.ReadFile(caCertPath); err == nil {
		keyPEM, err := os.ReadFile(caKeyPath)
		if err != nil {
			return nil, fmt.Errorf("ca key missing next to ca cert: %w", err)
		}
		ca, err := caFromPEM(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		return ca, nil
	}

	// Fresh CA.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "netlogger local CA",
			Organization: []string{"netlogger"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(caCertPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(caKeyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return caFromPEM(certPEM, keyPEM)
}

func caFromPEM(certPEM, keyPEM []byte) (*certAuthority, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("invalid CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid CA key PEM")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &certAuthority{
		caCert:     caCert,
		caKey:      caKey,
		caPEM:      certPEM,
		leafKey:    leafKey,
		leafKeyDER: x509.MarshalPKCS1PrivateKey(leafKey),
		cache:      make(map[string]*tls.Certificate),
	}, nil
}

// exportCACert writes the CA certificate (public part only) to the given path,
// e.g. the Desktop, for importing into Firefox.
func (ca *certAuthority) exportCACert(path string) error {
	return os.WriteFile(path, ca.caPEM, 0o644)
}

// certForHost returns a leaf certificate valid for host, minting and caching it
// on first use. host may be "example.com" or an IP literal.
func (ca *certAuthority) certForHost(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.cache[host]; ok {
		return c, nil
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &ca.leafKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, ca.caCert.Raw},
		PrivateKey:  ca.leafKey,
		Leaf:        tmpl,
	}
	ca.cache[host] = cert
	return cert, nil
}
