// Package managers provides the TLS certificate management for CubeOS.
package managers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
)

// TLSManager handles self-signed CA generation and per-app certificate signing.
type TLSManager struct {
	configDir string // e.g. /cubeos/config
}

// NewTLSManager creates a TLS manager that stores certificates under configDir/tls/.
func NewTLSManager(configDir string) *TLSManager {
	if configDir == "" {
		configDir = os.Getenv("CUBEOS_DATA_DIR")
		if configDir == "" {
			configDir = "/cubeos/config"
		}
	}
	return &TLSManager{configDir: configDir}
}

func (m *TLSManager) tlsDir() string {
	return filepath.Join(m.configDir, "tls")
}

func (m *TLSManager) caKeyPath() string {
	return filepath.Join(m.tlsDir(), "ca.key")
}

func (m *TLSManager) caCertPath() string {
	return filepath.Join(m.tlsDir(), "ca.crt")
}

// GenerateCA creates a 4096-bit RSA root CA certificate with 10-year validity.
// Writes ca.crt and ca.key to the TLS directory. Returns an error if already generated.
func (m *TLSManager) GenerateCA() error {
	dir := m.tlsDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create tls dir: %w", err)
	}

	// Check if CA already exists
	if _, err := os.Stat(m.caCertPath()); err == nil {
		return fmt.Errorf("CA certificate already exists at %s", m.caCertPath())
	}

	// Generate 4096-bit RSA key
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	// Serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	// CA certificate template
	caTmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "CubeOS Root CA",
			Organization: []string{"CubeOS"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour), // backdate slightly for clock skew
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	// Self-sign
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	// Write CA key (0600 — owner-only)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})
	if err := os.WriteFile(m.caKeyPath(), keyPEM, 0600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}

	// Write CA cert (0644 — readable by all)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(m.caCertPath(), certPEM, 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	log.Info().Str("cert", m.caCertPath()).Msg("Self-signed CA generated")
	return nil
}

// SignAppCertificate generates a certificate for a given domain, signed by the CubeOS CA.
// Returns the cert PEM and key PEM as byte slices (for uploading to NPM).
func (m *TLSManager) SignAppCertificate(domain string) (certPEM, keyPEM []byte, err error) {
	// Read CA
	caCertPEM, err := os.ReadFile(m.caCertPath())
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	caKeyPEM, err := os.ReadFile(m.caKeyPath())
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}

	// Parse CA cert
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, fmt.Errorf("invalid CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	// Parse CA key
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("invalid CA key PEM")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}

	// Generate app key (2048-bit RSA)
	appKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate app key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	// App certificate template
	appTmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"CubeOS"},
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Sign with CA
	appCertDER, err := x509.CreateCertificate(rand.Reader, appTmpl, caCert, &appKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign app cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: appCertDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(appKey)})

	log.Info().Str("domain", domain).Msg("Signed app certificate with CubeOS CA")
	return certPEM, keyPEM, nil
}

// GetCACertPEM returns the CA certificate in PEM format.
// Returns empty bytes if CA has not been generated.
func (m *TLSManager) GetCACertPEM() ([]byte, error) {
	data, err := os.ReadFile(m.caCertPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	return data, nil
}

// IsCAGenerated returns true if the CA certificate file exists.
func (m *TLSManager) IsCAGenerated() bool {
	_, err := os.Stat(m.caCertPath())
	return err == nil
}
