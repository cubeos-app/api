package managers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

// npmCertCreateRequest is the NPM API payload for creating a certificate.
type npmCertCreateRequest struct {
	Provider    string      `json:"provider"` // "letsencrypt" or "other"
	NiceName    string      `json:"nice_name"`
	DomainNames []string    `json:"domain_names"`
	Meta        interface{} `json:"meta,omitempty"`

	// For custom certificates (provider=other)
	Certificate    string `json:"certificate,omitempty"`
	CertificateKey string `json:"certificate_key,omitempty"`
}

// npmLEMeta holds Let's Encrypt metadata for the NPM certificate API.
type npmLEMeta struct {
	LetsEncryptAgree       bool   `json:"letsencrypt_agree"`
	LetsEncryptEmail       string `json:"letsencrypt_email"`
	DNSChallenge           bool   `json:"dns_challenge"`
	DNSProvider            string `json:"dns_provider"`
	DNSProviderCredentials string `json:"dns_provider_credentials"`
}

// npmCertResponse is the NPM API response after creating a certificate.
type npmCertResponse struct {
	ID          int      `json:"id"`
	NiceName    string   `json:"nice_name"`
	DomainNames []string `json:"domain_names"`
	Provider    string   `json:"provider"`
}

// CreateLetsEncryptCert provisions a Let's Encrypt certificate via NPM's API.
// Returns the certificate ID assigned by NPM.
func (m *NPMManager) CreateLetsEncryptCert(domain, email, dnsProvider, dnsCredentials string) (int, error) {
	req := npmCertCreateRequest{
		Provider:    "letsencrypt",
		NiceName:    "CubeOS - " + domain,
		DomainNames: []string{domain},
		Meta: npmLEMeta{
			LetsEncryptAgree:       true,
			LetsEncryptEmail:       email,
			DNSChallenge:           true,
			DNSProvider:            dnsProvider,
			DNSProviderCredentials: dnsCredentials,
		},
	}

	resp, err := m.doRequest("POST", "/api/nginx/certificates", req)
	if err != nil {
		return 0, fmt.Errorf("create LE cert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("NPM returned %d: %s", resp.StatusCode, string(respBody))
	}

	var certResp npmCertResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}

	log.Info().Int("cert_id", certResp.ID).Str("domain", domain).Msg("Let's Encrypt certificate created in NPM")
	return certResp.ID, nil
}

// UploadCustomCert uploads a custom certificate (PEM) to NPM.
// Used for self-signed CA certificates. Returns the certificate ID.
func (m *NPMManager) UploadCustomCert(name string, certPEM, keyPEM []byte) (int, error) {
	req := npmCertCreateRequest{
		Provider:       "other",
		NiceName:       name,
		DomainNames:    []string{},
		Certificate:    string(certPEM),
		CertificateKey: string(keyPEM),
	}

	resp, err := m.doRequest("POST", "/api/nginx/certificates", req)
	if err != nil {
		return 0, fmt.Errorf("upload custom cert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("NPM returned %d: %s", resp.StatusCode, string(respBody))
	}

	var certResp npmCertResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}

	log.Info().Int("cert_id", certResp.ID).Str("name", name).Msg("Custom certificate uploaded to NPM")
	return certResp.ID, nil
}

// GetCertificateByDomain searches NPM certificates for one matching the given domain.
// Returns the certificate ID, or 0 if not found.
func (m *NPMManager) GetCertificateByDomain(domain string) (int, error) {
	resp, err := m.doRequest("GET", "/api/nginx/certificates", nil)
	if err != nil {
		return 0, fmt.Errorf("list certs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("NPM returned %d", resp.StatusCode)
	}

	var certs []npmCertResponse
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}

	for _, cert := range certs {
		for _, d := range cert.DomainNames {
			if d == domain {
				return cert.ID, nil
			}
		}
	}
	return 0, nil
}
