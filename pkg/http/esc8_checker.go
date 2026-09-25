package http

import (
	"fmt"
	"net/http"
	"strings"
	"serAD/pkg/models"
)

func (p *ProbeClient) CheckESC8(ca *models.EnterpriseCA) (*models.Finding, error) {
	targetURL := fmt.Sprintf("http://%s/certsrv/", ca.DNSHostName)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "serAD/1.0")

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	ca.WebEnrollmentURL = targetURL
	ca.IsHTTP = true

	authHeaders := resp.Header.Values("WWW-Authenticate")
	ntlmSupported := false
	for _, h := range authHeaders {
		upperH := strings.ToUpper(h)
		if strings.Contains(upperH, "NTLM") || strings.Contains(upperH, "NEGOTIATE") {
			ntlmSupported = true
			break
		}
	}

	ca.NTLMAuthSupported = ntlmSupported
	if ca.IsHTTP && ca.NTLMAuthSupported {
		finding := &models.Finding{
			ID:             "ESC8",
			Title:          "AD CS Web Enrollment Unencrypted HTTP with NTLM Enabled",
			Severity:       models.SeverityCritical,
			Category:       "AD CS",
			AffectedEntity: ca.DNSHostName,
			Description:    fmt.Sprintf("Enterprise CA '%s' menyediakan layanan AD CS Web Enrollment pada %s dengan otentikasi NTLM.", ca.Name, targetURL),
			Remediation:    "Nonaktifkan layanan HTTP Web Enrollment jika tidak digunakan. Jika dibutuhkan, wajibkan penggunaan HTTPS (SSL/TLS), aktifkan Extended Protection for Authentication (EPA), dan matikan dukungan otentikasi NTLM pada server IIS.",
			References:     []string{"https://posts.specterops.io/certified-pre-owned-d959109652fb"},
		}
		return finding, nil
	}

	return nil, nil
}
