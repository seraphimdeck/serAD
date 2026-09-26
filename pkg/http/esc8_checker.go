package http

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/seraphimdeck/serAD/pkg/models"
)

func (p *ProbeClient) CheckESC8(ca *models.EnterpriseCA) (*models.Finding, error) {
	if ca == nil || strings.TrimSpace(ca.DNSHostName) == "" {
		return nil, fmt.Errorf("CA tidak memiliki DNS host name")
	}

	targetURL := fmt.Sprintf("http://%s/certsrv/", ca.DNSHostName)

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "serAD/1.0.1")

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
	if ntlmSupported {
		finding := &models.Finding{
			ID:             "ESC8",
			Title:          "AD CS Web Enrollment over HTTP with NTLM Advertised",
			Severity:       models.SeverityCritical,
			Confidence:     models.ConfidenceCandidate,
			Category:       "AD CS",
			AffectedEntity: ca.DNSHostName,
			Description:    fmt.Sprintf("Enterprise CA '%s' merespons HTTP Web Enrollment pada %s dan mengiklankan NTLM/Negotiate.", ca.Name, targetURL),
			Evidence:       []string{fmt.Sprintf("HTTP status=%d", resp.StatusCode), fmt.Sprintf("WWW-Authenticate=%v", authHeaders)},
			Remediation:    "Nonaktifkan layanan HTTP Web Enrollment jika tidak digunakan. Gunakan HTTPS/TLS dan evaluasi Extended Protection for Authentication (EPA) serta kebutuhan NTLM.",
			References:     []string{"https://posts.specterops.io/certified-pre-owned-d959109652fb"},
		}
		return finding, nil
	}

	return nil, nil
}
