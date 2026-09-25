package detectors

import (
	"fmt"
	"strings"
	"serAD/pkg/models"
)

func (e *Engine) DetectKerberoast() []models.Finding {
	var findings []models.Finding

	for _, user := range e.Users {
		if !user.Enabled || strings.HasSuffix(user.SAMAccountName, "$") {
			continue
		}

		if len(user.ServicePrincipalName) > 0 {
			findings = append(findings, models.Finding{
				ID:             "KERBEROAST",
				Title:          "User Account with Service Principal Name (Kerberoastable)",
				Severity:       models.SeverityHigh,
				Category:       "Kerberos",
				AffectedEntity: user.SAMAccountName,
				Description:    fmt.Sprintf("Akun pengguna '%s' memiliki SPN dikonfigurasi: %v. Akun ini rentan terhadap serangan Kerberoasting.", user.SAMAccountName, user.ServicePrincipalName),
				Remediation:    "Gunakan gMSA atau pastikan kata sandi akun pengguna ini menggunakan kompleksitas tinggi (25 karakter).",
				References:     []string{"https://adsecurity.org/?p=2293"},
			})
		}
	}

	return findings
}
