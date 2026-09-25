package detectors

import (
	"fmt"
	"serAD/pkg/models"
)

func (e *Engine) DetectDelegation() []models.Finding {
	var findings []models.Finding

	for _, comp := range e.Computers {
		if !comp.Enabled {
			continue
		}

		if comp.TrustedForDelegation {
			findings = append(findings, models.Finding{
				ID:             "UNCONSTRAINED_DELEGATION",
				Title:          "Unconstrained Kerberos Delegation Configured",
				Severity:       models.SeverityHigh,
				Category:       "Delegation",
				AffectedEntity: comp.SAMAccountName,
				Description:    fmt.Sprintf("Komputer/Server '%s' memiliki konfigurasi Unconstrained Delegation. Tiket TGT pengguna yang mengakses server ini tersimpan dalam memori LSASS.", comp.SAMAccountName),
				Remediation:    "Migrasi konfigurasi delegasi ke KCD atau RBCD.",
				References:     []string{"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"},
			})
		}

		if len(comp.AllowedToDelegateTo) > 0 {
			findings = append(findings, models.Finding{
				ID:             "CONSTRAINED_DELEGATION",
				Title:          "Kerberos Constrained Delegation Configured",
				Severity:       models.SeverityMedium,
				Category:       "Delegation",
				AffectedEntity: comp.SAMAccountName,
				Description:    fmt.Sprintf("Komputer/Server '%s' diizinkan melakukan delegasi ke layanan spesifik: %v.", comp.SAMAccountName, comp.AllowedToDelegateTo),
				Remediation:    "Tinjau kembali daftar SPN target dan least privilege.",
				References:     []string{"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"},
			})
		}
	}

	return findings
}
