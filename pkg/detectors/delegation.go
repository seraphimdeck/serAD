package detectors

import (
	"fmt"

	"github.com/seraphimdeck/serAD/pkg/models"
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
				Confidence:     models.ConfidenceConfirmed,
				Category:       "Delegation",
				AffectedEntity: comp.SAMAccountName,
				Description:    fmt.Sprintf("Komputer/Server '%s' memiliki konfigurasi Unconstrained Delegation.", comp.SAMAccountName),
				Evidence:       []string{"userAccountControl TRUSTED_FOR_DELEGATION flag is enabled"},
				Limitations:    []string{"Finding ini menunjukkan konfigurasi delegasi; dampak aktual bergantung pada akun yang dapat mengakses host."},
				Remediation:    "Migrasi konfigurasi delegasi ke KCD atau RBCD bila sesuai kebutuhan layanan, dan tinjau host yang memerlukan unconstrained delegation.",
				References:     []string{"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"},
			})
		}

		if len(comp.AllowedToDelegateTo) > 0 {
			findings = append(findings, models.Finding{
				ID:             "CONSTRAINED_DELEGATION",
				Title:          "Kerberos Constrained Delegation Configured",
				Severity:       models.SeverityInfo,
				Confidence:     models.ConfidenceObserved,
				Category:       "Delegation",
				AffectedEntity: comp.SAMAccountName,
				Description:    fmt.Sprintf("Komputer/Server '%s' memiliki daftar target delegasi: %v.", comp.SAMAccountName, comp.AllowedToDelegateTo),
				Evidence:       []string{fmt.Sprintf("msDS-AllowedToDelegateTo=%v", comp.AllowedToDelegateTo)},
				Limitations:    []string{"Constrained Delegation sendiri bukan bukti kerentanan; konfigurasi perlu ditinjau terhadap kebutuhan layanan dan least privilege."},
				Remediation:    "Tinjau daftar SPN target dan pastikan hanya layanan yang benar-benar diperlukan yang dapat didelegasikan.",
				References:     []string{"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"},
			})
		}

		if comp.RBCDConfigured {
			findings = append(findings, models.Finding{
				ID:             "RBCD_CONFIGURED",
				Title:          "Resource-Based Constrained Delegation Configured",
				Severity:       models.SeverityMedium,
				Confidence:     models.ConfidenceObserved,
				Category:       "Delegation",
				AffectedEntity: comp.SAMAccountName,
				Description:    fmt.Sprintf("Komputer/Server '%s' memiliki msDS-AllowedToActOnBehalfOfOtherIdentity.", comp.SAMAccountName),
				Evidence:       []string{"msDS-AllowedToActOnBehalfOfOtherIdentity memiliki nilai"},
				Limitations:    []string{"Release ini hanya mendeteksi keberadaan konfigurasi RBCD; belum melakukan parsing security descriptor untuk menentukan principal yang diberi hak."},
				Remediation:    "Tinjau security descriptor RBCD dan pastikan hanya computer/service accounts yang memang diperlukan yang memiliki hak delegasi.",
				References:     []string{"https://learn.microsoft.com/en-us/windows-server/security/kerberos/resource-based-constrained-delegation"},
			})
		}
	}

	return findings
}
