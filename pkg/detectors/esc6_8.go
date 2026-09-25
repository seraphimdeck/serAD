package detectors

import (
	"fmt"
	"serAD/pkg/models"
)

const FlagEditfAttributeSubjectAltName2 uint32 = 0x00000200

func (e *Engine) DetectESC6() []models.Finding {
	var findings []models.Finding

	for _, ca := range e.CAs {
		if (ca.Flags & FlagEditfAttributeSubjectAltName2) != 0 {
			findings = append(findings, models.Finding{
				ID:             "ESC6",
				Title:          "Enterprise CA Flag EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled (ESC6)",
				Severity:       models.SeverityCritical,
				Category:       "AD CS",
				AffectedEntity: ca.Name,
				Description:    fmt.Sprintf("Enterprise CA '%s' mengaktifkan flag EDITF_ATTRIBUTESUBJECTALTNAME2", ca.Name),
				Remediation:    "Jalankan `certutil -config \"%s\" -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2` lalu restart layanan CertSvc.",
				References:     []string{"https://posts.specterops.io/certified-pre-owned-d959109652fb"},
			})
		}
	}

	return findings
}





