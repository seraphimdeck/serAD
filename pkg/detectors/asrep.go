package detectors

import (
	"fmt"
	"serAD/pkg/models"
)

func (e *Engine) DetectASREP() []models.Finding {
	var findings []models.Finding

	for _, user := range e.Users {
		if user.Enabled && user.DontReqPreauth {
			findings = append(findings, models.Finding{
				ID:             "ASREP_ROAST",
				Title:          "Kerberos Pre-Authentication Disabled (AS-REP Roastable)",
				Severity:       models.SeverityHigh,
				Category:       "Kerberos",
				AffectedEntity: user.SAMAccountName,
				Description:    fmt.Sprintf("Akun pengguna '%s' me.iliki flag DONT_REQUIRE_PREAUTH.", user.SAMAccountName),
				Remediation:    "Aktifkan opsi 'Do not require Kerberos preauthentication', set false pada properti akun pengguna di Active Directory.",
				References:     []string{"https://adsecurity.org/?p=3513"},
			})
		}
	}

	return findings
}
