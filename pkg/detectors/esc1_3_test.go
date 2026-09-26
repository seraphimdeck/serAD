package detectors

import (
	"github.com/seraphimdeck/serAD/pkg/models"
	"testing"
)

func TestDetectESC1MarksCandidate(t *testing.T) {
	engine := &Engine{Templates: []models.CertificateTemplate{
		{
			Name:                    "UserTemplate",
			DisplayName:             "User Template",
			EnrolleeSuppliesSubject: true,
			EKUs:                    []string{OIDClientAuth},
			RequiresManagerApproval: false,
		},
	}}

	findings := engine.DetectESC1AndESC3()
	if len(findings) != 1 || findings[0].ID != "ESC1" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[0].Confidence != models.ConfidenceCandidate {
		t.Fatalf("expected CANDIDATE confidence, got %q", findings[0].Confidence)
	}
	if len(findings[0].Limitations) == 0 {
		t.Fatal("expected limitations to explain missing enrollment ACL analysis")
	}
}
