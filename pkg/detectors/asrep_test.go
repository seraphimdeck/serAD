package detectors

import (
	"github.com/seraphimdeck/serAD/pkg/models"
	"testing"
)

func TestDetectASREP(t *testing.T) {
	engine := &Engine{Users: []models.User{
		{SAMAccountName: "roastable", Enabled: true, DontReqPreauth: true},
		{SAMAccountName: "disabled", Enabled: false, DontReqPreauth: true},
		{SAMAccountName: "normal", Enabled: true, DontReqPreauth: false},
	}}

	findings := engine.DetectASREP()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].AffectedEntity != "roastable" {
		t.Fatalf("unexpected entity: %q", findings[0].AffectedEntity)
	}
	if findings[0].Remediation == "" || findings[0].Confidence != models.ConfidenceConfirmed {
		t.Fatalf("expected remediation and confirmed confidence: %+v", findings[0])
	}
}
