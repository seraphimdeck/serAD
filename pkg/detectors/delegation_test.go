package detectors

import (
	"github.com/seraphimdeck/serAD/pkg/models"
	"testing"
)

func TestDetectDelegationRBCD(t *testing.T) {
	engine := &Engine{Computers: []models.Computer{
		{SAMAccountName: "WEB01$", Enabled: true, RBCDConfigured: true},
	}}

	findings := engine.DetectDelegation()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "RBCD_CONFIGURED" {
		t.Fatalf("expected RBCD_CONFIGURED, got %q", findings[0].ID)
	}
	if findings[0].Confidence != models.ConfidenceObserved {
		t.Fatalf("expected OBSERVED confidence, got %q", findings[0].Confidence)
	}
}
