package reporter

import (
	"github.com/seraphimdeck/serAD/pkg/models"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportMarkdownEscapesCellsAndUsesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.md")
	findings := []models.Finding{{
		ID:             "TEST",
		Title:          "Title | test",
		Severity:       models.SeverityLow,
		Confidence:     models.ConfidenceObserved,
		Category:       "A|B",
		AffectedEntity: "host|01",
		Description:    "line one\nline two",
		Remediation:    "review | fix",
	}}

	if err := ExportMarkdown(path, findings); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "| Title | test |") {
		t.Fatal("markdown cell was not escaped")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}
