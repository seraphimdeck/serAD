package reporter

import (
	"fmt"
	"os"
	"serAD/pkg/models"
)

func ExportMarkdown(filename string, findings []models.Finding) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("gagal membuat file markdown: %w", err)
	}
	defer file.Close()

	file.WriteString("# Active Directory & AD CS Security Audit Report\n\n")
	file.WriteString(fmt.Sprintf("**Total Temuan**: %d\n\n", len(findings)))
	file.WriteString("| ID | Severity | Title | Category | Affected Entity |\n")
	file.WriteString("|---|---|---|---|---|\n")

	for _, f := range findings {
		file.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", f.ID, f.Severity, f.Title, f.Category, f.AffectedEntity))
	}

	file.WriteString("\n## Detail Temuan & Remediasi\n\n")

	for i, f := range findings {
		file.WriteString(fmt.Sprintf("### %d. %s (%s)\n", i+1, f.Title, f.Severity))
		file.WriteString(fmt.Sprintf("- **ID**: `%s`\n", f.ID))
		file.WriteString(fmt.Sprintf("- **Kategori**: %s\n", f.Category))
		file.WriteString(fmt.Sprintf("- **Entitas Terdampak**: `%s`\n", f.AffectedEntity))
		file.WriteString(fmt.Sprintf("- **Deskripsi**: %s\n", f.Description))
		file.WriteString(fmt.Sprintf("- **Panduan Remediasi**: %s\n\n", f.Remediation))
	}

	return nil
}
