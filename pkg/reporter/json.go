package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"serAD/pkg/models"
)

func ExportJSON(filename string, findings []models.Finding) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("gagal merubah data temuan ke JSON: %w", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("gagal menulis file JSON: %w", err)
	}

	return nil
}
