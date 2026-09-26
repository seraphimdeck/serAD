package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"github.com/seraphimdeck/serAD/pkg/models"
)

func ExportJSON(filename string, findings []models.Finding) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("gagal merubah data temuan ke JSON: %w", err)
	}

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("gagal membuka file JSON: %w", err)
	}
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("gagal mengatur permission file JSON: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("gagal menulis file JSON: %w", err)
	}

	return nil
}
