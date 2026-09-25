package reporter

import "serAD/pkg/models"

type Reporter interface {
	Generate(findings []models.Finding) error
}

type ConsoleReporter struct{}

func (c *ConsoleReporter) Generate(findings []models.Finding) error {
	PrintTerminal(findings)
	return nil
}

type MarkdownReporter struct {
	FilePath string
}

func (m *MarkdownReporter) Generate(findings []models.Finding) error {
	return ExportMarkdown(m.FilePath, findings)
}

type JSONReporter struct {
	FilePath string
}

func (j *JSONReporter) Generate(findings []models.Finding) error {
	return ExportJSON(j.FilePath, findings)
}
