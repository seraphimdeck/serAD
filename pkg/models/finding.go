package models

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type Finding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Severity       Severity `json:"severity"`
	Category       string   `json:"category"`
	AffectedEntity string   `json:"affected_entity"`
	Description    string   `json:"description"`
	Remediation    string   `json:"remediation"`
	References     []string `json:"references"`
}
