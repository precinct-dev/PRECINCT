package controlmatrix

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	DomainSecurity  = "security"
	DomainUsability = "usability"
	DomainBlindSpot = "blindspot"
)

type Matrix struct {
	SchemaVersion  string    `json:"schema_version"`
	Title          string    `json:"title"`
	SignalCatalogs []string  `json:"signal_catalogs"`
	Controls       []Control `json:"controls"`
}

type Control struct {
	ID             string             `json:"id"`
	Domain         string             `json:"domain"`
	Description    string             `json:"description"`
	ThreatRefs     []string           `json:"threat_refs"`
	TestEvidence   []TestEvidence     `json:"test_evidence"`
	RuntimeSignals []string           `json:"runtime_signals"`
	Artifacts      []ArtifactEvidence `json:"artifacts"`
}

type TestEvidence struct {
	Path    string `json:"path"`
	Command string `json:"command"`
}

type ArtifactEvidence struct {
	Path        string `json:"path"`
	MaxAgeHours int    `json:"max_age_hours"`
}

type Issue struct {
	Code      string `json:"code"`
	ControlID string `json:"control_id,omitempty"`
	Target    string `json:"target,omitempty"`
	Message   string `json:"message"`
}

type ControlStatus struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	Status string `json:"status"`
}

type ReportSummary struct {
	ControlsTotal  int `json:"controls_total"`
	ControlsPassed int `json:"controls_passed"`
	ControlsFailed int `json:"controls_failed"`
	IssueCount     int `json:"issue_count"`
}

type Report struct {
	GeneratedAt string          `json:"generated_at"`
	MatrixPath  string          `json:"matrix_path"`
	Summary     ReportSummary   `json:"summary"`
	Controls    []ControlStatus `json:"controls"`
	Issues      []Issue         `json:"issues"`
}

type Result struct {
	Matrix Matrix `json:"matrix"`
	Report Report `json:"report"`
}

type signalCatalog struct {
	RequiredSignalKeys []string         `json:"required_signal_keys"`
	Mappings           map[string][]any `json:"mappings"`
}

func CheckRepo(root, matrixPath string, now time.Time) (Result, error) {
	var out Result

	if root == "" {
		root = "."
	}
	if matrixPath == "" {
		matrixPath = "docs/security/artifacts/control-verification-matrix.v1.json"
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	absMatrix := filepath.Join(root, matrixPath)
	raw, err := os.ReadFile(absMatrix)
	if err != nil {
		return out, fmt.Errorf("read control matrix %s: %w", matrixPath, err)
	}

	var matrix Matrix
	if err := json.Unmarshal(raw, &matrix); err != nil {
		return out, fmt.Errorf("parse control matrix %s: %w", matrixPath, err)
	}

	issues := make([]Issue, 0)
	if strings.TrimSpace(matrix.SchemaVersion) == "" {
		issues = append(issues, Issue{
			Code:    "matrix_schema_missing",
			Target:  matrixPath,
			Message: "schema_version is required",
		})
	}
	if len(matrix.Controls) == 0 {
		issues = append(issues, Issue{
			Code:    "matrix_controls_empty",
			Target:  matrixPath,
			Message: "matrix must contain at least one control",
		})
	}

	allowedSignals, signalIssues := loadAllowedSignals(root, matrix.SignalCatalogs)
	issues = append(issues, signalIssues...)

	controlIDs := make(map[string]struct{}, len(matrix.Controls))
	domainCounts := map[string]int{
		DomainSecurity:  0,
		DomainUsability: 0,
		DomainBlindSpot: 0,
	}
	controlHasFailure := make(map[string]bool, len(matrix.Controls))

	for _, control := range matrix.Controls {
		controlID := strings.TrimSpace(control.ID)
		if controlID == "" {
			issues = append(issues, Issue{
				Code:    "control_id_missing",
				Target:  matrixPath,
				Message: "control id is required",
			})
			continue
		}

		if _, exists := controlIDs[controlID]; exists {
			issues = append(issues, Issue{
				Code:      "control_id_duplicate",
				ControlID: controlID,
				Target:    matrixPath,
				Message:   "control id must be unique",
			})
			controlHasFailure[controlID] = true
		}
		controlIDs[controlID] = struct{}{}

		domain := strings.ToLower(strings.TrimSpace(control.Domain))
		switch domain {
		case DomainSecurity, DomainUsability, DomainBlindSpot:
			domainCounts[domain]++
		default:
			issues = append(issues, Issue{
				Code:      "control_domain_invalid",
				ControlID: controlID,
				Target:    control.Domain,
				Message:   "domain must be one of security, usability, blindspot",
			})
			controlHasFailure[controlID] = true
		}

		if len(control.ThreatRefs) == 0 {
			issues = append(issues, Issue{
				Code:      "control_threat_refs_missing",
				ControlID: controlID,
				Message:   "threat_refs must not be empty",
			})
			controlHasFailure[controlID] = true
		}

		if len(control.TestEvidence) == 0 {
			issues = append(issues, Issue{
				Code:      "control_test_evidence_missing",
				ControlID: controlID,
				Message:   "test_evidence must not be empty",
			})
			controlHasFailure[controlID] = true
		}

		for _, test := range control.TestEvidence {
			testPath := strings.TrimSpace(test.Path)
			if testPath == "" {
				issues = append(issues, Issue{
					Code:      "test_path_missing",
					ControlID: controlID,
					Message:   "test evidence path is required",
				})
				controlHasFailure[controlID] = true
				continue
			}
			if strings.TrimSpace(test.Command) == "" {
				issues = append(issues, Issue{
					Code:      "test_command_missing",
					ControlID: controlID,
					Target:    testPath,
					Message:   "test evidence command is required",
				})
				controlHasFailure[controlID] = true
			}
			if _, err := os.Stat(filepath.Join(root, testPath)); err != nil {
				issues = append(issues, Issue{
					Code:      "test_path_missing",
					ControlID: controlID,
					Target:    testPath,
					Message:   "test evidence file not found",
				})
				controlHasFailure[controlID] = true
			}
		}

		if len(control.RuntimeSignals) == 0 {
			issues = append(issues, Issue{
				Code:      "runtime_signals_missing",
				ControlID: controlID,
				Message:   "runtime_signals must not be empty",
			})
			controlHasFailure[controlID] = true
		}
		for _, signal := range control.RuntimeSignals {
			key := strings.TrimSpace(signal)
			if key == "" {
				issues = append(issues, Issue{
					Code:      "runtime_signal_empty",
					ControlID: controlID,
					Message:   "runtime signal must not be empty",
				})
				controlHasFailure[controlID] = true
				continue
			}
			if _, ok := allowedSignals[key]; !ok {
				issues = append(issues, Issue{
					Code:      "runtime_signal_unknown",
					ControlID: controlID,
					Target:    key,
					Message:   "runtime signal is not present in signal catalogs",
				})
				controlHasFailure[controlID] = true
			}
		}

		if len(control.Artifacts) == 0 {
			issues = append(issues, Issue{
				Code:      "artifact_evidence_missing",
				ControlID: controlID,
				Message:   "artifacts must not be empty",
			})
			controlHasFailure[controlID] = true
		}

		for _, artifact := range control.Artifacts {
			artifactPath := strings.TrimSpace(artifact.Path)
			if artifactPath == "" {
				issues = append(issues, Issue{
					Code:      "artifact_path_missing",
					ControlID: controlID,
					Message:   "artifact path is required",
				})
				controlHasFailure[controlID] = true
				continue
			}

			info, err := os.Stat(filepath.Join(root, artifactPath))
			if err != nil {
				issues = append(issues, Issue{
					Code:      "artifact_missing",
					ControlID: controlID,
					Target:    artifactPath,
					Message:   "artifact missing",
				})
				controlHasFailure[controlID] = true
				continue
			}

			if artifact.MaxAgeHours > 0 {
				maxAge := time.Duration(artifact.MaxAgeHours) * time.Hour
				age := now.Sub(info.ModTime())
				if age > maxAge {
					issues = append(issues, Issue{
						Code:      "artifact_stale",
						ControlID: controlID,
						Target:    artifactPath,
						Message:   fmt.Sprintf("artifact age %s exceeds max_age_hours=%d", age.Round(time.Second), artifact.MaxAgeHours),
					})
					controlHasFailure[controlID] = true
				}
			}
		}
	}

	if domainCounts[DomainSecurity] == 0 {
		issues = append(issues, Issue{
			Code:    "domain_missing_security",
			Target:  matrixPath,
			Message: "matrix must include at least one security control",
		})
	}
	if domainCounts[DomainUsability] == 0 {
		issues = append(issues, Issue{
			Code:    "domain_missing_usability",
			Target:  matrixPath,
			Message: "matrix must include at least one usability control",
		})
	}
	if domainCounts[DomainBlindSpot] == 0 {
		issues = append(issues, Issue{
			Code:    "domain_missing_blindspot",
			Target:  matrixPath,
			Message: "matrix must include at least one blindspot control",
		})
	}

	sort.Slice(issues, func(i, j int) bool {
		if issues[i].ControlID == issues[j].ControlID {
			if issues[i].Code == issues[j].Code {
				return issues[i].Target < issues[j].Target
			}
			return issues[i].Code < issues[j].Code
		}
		return issues[i].ControlID < issues[j].ControlID
	})

	statuses := make([]ControlStatus, 0, len(matrix.Controls))
	passed := 0
	for _, control := range matrix.Controls {
		status := "pass"
		if controlHasFailure[control.ID] {
			status = "fail"
		} else {
			passed++
		}
		statuses = append(statuses, ControlStatus{
			ID:     control.ID,
			Domain: control.Domain,
			Status: status,
		})
	}
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].ID < statuses[j].ID
	})

	out.Matrix = matrix
	out.Report = Report{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		MatrixPath:  filepath.ToSlash(matrixPath),
		Summary: ReportSummary{
			ControlsTotal:  len(matrix.Controls),
			ControlsPassed: passed,
			ControlsFailed: len(matrix.Controls) - passed,
			IssueCount:     len(issues),
		},
		Controls: statuses,
		Issues:   issues,
	}

	return out, nil
}

func RenderMarkdown(report Report) string {
	var b strings.Builder

	b.WriteString("# Control Verification Report\n\n")
	b.WriteString(fmt.Sprintf("- Generated: `%s`\n", report.GeneratedAt))
	b.WriteString(fmt.Sprintf("- Matrix: `%s`\n", report.MatrixPath))
	b.WriteString(fmt.Sprintf("- Controls: `%d` total, `%d` pass, `%d` fail\n", report.Summary.ControlsTotal, report.Summary.ControlsPassed, report.Summary.ControlsFailed))
	b.WriteString(fmt.Sprintf("- Issues: `%d`\n\n", report.Summary.IssueCount))

	b.WriteString("## Control Status\n\n")
	b.WriteString("| Control ID | Domain | Status |\n")
	b.WriteString("|---|---|---|\n")
	for _, control := range report.Controls {
		b.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` |\n", control.ID, control.Domain, strings.ToUpper(control.Status)))
	}

	if len(report.Issues) == 0 {
		b.WriteString("\n## Issues\n\n")
		b.WriteString("No issues found.\n")
		return b.String()
	}

	b.WriteString("\n## Issues\n\n")
	for _, issue := range report.Issues {
		controlID := issue.ControlID
		if controlID == "" {
			controlID = "GLOBAL"
		}
		target := issue.Target
		if target == "" {
			target = "-"
		}
		b.WriteString(fmt.Sprintf("- `%s` `%s` target=`%s`: %s\n", issue.Code, controlID, target, issue.Message))
	}

	return b.String()
}

func loadAllowedSignals(root string, catalogs []string) (map[string]struct{}, []Issue) {
	signals := make(map[string]struct{})
	issues := make([]Issue, 0)

	if len(catalogs) == 0 {
		issues = append(issues, Issue{
			Code:    "signal_catalogs_missing",
			Message: "signal_catalogs must include at least one catalog path",
		})
		return signals, issues
	}

	for _, rel := range catalogs {
		path := strings.TrimSpace(rel)
		if path == "" {
			issues = append(issues, Issue{
				Code:    "signal_catalog_path_empty",
				Message: "signal catalog path must not be empty",
			})
			continue
		}

		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			issues = append(issues, Issue{
				Code:    "signal_catalog_missing",
				Target:  path,
				Message: "signal catalog file not found",
			})
			continue
		}

		var catalog signalCatalog
		if err := json.Unmarshal(raw, &catalog); err != nil {
			issues = append(issues, Issue{
				Code:    "signal_catalog_invalid",
				Target:  path,
				Message: "signal catalog is not valid JSON",
			})
			continue
		}

		for _, key := range catalog.RequiredSignalKeys {
			trimmed := strings.TrimSpace(key)
			if trimmed != "" {
				signals[trimmed] = struct{}{}
			}
		}
		for key := range catalog.Mappings {
			trimmed := strings.TrimSpace(key)
			if trimmed != "" {
				signals[trimmed] = struct{}{}
			}
		}
	}

	if len(signals) == 0 {
		issues = append(issues, Issue{
			Code:    "signal_catalogs_empty",
			Message: "no runtime signals could be loaded from signal catalogs",
		})
	}

	return signals, issues
}
