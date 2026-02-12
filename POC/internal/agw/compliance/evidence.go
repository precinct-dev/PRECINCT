package compliance

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ControlEvidenceParams struct {
	ControlID    string
	AuditLogPath string
	WorkDir      string
}

type ControlEvidenceResult struct {
	ControlID    string   `json:"control_id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	EvidenceType string   `json:"evidence_type"`
	Frameworks   []string `json:"frameworks"`
	AuditSource  string   `json:"audit_source"`
	Evidence     any      `json:"evidence"`
}

func CollectControlEvidence(p ControlEvidenceParams) (ControlEvidenceResult, error) {
	controlID := strings.ToUpper(strings.TrimSpace(p.ControlID))
	if controlID == "" {
		return ControlEvidenceResult{}, fmt.Errorf("control id is required")
	}

	wd := strings.TrimSpace(p.WorkDir)
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return ControlEvidenceResult{}, err
		}
	}

	projectRoot, err := FindProjectRoot(wd)
	if err != nil {
		return ControlEvidenceResult{}, err
	}

	taxonomyPath := filepath.Join(projectRoot, taxonomyRelPath)
	tax, err := LoadTaxonomy(taxonomyPath)
	if err != nil {
		return ControlEvidenceResult{}, err
	}

	var selected *Control
	for i := range tax.Controls {
		if strings.EqualFold(strings.TrimSpace(tax.Controls[i].ID), controlID) {
			selected = &tax.Controls[i]
			break
		}
	}
	if selected == nil {
		return ControlEvidenceResult{}, fmt.Errorf("control %s not found", controlID)
	}

	entries, auditSource, err := CollectAuditEntries(projectRoot, defaultAuditLogPath(p.AuditLogPath))
	if err != nil {
		return ControlEvidenceResult{}, err
	}

	evidencePayload, err := buildControlEvidencePayload(*selected, entries)
	if err != nil {
		return ControlEvidenceResult{}, err
	}

	frameworks := make([]string, 0, len(selected.Frameworks))
	for fw, reqs := range selected.Frameworks {
		if len(reqs) == 0 {
			continue
		}
		frameworks = append(frameworks, strings.ToUpper(fw))
	}
	sort.Strings(frameworks)

	return ControlEvidenceResult{
		ControlID:    selected.ID,
		Name:         selected.Name,
		Description:  selected.Description,
		EvidenceType: selected.EvidenceType,
		Frameworks:   frameworks,
		AuditSource:  auditSource,
		Evidence:     evidencePayload,
	}, nil
}
