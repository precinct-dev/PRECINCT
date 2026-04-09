// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

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
	AuditSource  string // auto|file|docker|opensearch
	AuditLogPath string // local JSONL audit log path (used by audit-source auto|file)
	WorkDir      string

	// OpenSearch-backed audit source options (used when AuditSource=opensearch).
	OpenSearchURL                string
	OpenSearchIndex              string
	OpenSearchUsername           string
	OpenSearchPassword           string
	OpenSearchCACertPath         string
	OpenSearchClientCertPath     string
	OpenSearchClientKeyPath      string
	OpenSearchTimeWindow         string
	OpenSearchMaxEntries         int
	OpenSearchInsecureSkipVerify bool
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

	entries, auditSource, err := CollectAuditEntriesWithOptions(projectRoot, AuditCollectionOptions{
		Source:       p.AuditSource,
		AuditLogPath: defaultAuditLogPath(p.AuditLogPath),
		OpenSearch: OpenSearchAuditOptions{
			URL:                p.OpenSearchURL,
			Index:              p.OpenSearchIndex,
			Username:           p.OpenSearchUsername,
			Password:           p.OpenSearchPassword,
			CACertPath:         p.OpenSearchCACertPath,
			ClientCertPath:     p.OpenSearchClientCertPath,
			ClientKeyPath:      p.OpenSearchClientKeyPath,
			TimeWindow:         p.OpenSearchTimeWindow,
			MaxEntries:         p.OpenSearchMaxEntries,
			InsecureSkipVerify: p.OpenSearchInsecureSkipVerify,
		},
	})
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
