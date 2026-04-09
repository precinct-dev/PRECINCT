// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type EvidenceSummary struct {
	TimestampRFC3339     string         `json:"timestamp"`
	Framework            string         `json:"framework"`
	ControlCount         int            `json:"control_count"`
	CollectionDurationMs int64          `json:"collection_duration_ms"`
	AuditSource          string         `json:"audit_source"`
	AuditEntryCount      int            `json:"audit_entry_count"`
	OutputDir            string         `json:"output_dir"`
	ConfigSnapshots      []SnapshotItem `json:"config_snapshots"`
}

type CollectParams struct {
	Framework    string
	OutputDir    string // base directory where the timestamped evidence dir is created
	AuditSource  string // auto|file|docker|opensearch
	AuditLogPath string // local JSONL audit log path (used by audit-source auto|file)
	WorkDir      string // cwd for project root discovery

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

type CollectResult struct {
	EvidenceDir string
	Summary     EvidenceSummary
}

func CollectEvidencePackage(p CollectParams) (*CollectResult, error) {
	start := time.Now()
	framework := strings.ToLower(strings.TrimSpace(p.Framework))
	if framework == "" {
		return nil, fmt.Errorf("framework is required")
	}

	wd := p.WorkDir
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return nil, err
		}
	}

	projectRoot, err := FindProjectRoot(wd)
	if err != nil {
		return nil, err
	}

	taxonomyPath := filepath.Join(projectRoot, taxonomyRelPath)
	tax, err := LoadTaxonomy(taxonomyPath)
	if err != nil {
		return nil, err
	}
	controls := FilterControlsByFramework(tax.Controls, framework)

	outBase := strings.TrimSpace(p.OutputDir)
	if outBase == "" {
		outBase = "reports"
	}
	if !filepath.IsAbs(outBase) {
		outBase = filepath.Join(projectRoot, outBase)
	}

	ts := time.Now().Format("20060102-150405")
	evidenceRoot := filepath.Join(outBase, fmt.Sprintf("compliance-evidence-%s", ts))
	frameworkDir := filepath.Join(evidenceRoot, framework)

	// Create base structure early.
	if err := os.MkdirAll(filepath.Join(frameworkDir, "controls"), 0o755); err != nil {
		return nil, err
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
		return nil, err
	}
	if err := WriteAuditSnapshotJSONL(filepath.Join(frameworkDir, "audit-log-snapshot.jsonl"), entries); err != nil {
		return nil, err
	}

	configSnapshots, err := snapshotConfig(projectRoot, filepath.Join(frameworkDir, "config-snapshots"))
	if err != nil {
		return nil, err
	}

	// Per-control evidence.
	for _, c := range controls {
		cDir := filepath.Join(frameworkDir, "controls", c.ID)
		if err := os.MkdirAll(cDir, 0o755); err != nil {
			return nil, err
		}
		if err := writeControlEvidence(cDir, c, entries); err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
	}

	summary := EvidenceSummary{
		TimestampRFC3339:     time.Now().Format(time.RFC3339),
		Framework:            framework,
		ControlCount:         len(controls),
		CollectionDurationMs: time.Since(start).Milliseconds(),
		AuditSource:          auditSource,
		AuditEntryCount:      len(entries),
		OutputDir:            evidenceRoot,
		ConfigSnapshots:      configSnapshots,
	}

	if err := writeJSON(filepath.Join(frameworkDir, "evidence-summary.json"), summary); err != nil {
		return nil, err
	}

	return &CollectResult{
		EvidenceDir: evidenceRoot,
		Summary:     summary,
	}, nil
}

func defaultAuditLogPath(v string) string {
	if strings.TrimSpace(v) == "" {
		return "/tmp/audit.jsonl"
	}
	return v
}

func writeControlEvidence(controlDir string, c Control, entries []map[string]any) error {
	payload, err := buildControlEvidencePayload(c, entries)
	if err != nil {
		return err
	}

	if err := writeJSON(filepath.Join(controlDir, "evidence.json"), payload); err != nil {
		return err
	}

	if c.EvidenceType == "configuration" {
		ref := configReferencesForControl(c)
		return writeYAML(filepath.Join(controlDir, "config-snapshot.yaml"), map[string]any{"references": ref})
	}
	return nil
}

func buildControlEvidencePayload(c Control, entries []map[string]any) (any, error) {
	switch c.EvidenceType {
	case "audit_log":
		query := ""
		if c.EvidenceQuery != nil {
			query = *c.EvidenceQuery
		}
		var matches []map[string]any
		if strings.TrimSpace(query) != "" {
			for _, e := range entries {
				if MatchesQuery(e, query) {
					matches = append(matches, e)
				}
			}
		}
		return matches, nil
	case "configuration":
		ref := configReferencesForControl(c)
		return map[string]any{
			"evidence_type": "configuration",
			"references":    ref,
		}, nil
	case "test_result":
		ref := testReferencesForControl(c)
		return map[string]any{
			"evidence_type": "test_result",
			"references":    ref,
		}, nil
	default:
		return map[string]any{
			"evidence_type": c.EvidenceType,
			"note":          "unsupported evidence_type; directory created for completeness",
		}, nil
	}
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func writeYAML(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		b = append(b, '\n')
	}
	return os.WriteFile(path, b, 0o644)
}
