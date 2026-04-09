// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

type RepaveStatusParams struct {
	StateFile string
	Now       time.Time
	Runner    CommandRunner
}

type RepaveStateFile struct {
	LastRepave map[string]RepaveStateRecord `json:"last_repave"`
}

type RepaveStateRecord struct {
	Timestamp string `json:"timestamp"`
	ImageHash string `json:"image_hash"`
	Health    string `json:"health"`
}

type RepaveContainerStatus struct {
	Name        string   `json:"name"`
	LastRepave  string   `json:"last_repave"`
	ImageHash   string   `json:"image_hash"`
	CurrentHash string   `json:"current_hash"`
	HashMatch   bool     `json:"hash_match"`
	Health      string   `json:"health"`
	AgeHours    int64    `json:"age_hours"`
	Warnings    []string `json:"warnings,omitempty"`
}

type RepaveStatusOutput struct {
	Containers []RepaveContainerStatus `json:"containers"`
}

type composePSRow struct {
	Service string `json:"Service"`
	Name    string `json:"Name"`
	Health  string `json:"Health"`
	Labels  string `json:"Labels"`
	State   string `json:"State"`
	Status  string `json:"Status"`
	Image   string `json:"Image"`
}

func CollectRepaveStatus(ctx context.Context, p RepaveStatusParams) (RepaveStatusOutput, error) {
	statePath := strings.TrimSpace(p.StateFile)
	if statePath == "" {
		statePath = ".repave-state.json"
	}

	runner := p.Runner
	if runner == nil {
		runner = execCommandRunner{}
	}

	now := p.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	state, err := loadRepaveStateFile(statePath)
	if err != nil {
		return RepaveStatusOutput{}, err
	}

	stdout, stderr, err := runner.Run(ctx, "docker", composeArgs("ps", "--format", "json")...)
	if err != nil {
		return RepaveStatusOutput{}, fmt.Errorf("docker compose ps --format json failed: %w (%s)", err, strings.TrimSpace(stderr))
	}
	rows, err := parseComposePSRows(stdout)
	if err != nil {
		return RepaveStatusOutput{}, err
	}

	out := RepaveStatusOutput{
		Containers: make([]RepaveContainerStatus, 0, len(rows)),
	}
	for _, row := range rows {
		name := strings.TrimSpace(row.Service)
		if name == "" {
			name = strings.TrimSpace(row.Name)
		}
		if name == "" {
			continue
		}

		currentHash := extractComposeImageHash(row.Labels, row.Image)
		health := normalizeHealthStatus(row.Health, row.State)

		entry := RepaveContainerStatus{
			Name:        name,
			LastRepave:  "NEVER",
			ImageHash:   currentHash,
			CurrentHash: currentHash,
			HashMatch:   false,
			Health:      health,
			AgeHours:    0,
		}

		record, ok := state.LastRepave[name]
		if ok {
			entry.LastRepave = strings.TrimSpace(record.Timestamp)
			if strings.TrimSpace(record.ImageHash) != "" {
				entry.ImageHash = strings.TrimSpace(record.ImageHash)
			}
			if entry.ImageHash != "" && entry.CurrentHash != "" && entry.ImageHash == entry.CurrentHash {
				entry.HashMatch = true
			}
			if ts, err := time.Parse(time.RFC3339, entry.LastRepave); err == nil {
				age := now.Sub(ts.UTC())
				if age > 0 {
					entry.AgeHours = int64(age.Hours())
				}
			} else {
				entry.Warnings = append(entry.Warnings, "invalid_timestamp")
			}
			if entry.ImageHash != "" && entry.CurrentHash != "" && entry.ImageHash != entry.CurrentHash {
				entry.Warnings = append(entry.Warnings, "hash_mismatch")
			}
		} else {
			entry.Warnings = append(entry.Warnings, "never_repaved")
		}

		if isUnhealthyStatus(health) {
			entry.Warnings = append(entry.Warnings, "unhealthy")
		}

		out.Containers = append(out.Containers, entry)
	}

	sort.Slice(out.Containers, func(i, j int) bool {
		return out.Containers[i].Name < out.Containers[j].Name
	})
	return out, nil
}

func RenderRepaveStatusJSON(out RepaveStatusOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderRepaveStatusTable(out RepaveStatusOutput) (string, error) {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "CONTAINER\tLAST REPAVE\tIMAGE HASH\tHEALTH\tAGE\tWARNINGS")
	for _, c := range out.Containers {
		age := "--"
		if !strings.EqualFold(c.LastRepave, "NEVER") {
			age = humanizeRepaveAge(c.AgeHours)
		}
		warnings := "-"
		if len(c.Warnings) > 0 {
			warnings = "WARNING: " + strings.Join(c.Warnings, ",")
		}
		_, _ = fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Name,
			c.LastRepave,
			shortHash(c.ImageHash),
			c.Health,
			age,
			warnings,
		)
	}
	_ = tw.Flush()
	return buf.String(), nil
}

func loadRepaveStateFile(path string) (RepaveStateFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RepaveStateFile{LastRepave: map[string]RepaveStateRecord{}}, nil
		}
		return RepaveStateFile{}, fmt.Errorf("read repave state file %s: %w", path, err)
	}

	var state RepaveStateFile
	if err := json.Unmarshal(b, &state); err != nil {
		return RepaveStateFile{}, fmt.Errorf("parse repave state file %s: %w", path, err)
	}
	if state.LastRepave == nil {
		state.LastRepave = map[string]RepaveStateRecord{}
	}
	return state, nil
}

func parseComposePSRows(raw string) ([]composePSRow, error) {
	rows := make([]composePSRow, 0, 16)
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row composePSRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("parse docker compose ps row: %w", err)
		}
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan docker compose ps output: %w", err)
	}
	return rows, nil
}

func extractComposeImageHash(labels, fallbackImage string) string {
	for _, pair := range strings.Split(labels, ",") {
		pair = strings.TrimSpace(pair)
		if !strings.HasPrefix(pair, "com.docker.compose.image=") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(pair, "com.docker.compose.image="))
	}
	return strings.TrimSpace(fallbackImage)
}

func normalizeHealthStatus(health, state string) string {
	health = strings.TrimSpace(health)
	if health != "" {
		return strings.ToLower(health)
	}
	state = strings.TrimSpace(state)
	if state == "" {
		return "unknown"
	}
	return strings.ToLower(state)
}

func isUnhealthyStatus(health string) bool {
	health = strings.ToLower(strings.TrimSpace(health))
	if health == "" || health == "healthy" || health == "running" || health == "unknown" {
		return false
	}
	return true
}

func humanizeRepaveAge(hours int64) string {
	if hours <= 0 {
		return "0h"
	}
	days := hours / 24
	rem := hours % 24
	if days == 0 {
		return fmt.Sprintf("%dh", rem)
	}
	if rem == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd %dh", days, rem)
}

func shortHash(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "-"
	}
	if len(v) <= 20 {
		return v
	}
	return v[:20] + "..."
}
