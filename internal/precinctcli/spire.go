// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
)

const (
	spireSocketPath      = "/tmp/spire-server/private/api.sock"
	spireTrustDomain     = "poc.local"
	spireDefaultParentID = "spiffe://poc.local/agent/local"
)

var workloadNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type SPIREEntry struct {
	EntryID   string   `json:"entry_id"`
	SPIFFEID  string   `json:"spiffe_id"`
	ParentID  string   `json:"parent_id"`
	Selectors []string `json:"selectors"`
}

type SPIREListOutput struct {
	Entries []SPIREEntry `json:"entries"`
}

type SPIRERegisterResult struct {
	EntryID   string   `json:"entry_id"`
	SPIFFEID  string   `json:"spiffe_id"`
	ParentID  string   `json:"parent_id"`
	Selectors []string `json:"selectors"`
	Status    string   `json:"status"`
}

type SPIRECLI struct {
	runner CommandRunner
}

func NewSPIRECLI() *SPIRECLI {
	return &SPIRECLI{runner: execCommandRunner{}}
}

func NewSPIRECLIWithRunner(runner CommandRunner) *SPIRECLI {
	if runner == nil {
		runner = execCommandRunner{}
	}
	return &SPIRECLI{runner: runner}
}

func (s *SPIRECLI) ListEntries(ctx context.Context) ([]SPIREEntry, error) {
	stdout, stderr, err := s.runner.Run(
		ctx,
		"docker",
		composeArgs(
			"exec", "-T", "spire-server",
			"/opt/spire/bin/spire-server", "entry", "show",
			"-socketPath", spireSocketPath,
			"-output", "json",
		)...,
	)
	if err != nil {
		return nil, fmt.Errorf("list SPIRE entries: %w", redactSecretValueInError(stderr, err))
	}
	entries, parseErr := parseSPIREEntryShowJSON(stdout)
	if parseErr != nil {
		return nil, parseErr
	}
	return entries, nil
}

func (s *SPIRECLI) RegisterIdentity(ctx context.Context, name string, selectors []string) (SPIRERegisterResult, error) {
	name = strings.TrimSpace(name)
	if !workloadNamePattern.MatchString(name) {
		return SPIRERegisterResult{}, errors.New("name must match [a-z0-9][a-z0-9-]*")
	}

	normalizedSelectors := normalizeSelectors(selectors)
	if len(normalizedSelectors) == 0 {
		return SPIRERegisterResult{}, errors.New("at least one selector is required")
	}

	parentID := s.detectParentID(ctx)
	spiffeID := fmt.Sprintf("spiffe://%s/agents/%s/dev", spireTrustDomain, name)

	args := append([]string{"docker"}, composeArgs(
		"exec", "-T", "spire-server",
		"/opt/spire/bin/spire-server", "entry", "create",
		"-socketPath", spireSocketPath,
		"-spiffeID", spiffeID,
		"-parentID", parentID,
	)...)
	for _, selector := range normalizedSelectors {
		args = append(args, "-selector", selector)
	}
	args = append(args, "-output", "json")

	stdout, stderr, err := s.runner.Run(ctx, args[0], args[1:]...)
	if err != nil {
		return SPIRERegisterResult{}, fmt.Errorf("register SPIRE identity: %w", redactSecretValueInError(stderr, err))
	}
	result, parseErr := parseSPIREEntryCreateJSON(stdout)
	if parseErr != nil {
		return SPIRERegisterResult{}, parseErr
	}
	result.SPIFFEID = spiffeID
	result.ParentID = parentID
	result.Selectors = normalizedSelectors
	if strings.TrimSpace(result.Status) == "" {
		result.Status = "registered"
	}
	return result, nil
}

func RenderSPIREEntriesTable(entries []SPIREEntry) (string, error) {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "SPIFFE ID\tSELECTORS\tPARENT")
	for _, entry := range entries {
		selectors := strings.Join(entry.Selectors, ",")
		if strings.TrimSpace(selectors) == "" {
			selectors = "-"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", entry.SPIFFEID, selectors, entry.ParentID)
	}
	if err := w.Flush(); err != nil {
		return "", err
	}
	return b.String(), nil
}

func RenderSPIREEntriesJSON(entries []SPIREEntry) ([]byte, error) {
	return json.MarshalIndent(SPIREListOutput{Entries: entries}, "", "  ")
}

func RenderSPIRERegisterTable(result SPIRERegisterResult) (string, error) {
	var b strings.Builder
	_, _ = fmt.Fprintln(&b, "Identity registered successfully")
	_, _ = fmt.Fprintf(&b, "SPIFFE ID: %s\n", result.SPIFFEID)
	_, _ = fmt.Fprintf(&b, "Parent ID: %s\n", result.ParentID)
	_, _ = fmt.Fprintf(&b, "Entry ID: %s\n", result.EntryID)
	_, _ = fmt.Fprintf(&b, "Selectors: %s\n", strings.Join(result.Selectors, ","))
	return b.String(), nil
}

func RenderSPIRERegisterJSON(result SPIRERegisterResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

func (s *SPIRECLI) detectParentID(ctx context.Context) string {
	stdout, _, err := s.runner.Run(
		ctx,
		"docker",
		composeArgs(
			"exec", "-T", "spire-server",
			"/opt/spire/bin/spire-server", "agent", "list",
			"-socketPath", spireSocketPath,
			"-output", "json",
		)...,
	)
	if err != nil {
		return spireDefaultParentID
	}
	if hasLocalAgentParent(stdout) {
		return spireDefaultParentID
	}
	return spireDefaultParentID
}

func parseSPIREEntryShowJSON(raw string) ([]SPIREEntry, error) {
	type spiffeJSON struct {
		TrustDomain string `json:"trust_domain"`
		Path        string `json:"path"`
	}
	type selectorJSON struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	type entryJSON struct {
		ID        string         `json:"id"`
		SPIFFEID  spiffeJSON     `json:"spiffe_id"`
		ParentID  spiffeJSON     `json:"parent_id"`
		Selectors []selectorJSON `json:"selectors"`
	}
	type response struct {
		Entries []entryJSON `json:"entries"`
	}

	var decoded response
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, fmt.Errorf("parse SPIRE entry show JSON: %w", err)
	}

	out := make([]SPIREEntry, 0, len(decoded.Entries))
	for _, entry := range decoded.Entries {
		selectors := make([]string, 0, len(entry.Selectors))
		for _, selector := range entry.Selectors {
			s := strings.TrimSpace(selector.Type + ":" + selector.Value)
			if s != ":" && s != "" {
				selectors = append(selectors, s)
			}
		}
		sort.Strings(selectors)
		out = append(out, SPIREEntry{
			EntryID:   strings.TrimSpace(entry.ID),
			SPIFFEID:  formatSPIFFEID(entry.SPIFFEID.TrustDomain, entry.SPIFFEID.Path),
			ParentID:  formatSPIFFEID(entry.ParentID.TrustDomain, entry.ParentID.Path),
			Selectors: selectors,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].SPIFFEID != out[j].SPIFFEID {
			return out[i].SPIFFEID < out[j].SPIFFEID
		}
		if out[i].ParentID != out[j].ParentID {
			return out[i].ParentID < out[j].ParentID
		}
		return out[i].EntryID < out[j].EntryID
	})
	return out, nil
}

func parseSPIREEntryCreateJSON(raw string) (SPIRERegisterResult, error) {
	type statusJSON struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	type entryJSON struct {
		ID string `json:"id"`
	}
	type resultJSON struct {
		Entry  entryJSON  `json:"entry"`
		Status statusJSON `json:"status"`
	}
	type response struct {
		Results []resultJSON `json:"results"`
	}

	var decoded response
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return SPIRERegisterResult{}, fmt.Errorf("parse SPIRE entry create JSON: %w", err)
	}
	if len(decoded.Results) == 0 {
		return SPIRERegisterResult{}, errors.New("SPIRE entry create returned no results")
	}

	first := decoded.Results[0]
	if first.Status.Code != 0 {
		return SPIRERegisterResult{}, fmt.Errorf("SPIRE create failed: %s", strings.TrimSpace(first.Status.Message))
	}

	return SPIRERegisterResult{
		EntryID: strings.TrimSpace(first.Entry.ID),
		Status:  strings.TrimSpace(first.Status.Message),
	}, nil
}

func hasLocalAgentParent(raw string) bool {
	type spiffeJSON struct {
		TrustDomain string `json:"trust_domain"`
		Path        string `json:"path"`
	}
	type agentJSON struct {
		ID spiffeJSON `json:"id"`
	}
	type response struct {
		Agents []agentJSON `json:"agents"`
	}

	var decoded response
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return false
	}
	for _, agent := range decoded.Agents {
		if strings.TrimSpace(agent.ID.TrustDomain) == spireTrustDomain && strings.TrimSpace(agent.ID.Path) == "/agent/local" {
			return true
		}
	}
	return false
}

func formatSPIFFEID(trustDomain, path string) string {
	td := strings.TrimSpace(trustDomain)
	p := strings.TrimSpace(path)
	if td == "" || p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return "spiffe://" + td + p
}

func normalizeSelectors(selectors []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		selector = strings.TrimSpace(selector)
		if selector == "" {
			continue
		}
		if _, exists := seen[selector]; exists {
			continue
		}
		seen[selector] = struct{}{}
		out = append(out, selector)
	}
	sort.Strings(out)
	return out
}
