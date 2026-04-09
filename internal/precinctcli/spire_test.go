// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseSPIREEntryShowJSON(t *testing.T) {
	raw := `{
  "entries": [
    {
      "id": "entry-1",
      "spiffe_id": {"trust_domain":"poc.local","path":"/agents/example/dev"},
      "parent_id": {"trust_domain":"poc.local","path":"/agent/local"},
      "selectors": [{"type":"docker","value":"label:spiffe-id:example"}]
    }
  ]
}`

	entries, err := parseSPIREEntryShowJSON(raw)
	if err != nil {
		t.Fatalf("parseSPIREEntryShowJSON() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %+v", entries)
	}
	got := entries[0]
	if got.EntryID != "entry-1" {
		t.Fatalf("unexpected entry id: %+v", got)
	}
	if got.SPIFFEID != "spiffe://poc.local/agents/example/dev" {
		t.Fatalf("unexpected spiffe id: %+v", got)
	}
	if got.ParentID != "spiffe://poc.local/agent/local" {
		t.Fatalf("unexpected parent id: %+v", got)
	}
	if len(got.Selectors) != 1 || got.Selectors[0] != "docker:label:spiffe-id:example" {
		t.Fatalf("unexpected selectors: %+v", got)
	}
}

func TestSPIRECLI_RegisterIdentity_BuildsExpectedCommands(t *testing.T) {
	runner := &fakeCommandRunner{
		results: []fakeCommandResult{
			{
				stdout: `{"agents":[{"id":{"trust_domain":"poc.local","path":"/agent/local"}}]}`,
			},
			{
				stdout: `{"results":[{"entry":{"id":"entry-created"},"status":{"code":0,"message":"OK"}}]}`,
			},
		},
	}
	cli := NewSPIRECLIWithRunner(runner)

	result, err := cli.RegisterIdentity(context.Background(), "demo-agent", []string{"docker:label:spiffe-id:demo-agent"})
	if err != nil {
		t.Fatalf("RegisterIdentity() error = %v", err)
	}
	if result.EntryID != "entry-created" {
		t.Fatalf("unexpected register result: %+v", result)
	}
	if result.ParentID != "spiffe://poc.local/agent/local" {
		t.Fatalf("unexpected parent id: %+v", result)
	}
	if result.SPIFFEID != "spiffe://poc.local/agents/demo-agent/dev" {
		t.Fatalf("unexpected spiffe id: %+v", result)
	}

	if len(runner.calls) != 2 {
		t.Fatalf("expected 2 calls, got %+v", runner.calls)
	}
	wantFirst := []string{
		"docker",
	}
	wantFirst = append(wantFirst, composeArgs(
		"exec", "-T", "spire-server",
		"/opt/spire/bin/spire-server", "agent", "list",
		"-socketPath", "/tmp/spire-server/private/api.sock",
		"-output", "json",
	)...)
	if !reflect.DeepEqual(runner.calls[0], wantFirst) {
		t.Fatalf("unexpected first command: got=%v want=%v", runner.calls[0], wantFirst)
	}
	wantSecondPrefix := []string{
		"docker",
	}
	wantSecondPrefix = append(wantSecondPrefix, composeArgs(
		"exec", "-T", "spire-server",
		"/opt/spire/bin/spire-server", "entry", "create",
		"-socketPath", "/tmp/spire-server/private/api.sock",
		"-spiffeID", "spiffe://poc.local/agents/demo-agent/dev",
		"-parentID", "spiffe://poc.local/agent/local",
		"-selector", "docker:label:spiffe-id:demo-agent",
	)...)
	if len(runner.calls[1]) < len(wantSecondPrefix) {
		t.Fatalf("second command shorter than expected: %v", runner.calls[1])
	}
	if !reflect.DeepEqual(runner.calls[1][:len(wantSecondPrefix)], wantSecondPrefix) {
		t.Fatalf("unexpected second command prefix: got=%v want=%v", runner.calls[1], wantSecondPrefix)
	}
}

func TestSPIRECLI_ListEntries_Error(t *testing.T) {
	runner := &fakeCommandRunner{
		results: []fakeCommandResult{
			{
				stderr: "compose failed",
				err:    errors.New("exit status 1"),
			},
		},
	}
	cli := NewSPIRECLIWithRunner(runner)

	_, err := cli.ListEntries(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "list SPIRE entries") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenderSPIREEntriesTableAndJSON(t *testing.T) {
	entries := []SPIREEntry{
		{
			EntryID:   "entry-1",
			SPIFFEID:  "spiffe://poc.local/agents/example/dev",
			ParentID:  "spiffe://poc.local/agent/local",
			Selectors: []string{"docker:label:spiffe-id:example"},
		},
	}

	table, err := RenderSPIREEntriesTable(entries)
	if err != nil {
		t.Fatalf("RenderSPIREEntriesTable() error = %v", err)
	}
	if !strings.Contains(table, "SPIFFE ID") || !strings.Contains(table, "spiffe://poc.local/agents/example/dev") {
		t.Fatalf("unexpected table output: %q", table)
	}

	js, err := RenderSPIREEntriesJSON(entries)
	if err != nil {
		t.Fatalf("RenderSPIREEntriesJSON() error = %v", err)
	}
	if !strings.Contains(string(js), `"spiffe_id": "spiffe://poc.local/agents/example/dev"`) {
		t.Fatalf("unexpected json output: %s", string(js))
	}
}
