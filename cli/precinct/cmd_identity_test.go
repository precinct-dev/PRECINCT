// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/precinctcli"
)

type fakeSPIREManager struct {
	listEntries []precinctcli.SPIREEntry
	listErr     error

	registerResult precinctcli.SPIRERegisterResult
	registerErr    error
	registerName   string
	registerSel    []string
}

func (f *fakeSPIREManager) ListEntries(_ context.Context) ([]precinctcli.SPIREEntry, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listEntries, nil
}

func (f *fakeSPIREManager) RegisterIdentity(_ context.Context, name string, selectors []string) (precinctcli.SPIRERegisterResult, error) {
	f.registerName = name
	f.registerSel = append([]string(nil), selectors...)
	if f.registerErr != nil {
		return precinctcli.SPIRERegisterResult{}, f.registerErr
	}
	return f.registerResult, nil
}

func withFakeSPIREManager(t *testing.T, mgr spireManager) {
	t.Helper()
	orig := newSPIREManager
	newSPIREManager = func() spireManager { return mgr }
	t.Cleanup(func() { newSPIREManager = orig })
}

func TestPrecinctIdentityList_JSON(t *testing.T) {
	withFakeSPIREManager(t, &fakeSPIREManager{
		listEntries: []precinctcli.SPIREEntry{
			{
				EntryID:   "entry-1",
				SPIFFEID:  "spiffe://poc.local/agents/example/dev",
				ParentID:  "spiffe://poc.local/agent/local",
				Selectors: []string{"docker:label:spiffe-id:example"},
			},
		},
	})

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"identity", "list", "--format", "json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed struct {
		Entries []struct {
			SPIFFEID string `json:"spiffe_id"`
			ParentID string `json:"parent_id"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json output: %v raw=%q", err, stdout.String())
	}
	if len(parsed.Entries) != 1 {
		t.Fatalf("expected one entry, got %+v", parsed)
	}
	if parsed.Entries[0].SPIFFEID == "" || parsed.Entries[0].ParentID == "" {
		t.Fatalf("unexpected parsed output: %+v", parsed)
	}
}

func TestPrecinctIdentityRegister_ConfirmRequired(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"identity", "register", "demo-agent"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--confirm is required for identity register") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestPrecinctIdentityRegister_UsesPromptedDefaultSelector(t *testing.T) {
	fake := &fakeSPIREManager{
		registerResult: precinctcli.SPIRERegisterResult{
			EntryID:   "entry-1",
			SPIFFEID:  "spiffe://poc.local/agents/demo-agent/dev",
			ParentID:  "spiffe://poc.local/agent/local",
			Selectors: []string{"docker:label:spiffe-id:demo-agent"},
			Status:    "OK",
		},
	}
	withFakeSPIREManager(t, fake)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"identity", "register", "demo-agent", "--confirm", "--format", "json"},
		strings.NewReader("\n"),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if fake.registerName != "demo-agent" {
		t.Fatalf("unexpected register name: %q", fake.registerName)
	}
	if len(fake.registerSel) != 1 || fake.registerSel[0] != "docker:label:spiffe-id:demo-agent" {
		t.Fatalf("unexpected selectors passed to manager: %+v", fake.registerSel)
	}

	var parsed struct {
		EntryID  string `json:"entry_id"`
		ParentID string `json:"parent_id"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json output: %v raw=%q", err, stdout.String())
	}
	if parsed.EntryID == "" || parsed.ParentID != "spiffe://poc.local/agent/local" {
		t.Fatalf("unexpected parsed output: %+v", parsed)
	}
}

func TestPrecinctIdentityList_TableDefault(t *testing.T) {
	withFakeSPIREManager(t, &fakeSPIREManager{
		listEntries: []precinctcli.SPIREEntry{
			{
				EntryID:   "entry-1",
				SPIFFEID:  "spiffe://poc.local/agents/example/dev",
				ParentID:  "spiffe://poc.local/agent/local",
				Selectors: []string{"docker:label:spiffe-id:example"},
			},
		},
	})

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"identity", "list"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "SPIFFE ID") || !strings.Contains(out, "spiffe://poc.local/agents/example/dev") {
		t.Fatalf("unexpected table output: %q", out)
	}
}

func TestPrecinctIdentityList_Error(t *testing.T) {
	withFakeSPIREManager(t, &fakeSPIREManager{
		listErr: errors.New("spire unreachable"),
	})

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"identity", "list"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "spire unreachable") {
		t.Fatalf("expected propagated error, got %q", stderr.String())
	}
}
