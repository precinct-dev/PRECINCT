// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctevidence

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

type mockAuditLogger struct {
	events []middleware.AuditEvent
}

func (m *mockAuditLogger) Log(event middleware.AuditEvent) {
	m.events = append(m.events, event)
}

func TestLogConnectorAuthorityDecisionRecordsAuditFields(t *testing.T) {
	t.Parallel()

	logger := &mockAuditLogger{}
	req := httptest.NewRequest(http.MethodPost, "/v1/connectors/register", nil)
	ctx := middleware.WithSPIFFEID(req.Context(), "spiffe://poc.local/agents/admin")
	ctx = middleware.WithSessionID(ctx, "session-1")
	req = req.WithContext(ctx)

	LogConnectorAuthorityDecision(logger, req, "connector-a", "register", "allow", "ok", "decision-1", "trace-1", http.StatusOK)

	if len(logger.events) != 1 {
		t.Fatalf("expected one audit event, got %d", len(logger.events))
	}
	ev := logger.events[0]
	if ev.Action != "connector_authority.register" {
		t.Fatalf("expected action connector_authority.register, got %q", ev.Action)
	}
	if ev.DecisionID != "decision-1" {
		t.Fatalf("expected decision_id decision-1, got %q", ev.DecisionID)
	}
	if ev.TraceID != "trace-1" {
		t.Fatalf("expected trace_id trace-1, got %q", ev.TraceID)
	}
	if ev.Method != http.MethodPost {
		t.Fatalf("expected method %s, got %q", http.MethodPost, ev.Method)
	}
	if ev.Path != "/v1/connectors/register" {
		t.Fatalf("expected path /v1/connectors/register, got %q", ev.Path)
	}
	if ev.Result == "" {
		t.Fatal("expected non-empty result")
	}
}

func TestCloneConnectorConformanceReportAugmentsCorrelationMetadata(t *testing.T) {
	t.Parallel()

	base := map[string]any{
		"report_type":  "connector_conformance_v1",
		"connectors":   []string{"connector-a"},
		"schema_ver":   "v1",
		"generated_at": "2026-01-01T00:00:00Z",
	}

	out := CloneConnectorConformanceReport(base, "trace-2", "decision-2")
	if out["trace_id"] != "trace-2" {
		t.Fatalf("expected trace_id trace-2, got %v", out["trace_id"])
	}
	if out["decision_id"] != "decision-2" {
		t.Fatalf("expected decision_id decision-2, got %v", out["decision_id"])
	}

	// Ensure original report stays unchanged.
	if _, ok := base["trace_id"]; ok {
		t.Fatalf("expected base report to remain unmodified")
	}

	if !reflect.DeepEqual(base["connectors"], out["connectors"]) {
		t.Fatalf("expected connectors to be preserved")
	}
}

func TestWriteJSONResponse(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"status": "ok",
		"count":  1,
	}
	w := httptest.NewRecorder()
	WriteJSONResponse(w, http.StatusAccepted, payload)
	res := w.Result()
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, res.StatusCode)
	}
	if got := res.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected application/json content type, got %q", got)
	}
}
