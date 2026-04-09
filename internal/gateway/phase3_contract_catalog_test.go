// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/xeipuuv/gojsonschema"
)

func TestCanonicalSchemasValidateExamples(t *testing.T) {
	requestSchema := repoPath("contracts", "v2.4", "schemas", "plane_request_v2.schema.json")
	decisionSchema := repoPath("contracts", "v2.4", "schemas", "plane_decision_v2.schema.json")

	if err := validateJSONExampleAgainstSchema(requestSchema, repoPath("contracts", "v2.4", "examples", "ingress_admit_request.example.json")); err != nil {
		t.Fatalf("request example invalid: %v", err)
	}
	if err := validateJSONExampleAgainstSchema(decisionSchema, repoPath("contracts", "v2.4", "examples", "ingress_allow_response.example.json")); err != nil {
		t.Fatalf("ingress response example invalid: %v", err)
	}
	if err := validateJSONExampleAgainstSchema(decisionSchema, repoPath("contracts", "v2.4", "examples", "model_deny_response.example.json")); err != nil {
		t.Fatalf("model response example invalid: %v", err)
	}
}

func TestReasonCodeCatalogMatchesPhase3Constants(t *testing.T) {
	sourceBytes, err := os.ReadFile(repoPath("internal", "gateway", "phase3_contracts.go"))
	if err != nil {
		t.Fatalf("read phase3 contracts source: %v", err)
	}

	re := regexp.MustCompile(`Reason[A-Za-z0-9]+\s+ReasonCode\s+=\s+"([A-Z0-9_]+)"`)
	matches := re.FindAllSubmatch(sourceBytes, -1)
	if len(matches) == 0 {
		t.Fatal("no ReasonCode constants found in phase3_contracts.go")
	}

	expected := map[string]struct{}{}
	for _, m := range matches {
		expected[string(m[1])] = struct{}{}
	}

	catalogCodes, err := loadCatalogCodeSet(repoPath("contracts", "v2.4", "reason-code-catalog.v2.4.json"))
	if err != nil {
		t.Fatalf("load reason-code catalog: %v", err)
	}

	for code := range expected {
		if _, ok := catalogCodes[code]; !ok {
			t.Fatalf("catalog missing reason code from source constants: %s", code)
		}
	}

	for code := range catalogCodes {
		if _, ok := expected[code]; !ok {
			t.Fatalf("catalog contains reason code not present in source constants: %s", code)
		}
	}

	if len(expected) != len(catalogCodes) {
		t.Fatalf("catalog size mismatch: expected=%d got=%d", len(expected), len(catalogCodes))
	}
}

func TestLiveResponsesMapToCanonicalReasonCodeCatalog(t *testing.T) {
	catalogCodes, err := loadCatalogCodeSet(repoPath("contracts", "v2.4", "reason-code-catalog.v2.4.json"))
	if err != nil {
		t.Fatalf("load reason-code catalog: %v", err)
	}

	gw, _ := newPhase3TestGateway(t)
	// Keep this conformance test deterministic regardless of package-wide env/config
	// mutations by forcing a permissive in-memory rate limiter.
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	handler := gw.Handler()

	ingressBody := map[string]any{
		"envelope": map[string]any{
			"run_id":          "run-catalog-ingress",
			"session_id":      "session-catalog",
			"tenant":          "tenant-a",
			"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "run-catalog-ingress",
				"session_id":      "session-catalog",
				"tenant":          "tenant-a",
				"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
			"attributes": map[string]any{
				"source_principal": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				"event_id":         "evt-catalog-ingress",
			},
		},
	}

	code, resp := postPlaneJSON(t, handler, "/v1/ingress/admit", ingressBody)
	if code != http.StatusOK {
		t.Fatalf("expected ingress 200, got %d body=%v", code, resp)
	}
	assertReasonCodeInCatalog(t, resp, catalogCodes)

	modelBody := map[string]any{
		"envelope": map[string]any{
			"run_id":          "run-catalog-model-deny",
			"session_id":      "session-catalog",
			"tenant":          "tenant-a",
			"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"plane":           "model",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "run-catalog-model-deny",
				"session_id":      "session-catalog",
				"tenant":          "tenant-a",
				"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				"plane":           "model",
			},
			"action":   "model.call",
			"resource": "model/inference",
			"attributes": map[string]any{
				"provider": "unknown-provider",
				"model":    "any-model",
			},
		},
	}

	code, resp = postPlaneJSON(t, handler, "/v1/model/call", modelBody)
	if code != http.StatusForbidden {
		t.Fatalf("expected model deny 403, got %d body=%v", code, resp)
	}
	assertReasonCodeInCatalog(t, resp, catalogCodes)
}

func validateJSONExampleAgainstSchema(schemaPath, docPath string) error {
	schemaLoader := gojsonschema.NewReferenceLoader("file://" + schemaPath)
	docLoader := gojsonschema.NewReferenceLoader("file://" + docPath)

	result, err := gojsonschema.Validate(schemaLoader, docLoader)
	if err != nil {
		return err
	}
	if !result.Valid() {
		errs := make([]string, 0, len(result.Errors()))
		for _, verr := range result.Errors() {
			errs = append(errs, verr.String())
		}
		sort.Strings(errs)
		return &schemaValidationError{Errors: errs}
	}
	return nil
}

type schemaValidationError struct {
	Errors []string
}

func (e *schemaValidationError) Error() string {
	b, _ := json.Marshal(e.Errors)
	return string(b)
}

func loadCatalogCodeSet(path string) (map[string]struct{}, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Codes []struct {
			Code string `json:"code"`
		} `json:"codes"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(payload.Codes))
	for _, c := range payload.Codes {
		out[c.Code] = struct{}{}
	}
	return out, nil
}

func repoPath(parts ...string) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to resolve caller path")
	}
	// This file is at POC/internal/gateway; repo root for this module is POC.
	base := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return filepath.Join(append([]string{base}, parts...)...)
}

func postPlaneJSON(t *testing.T, handler http.Handler, path string, payload map[string]any) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response body: %v body=%s", err, rec.Body.String())
	}
	return rec.Code, out
}

func assertReasonCodeInCatalog(t *testing.T, resp map[string]any, catalog map[string]struct{}) {
	t.Helper()
	reason, ok := resp["reason_code"].(string)
	if !ok || reason == "" {
		t.Fatalf("response missing reason_code: %#v", resp)
	}
	if _, ok := catalog[reason]; !ok {
		t.Fatalf("reason_code %q not found in canonical catalog", reason)
	}
}
