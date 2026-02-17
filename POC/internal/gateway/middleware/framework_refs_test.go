package middleware

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResolveFrameworkRefs_DeduplicatesAndSorts(t *testing.T) {
	refs := resolveFrameworkRefs(
		[]string{"potential_injection", "blocked_content", "potential_injection"},
		false,
		http.StatusTooManyRequests,
	)

	if refs == nil {
		t.Fatal("expected framework refs, got nil")
	}

	want := []string{
		"availability.rate_limited",
		"content.blocked",
		"prompt.injection_detected",
		"tool.hash_unverified",
	}
	if !reflect.DeepEqual(refs.SignalKeys, want) {
		t.Fatalf("signal keys mismatch\nwant: %v\ngot:  %v", want, refs.SignalKeys)
	}
}

func TestResolveFrameworkRefs_UnknownSignalsAreIgnored(t *testing.T) {
	refs := resolveFrameworkRefs([]string{"unknown_signal"}, true, http.StatusOK)
	if refs != nil {
		t.Fatalf("expected nil refs for unknown-only signals, got %#v", refs)
	}
}

func TestResolveFrameworkRefs_StatusDerivedSignals(t *testing.T) {
	refs := resolveFrameworkRefs(nil, true, http.StatusForbidden)
	if refs == nil {
		t.Fatal("expected refs for authorization denied signal")
	}

	want := []string{"policy.authorization_denied"}
	if !reflect.DeepEqual(refs.SignalKeys, want) {
		t.Fatalf("signal keys mismatch\nwant: %v\ngot:  %v", want, refs.SignalKeys)
	}
}

func TestAuditLog_EmitsFrameworkRefsFromSignals(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	bundlePath := filepath.Join(tmpDir, "bundle.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")

	if err := os.WriteFile(bundlePath, []byte("package test"), 0644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	auditor, err := NewAuditor(auditPath, bundlePath, registryPath)
	if err != nil {
		t.Fatalf("new auditor: %v", err)
	}

	handler := AuditLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = WithSecurityFlags(r.Context(), []string{"blocked_content", "potential_injection"})
		w.WriteHeader(http.StatusTooManyRequests)
	}), auditor)

	req := httptest.NewRequest("POST", "/framework-refs", nil)
	req = req.WithContext(WithSessionID(req.Context(), "session-framework-refs"))
	req = req.WithContext(WithDecisionID(req.Context(), "decision-framework-refs"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status 429, got %d", rec.Code)
	}

	if err := auditor.Close(); err != nil {
		t.Fatalf("close auditor: %v", err)
	}

	f, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("open audit file: %v", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("expected at least one audit event")
	}

	var event AuditEvent
	if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
		t.Fatalf("unmarshal audit event: %v", err)
	}
	if event.Security == nil || event.Security.FrameworkRefs == nil {
		t.Fatalf("expected framework refs in security audit, got %#v", event.Security)
	}

	want := []string{
		"availability.rate_limited",
		"content.blocked",
		"prompt.injection_detected",
		"tool.hash_unverified",
	}
	if !reflect.DeepEqual(event.Security.FrameworkRefs.SignalKeys, want) {
		t.Fatalf("signal keys mismatch\nwant: %v\ngot:  %v", want, event.Security.FrameworkRefs.SignalKeys)
	}
}
