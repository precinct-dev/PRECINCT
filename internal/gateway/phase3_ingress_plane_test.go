// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// ---------------------------------------------------------------------------
// Unit tests: ingressPlanePolicyEngine.evaluate
// ---------------------------------------------------------------------------

func validCanonicalRequest(spiffe string, now time.Time) PlaneRequestV2 {
	return PlaneRequestV2{
		Envelope: RunEnvelope{
			RunID:         "run-canonical-1",
			SessionID:     "session-canonical-1",
			Tenant:        "tenant-a",
			ActorSPIFFEID: spiffe,
			Plane:         PlaneIngress,
		},
		Policy: PolicyInputV2{
			Envelope: RunEnvelope{
				RunID:         "run-canonical-1",
				SessionID:     "session-canonical-1",
				Tenant:        "tenant-a",
				ActorSPIFFEID: spiffe,
				Plane:         PlaneIngress,
			},
			Action:   "ingress.admit",
			Resource: "ingress/event",
			Attributes: map[string]any{
				"connector_type":   "webhook",
				"source_id":        "connector-abc",
				"source_principal": spiffe,
				"event_id":         "evt-001",
				"nonce":            "nonce-xyz",
				"event_timestamp":  now.UTC().Format(time.RFC3339),
				"payload":          map[string]any{"key": "value"},
			},
		},
	}
}

func TestIngressPlane_ValidCanonicalEnvelope_Allow(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	req := validCanonicalRequest(spiffe, now)

	decision, reason, status, meta := engine.evaluate(req, now)

	if decision != DecisionAllow {
		t.Fatalf("expected allow, got %s", decision)
	}
	if reason != ReasonIngressAllow {
		t.Fatalf("expected %s, got %s", ReasonIngressAllow, reason)
	}
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	// AC7: metadata includes required fields.
	for _, key := range []string{"connector_type", "source_id", "event_id", "payload_ref", "payload_size_bytes", "raw_payload_stripped"} {
		if _, ok := meta[key]; !ok {
			t.Fatalf("metadata missing key: %s", key)
		}
	}
	if meta["connector_type"] != "webhook" {
		t.Fatalf("expected connector_type=webhook, got %v", meta["connector_type"])
	}
	if meta["raw_payload_stripped"] != true {
		t.Fatalf("expected raw_payload_stripped=true, got %v", meta["raw_payload_stripped"])
	}
	// AC3: payload_ref uses ingress://payload/ prefix.
	ref, ok := meta["payload_ref"].(string)
	if !ok || len(ref) < len("ingress://payload/") {
		t.Fatalf("expected ingress://payload/<hex>, got %v", meta["payload_ref"])
	}
	if ref[:len("ingress://payload/")] != "ingress://payload/" {
		t.Fatalf("payload_ref missing prefix: %s", ref)
	}
}

func TestIngressPlane_MissingConnectorType_SchemaInvalid(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	delete(req.Policy.Attributes, "connector_type")

	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionDeny || reason != ReasonIngressSchemaInvalid || status != 400 {
		t.Fatalf("expected deny/INGRESS_SCHEMA_INVALID/400, got %s/%s/%d", decision, reason, status)
	}
}

func TestIngressPlane_InvalidConnectorType_SchemaInvalid(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	req.Policy.Attributes["connector_type"] = "grpc"

	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionDeny || reason != ReasonIngressSchemaInvalid || status != 400 {
		t.Fatalf("expected deny/INGRESS_SCHEMA_INVALID/400, got %s/%s/%d", decision, reason, status)
	}
}

func TestIngressPlane_MissingSourceID_SchemaInvalid(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	delete(req.Policy.Attributes, "source_id")

	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionDeny || reason != ReasonIngressSchemaInvalid || status != 400 {
		t.Fatalf("expected deny/INGRESS_SCHEMA_INVALID/400, got %s/%s/%d", decision, reason, status)
	}
}

func TestIngressPlane_MissingSourcePrincipal_SchemaInvalid(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	delete(req.Policy.Attributes, "source_principal")

	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionDeny || reason != ReasonIngressSchemaInvalid || status != 400 {
		t.Fatalf("expected deny/INGRESS_SCHEMA_INVALID/400, got %s/%s/%d", decision, reason, status)
	}
}

func TestIngressPlane_SourcePrincipalMismatch_Unauthenticated(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	actorSPIFFE := "spiffe://poc.local/test/agent-a"
	req := validCanonicalRequest(actorSPIFFE, now)
	// Set source_principal to something different than ActorSPIFFEID.
	req.Policy.Attributes["source_principal"] = "spiffe://poc.local/test/agent-b"

	decision, reason, status, meta := engine.evaluate(req, now)
	if decision != DecisionDeny || reason != ReasonIngressSourceUnauth || status != 401 {
		t.Fatalf("expected deny/INGRESS_SOURCE_UNAUTHENTICATED/401, got %s/%s/%d", decision, reason, status)
	}
	if meta["source_principal"] != "spiffe://poc.local/test/agent-b" {
		t.Fatalf("metadata should include mismatched source_principal")
	}
	if meta["actor_spiffe_id"] != actorSPIFFE {
		t.Fatalf("metadata should include actor_spiffe_id")
	}
}

func TestIngressPlane_MissingEventID_SchemaInvalid(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	delete(req.Policy.Attributes, "event_id")

	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionDeny || reason != ReasonIngressSchemaInvalid || status != 400 {
		t.Fatalf("expected deny/INGRESS_SCHEMA_INVALID/400, got %s/%s/%d", decision, reason, status)
	}
}

func TestIngressPlane_MissingNonce_SchemaInvalid(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	delete(req.Policy.Attributes, "nonce")

	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionDeny || reason != ReasonIngressSchemaInvalid || status != 400 {
		t.Fatalf("expected deny/INGRESS_SCHEMA_INVALID/400, got %s/%s/%d", decision, reason, status)
	}
}

func TestIngressPlane_MissingEventTimestamp_SchemaInvalid(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	delete(req.Policy.Attributes, "event_timestamp")

	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionDeny || reason != ReasonIngressSchemaInvalid || status != 400 {
		t.Fatalf("expected deny/INGRESS_SCHEMA_INVALID/400, got %s/%s/%d", decision, reason, status)
	}
}

func TestIngressPlane_StaleTimestamp_FreshnessStale(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	// Set event_timestamp to 15 minutes ago (beyond 10min window).
	stale := now.Add(-15 * time.Minute)
	req.Policy.Attributes["event_timestamp"] = stale.Format(time.RFC3339)

	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionQuarantine {
		t.Fatalf("expected quarantine, got %s", decision)
	}
	if reason != ReasonIngressFreshnessStale {
		t.Fatalf("expected %s, got %s", ReasonIngressFreshnessStale, reason)
	}
	if status != 202 {
		t.Fatalf("expected 202, got %d", status)
	}
}

func TestIngressPlane_FutureTimestamp_FreshnessStale(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	// Set event_timestamp to 15 minutes in the future.
	future := now.Add(15 * time.Minute)
	req.Policy.Attributes["event_timestamp"] = future.Format(time.RFC3339)

	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionQuarantine || reason != ReasonIngressFreshnessStale || status != 202 {
		t.Fatalf("expected quarantine/INGRESS_FRESHNESS_STALE/202, got %s/%s/%d", decision, reason, status)
	}
}

func TestIngressPlane_ReplayDetected(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)

	// First call should allow.
	decision, reason, _, _ := engine.evaluate(req, now)
	if decision != DecisionAllow || reason != ReasonIngressAllow {
		t.Fatalf("first call expected allow, got %s/%s", decision, reason)
	}

	// Second call with same nonce+event_id should detect replay.
	req.Envelope.RunID = "run-canonical-2"
	req.Policy.Envelope.RunID = "run-canonical-2"
	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionDeny || reason != ReasonIngressReplayDetected || status != 409 {
		t.Fatalf("expected deny/INGRESS_REPLAY_DETECTED/409, got %s/%s/%d", decision, reason, status)
	}
}

func TestIngressPlane_RequiresStepUp(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	req.Policy.Attributes["requires_step_up"] = true

	decision, reason, status, meta := engine.evaluate(req, now)
	if decision != DecisionStepUp {
		t.Fatalf("expected step_up, got %s", decision)
	}
	if reason != ReasonIngressStepUpRequired {
		t.Fatalf("expected %s, got %s", ReasonIngressStepUpRequired, reason)
	}
	if status != 202 {
		t.Fatalf("expected 202, got %d", status)
	}
	if meta["connector_type"] != "webhook" {
		t.Fatalf("metadata should include connector_type")
	}
}

func TestIngressPlane_PayloadContentAddressing_Deterministic(t *testing.T) {
	payload := map[string]any{"key": "value", "nested": map[string]any{"a": 1}}

	ref1, size1 := ingressPayloadRef(payload)
	ref2, size2 := ingressPayloadRef(payload)

	if ref1 != ref2 {
		t.Fatalf("payload_ref not deterministic: %s vs %s", ref1, ref2)
	}
	if size1 != size2 {
		t.Fatalf("payload_size not deterministic: %d vs %d", size1, size2)
	}

	// Verify it produces ingress://payload/<sha256hex>.
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	expected := "ingress://payload/" + hex.EncodeToString(sum[:])
	if ref1 != expected {
		t.Fatalf("expected payload_ref=%s, got %s", expected, ref1)
	}
}

func TestIngressPlane_NonceTTLCleanup(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	spiffe := "spiffe://poc.local/test/agent"
	now := time.Now().UTC()

	req := validCanonicalRequest(spiffe, now)
	// First request at t=0.
	decision, _, _, _ := engine.evaluate(req, now)
	if decision != DecisionAllow {
		t.Fatalf("first call expected allow, got %s", decision)
	}

	// Same nonce at t=31min should be allowed (TTL=30min, nonce evicted).
	later := now.Add(31 * time.Minute)
	req.Envelope.RunID = "run-canonical-after-ttl"
	req.Policy.Envelope.RunID = "run-canonical-after-ttl"
	req.Policy.Attributes["event_timestamp"] = later.Format(time.RFC3339)

	decision, reason, _, _ := engine.evaluate(req, later)
	if decision != DecisionAllow || reason != ReasonIngressAllow {
		t.Fatalf("after TTL expected allow, got %s/%s", decision, reason)
	}
}

func TestIngressPlane_QueueConnectorType(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	req.Policy.Attributes["connector_type"] = "queue"

	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionAllow || reason != ReasonIngressAllow || status != 200 {
		t.Fatalf("queue connector expected allow, got %s/%s/%d", decision, reason, status)
	}
}

func TestIngressPlane_TimestampUnixSeconds(t *testing.T) {
	engine := newIngressPlanePolicyEngine()
	now := time.Now().UTC()
	spiffe := "spiffe://poc.local/test/agent"
	req := validCanonicalRequest(spiffe, now)
	// Use unix seconds (float64, as JSON deserializes numbers).
	req.Policy.Attributes["event_timestamp"] = float64(now.Unix())

	decision, reason, status, _ := engine.evaluate(req, now)
	if decision != DecisionAllow || reason != ReasonIngressAllow || status != 200 {
		t.Fatalf("unix timestamp expected allow, got %s/%s/%d", decision, reason, status)
	}
}

func TestHasCanonicalEnvelopeFields(t *testing.T) {
	tests := []struct {
		name   string
		attrs  map[string]any
		expect bool
	}{
		{
			name:   "nil attrs",
			attrs:  nil,
			expect: false,
		},
		{
			name:   "empty attrs",
			attrs:  map[string]any{},
			expect: false,
		},
		{
			name: "missing nonce",
			attrs: map[string]any{
				"connector_type": "webhook",
				"source_id":      "src-1",
				"payload":        "data",
			},
			expect: false,
		},
		{
			name: "missing payload",
			attrs: map[string]any{
				"connector_type": "webhook",
				"source_id":      "src-1",
				"nonce":          "n-1",
			},
			expect: false,
		},
		{
			name: "all canonical fields present",
			attrs: map[string]any{
				"connector_type": "webhook",
				"source_id":      "src-1",
				"nonce":          "n-1",
				"payload":        map[string]any{"k": "v"},
			},
			expect: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasCanonicalEnvelopeFields(tt.attrs)
			if got != tt.expect {
				t.Fatalf("hasCanonicalEnvelopeFields: expected %v, got %v", tt.expect, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration tests: full HTTP handleIngressAdmit flow (no mocks)
// ---------------------------------------------------------------------------

func TestIngressPlane_Integration_CanonicalEnvelope_FullHTTPFlow(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	spiffe := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	now := time.Now().UTC()

	payload := map[string]any{
		"envelope": map[string]any{
			"run_id":          "run-integ-canonical",
			"session_id":      "session-integ-canonical",
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffe,
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "run-integ-canonical",
				"session_id":      "session-integ-canonical",
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffe,
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
			"attributes": map[string]any{
				"connector_type":   "webhook",
				"source_id":        "connector-integ-1",
				"source_principal": spiffe,
				"event_id":         "evt-integ-001",
				"nonce":            "nonce-integ-001",
				"event_timestamp":  now.Format(time.RFC3339),
				"payload":          map[string]any{"data": "integration-test"},
			},
		},
	}

	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", payload)
	if code != http.StatusOK {
		t.Fatalf("canonical envelope expected 200, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressAllow) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonIngressAllow, resp["reason_code"])
	}

	// Verify metadata includes payload_ref and payload_size_bytes.
	meta, ok := resp["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata in response, got %v", resp)
	}
	payloadRef, ok := meta["payload_ref"].(string)
	if !ok || payloadRef == "" {
		t.Fatalf("expected payload_ref in metadata, got %v", meta["payload_ref"])
	}
	if payloadRef[:len("ingress://payload/")] != "ingress://payload/" {
		t.Fatalf("payload_ref missing prefix: %s", payloadRef)
	}
	if meta["raw_payload_stripped"] != true {
		t.Fatalf("expected raw_payload_stripped=true, got %v", meta["raw_payload_stripped"])
	}
	if meta["connector_type"] != "webhook" {
		t.Fatalf("expected connector_type=webhook, got %v", meta["connector_type"])
	}
	if meta["source_id"] != "connector-integ-1" {
		t.Fatalf("expected source_id=connector-integ-1, got %v", meta["source_id"])
	}
}

func TestIngressPlane_Integration_MetadataLikePIIPassesToPlaneHandler(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	spiffe := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	now := time.Now().UTC()

	payload := map[string]any{
		"envelope": map[string]any{
			"run_id":          "phase3-compose-1773129666",
			"session_id":      "phase3-compose-session-1773129666",
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffe,
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "phase3-compose-1773129666",
				"session_id":      "phase3-compose-session-1773129666",
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffe,
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
			"attributes": map[string]any{
				"connector_type":   "webhook",
				"source_id":        "connector-integ-phoney",
				"source_principal": spiffe,
				"event_id":         "evt-integ-phoney",
				"nonce":            "nonce-integ-phoney",
				"event_timestamp":  now.Format(time.RFC3339),
				"payload":          map[string]any{"message": "integration-test"},
			},
		},
	}

	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", payload)
	if code != http.StatusOK {
		t.Fatalf("expected 200 with structured phase3 decision, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressAllow) {
		t.Fatalf("expected reason_code=%s, got %v", ReasonIngressAllow, resp["reason_code"])
	}
	if got, _ := resp["middleware"].(string); got == "dlp_scan" {
		t.Fatalf("expected phase3 ingress handler response, got generic dlp response: %v", resp)
	}
	envelope, _ := resp["envelope"].(map[string]any)
	if got, _ := envelope["session_id"].(string); got != "phase3-compose-session-1773129666" {
		t.Fatalf("expected response envelope session_id to round-trip, got %v", envelope["session_id"])
	}
}

func TestIngressPlane_Integration_WithoutCanonicalFields_BackwardCompat(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	spiffe := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"

	// Request WITHOUT canonical fields (no connector_type, no nonce, no payload).
	// Should fall through to the existing handler and return INGRESS_ALLOW.
	payload := map[string]any{
		"envelope": map[string]any{
			"run_id":          "run-integ-compat",
			"session_id":      "session-integ-compat",
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffe,
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "run-integ-compat",
				"session_id":      "session-integ-compat",
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffe,
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
			"attributes": map[string]any{
				"event_id":        "evt-compat-001",
				"event_timestamp": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", payload)
	if code != http.StatusOK {
		t.Fatalf("backward compat expected 200, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressAllow) {
		t.Fatalf("backward compat expected reason_code=%s, got %v", ReasonIngressAllow, resp["reason_code"])
	}

	// Verify the response does NOT contain payload_ref (not a canonical envelope).
	if meta, ok := resp["metadata"].(map[string]any); ok {
		if _, hasRef := meta["payload_ref"]; hasRef {
			t.Fatalf("backward compat should not produce payload_ref")
		}
	}
}

func TestIngressPlane_Integration_ReplayViaHTTP(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	spiffe := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	now := time.Now().UTC()

	buildPayload := func(runID string) map[string]any {
		return map[string]any{
			"envelope": map[string]any{
				"run_id":          runID,
				"session_id":      "session-integ-replay",
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffe,
				"plane":           "ingress",
			},
			"policy": map[string]any{
				"envelope": map[string]any{
					"run_id":          runID,
					"session_id":      "session-integ-replay",
					"tenant":          "tenant-a",
					"actor_spiffe_id": spiffe,
					"plane":           "ingress",
				},
				"action":   "ingress.admit",
				"resource": "ingress/event",
				"attributes": map[string]any{
					"connector_type":   "webhook",
					"source_id":        "connector-integ-replay",
					"source_principal": spiffe,
					"event_id":         "evt-replay-integ",
					"nonce":            "nonce-replay-integ",
					"event_timestamp":  now.Format(time.RFC3339),
					"payload":          map[string]any{"data": "replay-test"},
				},
			},
		}
	}

	// First request should succeed.
	code, _ := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", buildPayload("run-replay-1"))
	if code != http.StatusOK {
		t.Fatalf("first submit expected 200, got %d", code)
	}

	// Second request with same nonce+event_id should be 409.
	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", buildPayload("run-replay-2"))
	if code != http.StatusConflict {
		t.Fatalf("replay expected 409, got %d", code)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressReplayDetected) {
		t.Fatalf("replay expected %s, got %v", ReasonIngressReplayDetected, resp["reason_code"])
	}
}

func TestIngressPlane_Integration_SourcePrincipalMismatchViaHTTP(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	actorSPIFFE := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	wrongPrincipal := "spiffe://poc.local/agents/mcp-client/other/dev"
	now := time.Now().UTC()

	payload := map[string]any{
		"envelope": map[string]any{
			"run_id":          "run-integ-mismatch",
			"session_id":      "session-integ-mismatch",
			"tenant":          "tenant-a",
			"actor_spiffe_id": actorSPIFFE,
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "run-integ-mismatch",
				"session_id":      "session-integ-mismatch",
				"tenant":          "tenant-a",
				"actor_spiffe_id": actorSPIFFE,
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
			"attributes": map[string]any{
				"connector_type":   "webhook",
				"source_id":        "connector-integ-mismatch",
				"source_principal": wrongPrincipal,
				"event_id":         "evt-mismatch-integ",
				"nonce":            "nonce-mismatch-integ",
				"event_timestamp":  now.Format(time.RFC3339),
				"payload":          map[string]any{"data": "mismatch-test"},
			},
		},
	}

	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", payload)
	if code != http.StatusUnauthorized {
		t.Fatalf("mismatch expected 401, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressSourceUnauth) {
		t.Fatalf("mismatch expected %s, got %v", ReasonIngressSourceUnauth, resp["reason_code"])
	}
}

func TestIngressPlane_Integration_StaleTimestampViaHTTP(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	spiffe := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	stale := time.Now().UTC().Add(-15 * time.Minute)

	payload := map[string]any{
		"envelope": map[string]any{
			"run_id":          "run-integ-stale",
			"session_id":      "session-integ-stale",
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffe,
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "run-integ-stale",
				"session_id":      "session-integ-stale",
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffe,
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
			"attributes": map[string]any{
				"connector_type":   "webhook",
				"source_id":        "connector-integ-stale",
				"source_principal": spiffe,
				"event_id":         "evt-stale-integ",
				"nonce":            "nonce-stale-integ",
				"event_timestamp":  stale.Format(time.RFC3339),
				"payload":          map[string]any{"data": "stale-test"},
			},
		},
	}

	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", payload)
	if code != http.StatusAccepted {
		t.Fatalf("stale expected 202, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressFreshnessStale) {
		t.Fatalf("stale expected %s, got %v", ReasonIngressFreshnessStale, resp["reason_code"])
	}
}

func TestIngressPlane_Integration_StepUpViaHTTP(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	spiffe := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	now := time.Now().UTC()

	payload := map[string]any{
		"envelope": map[string]any{
			"run_id":          "run-integ-stepup",
			"session_id":      "session-integ-stepup",
			"tenant":          "tenant-a",
			"actor_spiffe_id": spiffe,
			"plane":           "ingress",
		},
		"policy": map[string]any{
			"envelope": map[string]any{
				"run_id":          "run-integ-stepup",
				"session_id":      "session-integ-stepup",
				"tenant":          "tenant-a",
				"actor_spiffe_id": spiffe,
				"plane":           "ingress",
			},
			"action":   "ingress.admit",
			"resource": "ingress/event",
			"attributes": map[string]any{
				"connector_type":   "webhook",
				"source_id":        "connector-integ-stepup",
				"source_principal": spiffe,
				"event_id":         "evt-stepup-integ",
				"nonce":            "nonce-stepup-integ",
				"event_timestamp":  now.Format(time.RFC3339),
				"payload":          map[string]any{"data": "stepup-test"},
				"requires_step_up": true,
			},
		},
	}

	code, resp := postGatewayJSON(t, h, http.MethodPost, "/v1/ingress/submit", payload)
	if code != http.StatusAccepted {
		t.Fatalf("step-up expected 202, got %d body=%v", code, resp)
	}
	if got, _ := resp["reason_code"].(string); got != string(ReasonIngressStepUpRequired) {
		t.Fatalf("step-up expected %s, got %v", ReasonIngressStepUpRequired, resp["reason_code"])
	}
}
