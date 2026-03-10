package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestV24AdminEndpointsEnforceSPIFFEAuth(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	req := httptest.NewRequest(http.MethodPost, "/admin/dlp/rulesets/create", bytes.NewBufferString(`{"ruleset_id":"rs-auth"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, rec.Body.String())
	}
	if got := stringField(body["code"]); got != middleware.ErrAuthMissingIdentity {
		t.Fatalf("expected code=%q, got %q body=%v", middleware.ErrAuthMissingIdentity, got, body)
	}
	if got := stringField(body["middleware"]); got != "spiffe_auth" {
		t.Fatalf("expected middleware=spiffe_auth, got %q body=%v", got, body)
	}
}

func TestV24ConnectorErrorsUseUnifiedGatewayEnvelope(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/connectors/status", nil)
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, rec.Body.String())
	}
	if got := stringField(body["code"]); got != middleware.ErrContractValidationFailed {
		t.Fatalf("expected code=%q, got %q body=%v", middleware.ErrContractValidationFailed, got, body)
	}
	if got := stringField(body["middleware"]); got != v24MiddlewareConnectorAuth {
		t.Fatalf("expected middleware=%q, got %q body=%v", v24MiddlewareConnectorAuth, got, body)
	}
	if got := intField(body["middleware_step"]); got != v24MiddlewareStep {
		t.Fatalf("expected middleware_step=%d, got %d body=%v", v24MiddlewareStep, got, body)
	}
	if stringField(body["decision_id"]) == "" || stringField(body["trace_id"]) == "" {
		t.Fatalf("expected decision_id/trace_id in envelope: %v", body)
	}
}

func TestV24RuleOpsErrorsUseUnifiedGatewayEnvelope(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	req := httptest.NewRequest(http.MethodPost, "/admin/dlp/rulesets/create", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, rec.Body.String())
	}
	if got := stringField(body["code"]); got != middleware.ErrMCPInvalidRequest {
		t.Fatalf("expected code=%q, got %q body=%v", middleware.ErrMCPInvalidRequest, got, body)
	}
	if got := stringField(body["middleware"]); got != v24MiddlewareRuleOpsAdmin {
		t.Fatalf("expected middleware=%q, got %q body=%v", v24MiddlewareRuleOpsAdmin, got, body)
	}
}

func TestV24ProxySpanAttributesForEndpointEntries(t *testing.T) {
	exporter, teardown := setupTracerAndPropagator(t)
	defer teardown()

	gw, _ := newPhase3TestGateway(t)
	gw.rateLimiter = middleware.NewRateLimiter(100000, 100000, middleware.NewInMemoryRateLimitStore())
	h := gw.Handler()

	req1 := httptest.NewRequest(http.MethodGet, "/v1/connectors/report", nil)
	req1.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("connectors/report expected 200, got %d body=%s", rec1.Code, rec1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/admin/dlp/rulesets/active", nil)
	req2.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("ruleops/active expected 200, got %d body=%s", rec2.Code, rec2.Body.String())
	}

	spans := exporter.GetSpans()
	connectorSpan := findGatewayProxySpanByEndpoint(spans, "/v1/connectors/report")
	if connectorSpan == nil {
		t.Fatalf("missing gateway.proxy span for connectors/report; spans=%d", len(spans))
	}
	if got, ok := spanAttrString(connectorSpan.Attributes, "mcp.gateway.middleware"); !ok || got != v24MiddlewareConnectorAuth {
		t.Fatalf("expected mcp.gateway.middleware=%q on connector span, got %q (ok=%v)", v24MiddlewareConnectorAuth, got, ok)
	}
	if got, ok := spanAttrInt(connectorSpan.Attributes, "mcp.gateway.step"); !ok || got != v24MiddlewareStep {
		t.Fatalf("expected mcp.gateway.step=%d on connector span, got %d (ok=%v)", v24MiddlewareStep, got, ok)
	}

	adminSpan := findGatewayProxySpanByEndpoint(spans, "/admin/dlp/rulesets/active")
	if adminSpan == nil {
		t.Fatalf("missing gateway.proxy span for admin/ruleops active; spans=%d", len(spans))
	}
	if got, ok := spanAttrString(adminSpan.Attributes, "mcp.gateway.middleware"); !ok || got != v24MiddlewareRuleOpsAdmin {
		t.Fatalf("expected mcp.gateway.middleware=%q on admin span, got %q (ok=%v)", v24MiddlewareRuleOpsAdmin, got, ok)
	}
	if got, ok := spanAttrString(adminSpan.Attributes, "mcp.reason"); !ok || got != "v24_admin_entry" {
		t.Fatalf("expected mcp.reason=v24_admin_entry on admin span, got %q (ok=%v)", got, ok)
	}
}

func intField(v any) int {
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	default:
		return 0
	}
}

func stringField(v any) string {
	s, _ := v.(string)
	return s
}

func findGatewayProxySpanByEndpoint(spans tracetest.SpanStubs, endpoint string) *tracetest.SpanStub {
	for i := len(spans) - 1; i >= 0; i-- {
		s := spans[i]
		if s.Name != "gateway.proxy" {
			continue
		}
		if got, ok := spanAttrString(s.Attributes, "mcp.v24.endpoint"); ok && got == endpoint {
			return &spans[i]
		}
	}
	return nil
}

func spanAttrString(attrs []attribute.KeyValue, key string) (string, bool) {
	for _, kv := range attrs {
		if string(kv.Key) == key {
			return kv.Value.AsString(), true
		}
	}
	return "", false
}

func spanAttrInt(attrs []attribute.KeyValue, key string) (int, bool) {
	for _, kv := range attrs {
		if string(kv.Key) == key {
			return int(kv.Value.AsInt64()), true
		}
	}
	return 0, false
}
