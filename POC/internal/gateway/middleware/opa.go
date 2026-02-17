package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// OPAClient handles OPA policy evaluation
type OPAClient struct {
	endpoint string
	client   *http.Client
}

// NewOPAClient creates a new OPA client
func NewOPAClient(endpoint string) *OPAClient {
	return &OPAClient{
		endpoint: endpoint,
		client:   &http.Client{},
	}
}

// OPAInput represents input to OPA policy evaluation
type OPAInput struct {
	SPIFFEID    string                 `json:"spiffe_id"`
	Tool        string                 `json:"tool"`
	Action      string                 `json:"action"`
	Method      string                 `json:"method"`
	Path        string                 `json:"path"`
	Params      map[string]interface{} `json:"params"`
	StepUpToken string                 `json:"step_up_token"`
	Session     SessionInput           `json:"session"`
	UI          *UIInput               `json:"ui,omitempty"` // RFA-j2d.7: MCP-UI fields for UI-aware policy evaluation
}

// SessionInput represents session data for OPA evaluation
type SessionInput struct {
	RiskScore       float64      `json:"risk_score"`
	PreviousActions []ToolAction `json:"previous_actions"`
}

// OPARequest represents OPA API request
type OPARequest struct {
	Input OPAInput `json:"input"`
}

// OPAResponse represents OPA API response
type OPAResponse struct {
	Result interface{} `json:"result"`
}

// Evaluate sends request to OPA and returns decision
func (oc *OPAClient) Evaluate(input OPAInput) (bool, string, error) {
	// Build OPA request
	opaReq := OPARequest{Input: input}
	reqBody, err := json.Marshal(opaReq)
	if err != nil {
		return false, "", fmt.Errorf("failed to marshal OPA request: %w", err)
	}

	// Send to OPA
	// Using path: /v1/data/mcp/allow (matches our policy structure)
	url := fmt.Sprintf("%s/v1/data/mcp/allow", oc.endpoint)
	resp, err := oc.client.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		// If OPA is unavailable, fail closed (deny)
		return false, "opa_unavailable", nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, "opa_error", nil
	}

	// Parse OPA response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "opa_parse_error", nil
	}

	var opaResp OPAResponse
	if err := json.Unmarshal(respBody, &opaResp); err != nil {
		return false, "opa_parse_error", nil
	}

	// Handle result - can be bool or struct with allow field
	allow := false
	reason := ""

	switch v := opaResp.Result.(type) {
	case bool:
		allow = v
	case map[string]interface{}:
		if allowVal, ok := v["allow"].(bool); ok {
			allow = allowVal
		}
		if reasonVal, ok := v["reason"].(string); ok {
			reason = reasonVal
		}
	}

	return allow, reason, nil
}

// OPAEvaluator interface for OPA policy evaluation
// Satisfied by both OPAClient (HTTP-based) and OPAEngine (embedded)
type OPAEvaluator interface {
	Evaluate(input OPAInput) (bool, string, error)
}

// ContextPolicyInput represents input to the OPA context injection policy (mcp.context)
// RFA-xwc: Step 7 of the mandatory validation pipeline (Section 10.15.1)
type ContextPolicyInput struct {
	Context     ContextInput        `json:"context"`
	Session     ContextSessionInput `json:"session"`
	StepUpToken string              `json:"step_up_token"` // Non-empty when step-up approval was obtained for sensitive content
}

// ContextInput represents the external context metadata for policy evaluation
type ContextInput struct {
	Source         string `json:"source"`         // "external" for fetched content
	Validated      bool   `json:"validated"`      // true if steps 1-6 passed
	Classification string `json:"classification"` // DLP classification result (e.g., "clean", "sensitive", "pii")
	Handle         string `json:"handle"`         // UUID content_ref handle
}

// ContextSessionInput represents session data for context policy evaluation
// Uses a map for flags so OPA can check input.session.flags["high_risk"]
type ContextSessionInput struct {
	Flags map[string]bool `json:"flags"`
}

// ContextPolicyEvaluator interface for context injection policy evaluation
// RFA-xwc: Separated from OPAEvaluator because input shape is different
type ContextPolicyEvaluator interface {
	EvaluateContextPolicy(input ContextPolicyInput) (bool, string, error)
}

// OPAPolicy middleware enforces OPA authorization
func OPAPolicy(next http.Handler, opa OPAEvaluator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.1: Create OTel span for step 6
		ctx, span := tracer.Start(r.Context(), "gateway.opa_policy",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 6),
				attribute.String("mcp.gateway.middleware", "opa_policy"),
			),
		)
		defer span.End()

		// Demo-only: allow the deterministic rate-limit proof endpoint to flow
		// through the chain. The endpoint itself enforces secure-by-default gating
		// (404 unless explicitly enabled in dev mode), so OPA should not block it.
		if r.URL.Path == "/__demo__/ratelimit" {
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "demo ratelimit passthrough"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Phase 3 plane entry points and OpenAI-compatible model egress are
		// governed by dedicated UASGS contracts, not MCP tool-grant policy.
		if strings.HasPrefix(r.URL.Path, "/v1/") ||
			r.URL.Path == "/tools/invoke" ||
			r.URL.Path == "/openclaw/ws" ||
			strings.HasPrefix(r.URL.Path, "/openai/v1/") ||
			r.URL.Path == "/admin" ||
			strings.HasPrefix(r.URL.Path, "/admin/") {
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "phase3 model/plane/admin passthrough"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Extract tool name and params from request body
		body := GetRequestBody(ctx)
		toolName := ""
		params := make(map[string]interface{})
		var parsed *ParsedMCPRequest
		if len(body) > 0 {
			if p, err := ParseMCPRequestBody(body); err == nil {
				parsed = p
				if tn, err := parsed.EffectiveToolName(); err == nil {
					toolName = tn
				}
				params = parsed.EffectiveToolParams()
			}
		}

		// RFA-6fse.2: MCP protocol methods are not "tools" and should not be
		// denied by tool-grant policy. UI methods are governed by dedicated
		// MCP-UI controls in the gateway handler (request-side gating + response-side
		// processors). We bypass OPA for:
		//   - tools/list (required MCP protocol method)
		//   - resources/read ONLY when ui:// (governed by UI capability gating)
		if parsed != nil {
			if parsed.IsToolsList() {
				span.SetAttributes(
					attribute.String("mcp.result", "allowed"),
					attribute.String("mcp.reason", "protocol method passthrough"),
				)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			if parsed.IsResourcesRead() {
				uri, _ := parsed.Params["uri"].(string)
				if strings.HasPrefix(uri, "ui://") {
					span.SetAttributes(
						attribute.String("mcp.result", "allowed"),
						attribute.String("mcp.reason", "ui:// resources/read passthrough (UI-gated)"),
					)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		// Extract step-up token from headers
		stepUpToken := r.Header.Get("X-Step-Up-Token")

		// Get session data if available
		sessionData := GetSessionContextData(ctx)
		sessionInput := SessionInput{
			RiskScore:       0.0,
			PreviousActions: make([]ToolAction, 0),
		}
		if sessionData != nil {
			sessionInput.RiskScore = sessionData.RiskScore
			sessionInput.PreviousActions = sessionData.Actions
		}

		// Build OPA input
		input := OPAInput{
			SPIFFEID:    GetSPIFFEID(ctx),
			Tool:        toolName,
			Action:      "execute",
			Method:      r.Method,
			Path:        r.URL.Path,
			Params:      params,
			StepUpToken: stepUpToken,
			Session:     sessionInput,
		}

		// RFA-j2d.7: Populate UI section from request context when MCP-UI is relevant.
		// The UI context values are set by upstream middleware or the gateway handler
		// (e.g., from X-UI-Call-Origin header, session state, or gateway config).
		if GetUIEnabled(ctx) {
			uiInput := BuildUIInput(
				true,
				GetUIResourceURI(ctx),
				"", // content hash populated by resource controls (RFA-j2d.2)
				GetUICallOrigin(ctx),
				GetUIAppToolCalls(ctx),
				false, // resource registered status from registry (RFA-j2d.5)
				GetToolHashVerified(ctx),
			)
			input.UI = &uiInput
		}

		// Evaluate policy
		allowed, reason, err := opa.Evaluate(input)
		if err != nil {
			span.SetAttributes(
				attribute.String("mcp.result", "error"),
				attribute.String("mcp.reason", err.Error()),
			)
			WriteGatewayError(w, r.WithContext(ctx), http.StatusInternalServerError, GatewayError{
				Code:           "authz_evaluation_error",
				Message:        fmt.Sprintf("Policy evaluation failed: %v", err),
				Middleware:     "opa_policy",
				MiddlewareStep: 6,
			})
			return
		}

		// RFA-m6j.1: Record decision outcome on the span
		if allowed {
			span.SetAttributes(attribute.String("mcp.result", "allowed"))
		} else {
			span.SetAttributes(attribute.String("mcp.result", "denied"))
		}
		span.SetAttributes(attribute.String("mcp.reason", reason))

		// Store OPA decision ID in context for audit (RFA-qq0.13)
		// Use the decision ID from context (same as request decision ID for now)
		opaDecisionID := GetDecisionID(ctx)
		ctx = WithOPADecisionID(ctx, opaDecisionID)

		if !allowed {
			WriteGatewayError(w, r.WithContext(ctx), http.StatusForbidden, GatewayError{
				Code:           ErrAuthzPolicyDenied,
				Message:        fmt.Sprintf("Policy denied: %s", reason),
				Middleware:     "opa_policy",
				MiddlewareStep: 6,
				Details:        map[string]any{"reason": reason},
				Remediation:    "Check that the SPIFFE ID has a grant for the requested tool and path.",
			})
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
