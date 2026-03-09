package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
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

// PrincipalInput represents the principal authority metadata for OPA policy evaluation.
// OC-3ch6: Enables level-based access control for destructive operations, data export,
// inter-agent messaging, and anonymous access.
type PrincipalInput struct {
	Level        int      `json:"level"`
	Role         string   `json:"role"`
	Capabilities []string `json:"capabilities"`
}

// DataSourceInput represents data source metadata for OPA policy evaluation.
// OC-4zrf: Enables identity-based access control for registered data sources,
// mutable source admin gating, and high-risk session blocking for unregistered URIs.
type DataSourceInput struct {
	URI            string `json:"uri"`
	Registered     bool   `json:"registered"`
	MutablePolicy  string `json:"mutable_policy"`
	ContentChanged bool   `json:"content_changed"`
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
	UI          *UIInput               `json:"ui,omitempty"`         // RFA-j2d.7: MCP-UI fields for UI-aware policy evaluation
	Principal   *PrincipalInput        `json:"principal,omitempty"`  // OC-3ch6: principal authority for level-based access control
	DataSource  *DataSourceInput       `json:"data_source,omitempty"` // OC-4zrf: data source access control
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

		// OPA bypasses are contract-driven. Every bypassed route class must
		// declare compensating checks in opa_bypass_contracts.go.
		if contract, ok := MatchOPABypassContract(r); ok {
			reason := strings.TrimSpace(contract.PassthroughReason)
			if reason == "" {
				reason = "opa bypass contract passthrough"
			}
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", reason),
				attribute.String("mcp.contract_id", contract.ID),
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

		// OC-66bi: Derive Action from request semantics instead of hardcoding "execute".
		// Priority: (1) explicit params["action"], (2) keyword from tool name, (3) fallback "execute".
		action := deriveAction(toolName, params)

		// Build OPA input
		input := OPAInput{
			SPIFFEID:    GetSPIFFEID(ctx),
			Tool:        toolName,
			Action:      action,
			Method:      r.Method,
			Path:        r.URL.Path,
			Params:      params,
			StepUpToken: stepUpToken,
			Session:     sessionInput,
		}

		// OC-3ch6: Populate principal from request context for level-based access control
		if role := GetPrincipalRole(ctx); role.Role != "" {
			input.Principal = &PrincipalInput{
				Level:        role.Level,
				Role:         role.Role,
				Capabilities: role.Capabilities,
			}
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
			// Record OPA denial metric
			if gwMetrics != nil {
				gwMetrics.DenialTotal.Add(ctx, 1,
					metric.WithAttributes(
						attribute.String("middleware", "opa"),
						attribute.String("reason", reason),
						attribute.String("spiffe_id", GetSPIFFEID(ctx)),
					),
				)
			}
			// OC-3ch6: Use specific error code when OPA denies due to principal level
			errorCode := ErrAuthzPolicyDenied
			remediation := "Check that the SPIFFE ID has a grant for the requested tool and path."
			if reason == "principal_level_insufficient" {
				errorCode = ErrPrincipalLevelInsufficient
				remediation = "The principal's authority level is insufficient for this operation. A higher-privilege identity is required."
			}

			WriteGatewayError(w, r.WithContext(ctx), http.StatusForbidden, GatewayError{
				Code:           errorCode,
				Message:        fmt.Sprintf("Policy denied: %s", reason),
				Middleware:     "opa_policy",
				MiddlewareStep: 6,
				Details:        map[string]any{"reason": reason},
				Remediation:    remediation,
			})
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isWebSocketUpgradeRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket")
}

// toolNamePatterns maps substrings found in tool names to the canonical OPA action
// keyword that triggers the corresponding is_*_action rule. The value must be one
// of the keywords recognized by the OPA policy (is_destructive_action,
// is_data_export_action, is_messaging_action).
//
// Patterns include both the exact policy keywords AND common morphological
// variants (e.g., "messaging" -> "message") so that tool names like
// "messaging_send" correctly derive an action that fires the policy rule.
var toolNamePatterns = []struct {
	pattern string // substring to match in lowered tool name
	action  string // canonical OPA action keyword to return
}{
	// destructive
	{"delete", "delete"}, {"rm", "rm"}, {"remove", "remove"}, {"drop", "drop"},
	{"reset", "reset"}, {"wipe", "wipe"}, {"shutdown", "shutdown"},
	{"terminate", "terminate"}, {"revoke", "revoke"}, {"purge", "purge"}, {"destroy", "destroy"},
	// data export
	{"export", "export"}, {"dump", "dump"}, {"backup", "backup"},
	{"extract", "extract"}, {"exfil", "exfil"},
	// messaging (includes morphological variants; longer patterns first to avoid premature match)
	{"messaging", "message"}, {"message", "message"},
	{"broadcast", "broadcast"},
	{"notification", "notify"}, {"notify", "notify"},
	{"send_agent", "send_agent"}, {"agent_invoke", "agent_invoke"},
}

// deriveAction determines the OPA input.action from request semantics.
// OC-66bi: Replaces the hardcoded "execute" value so principal-level rules fire.
//
// Priority:
//  1. Explicit params["action"] string value
//  2. First matching pattern found in the tool name (maps to canonical keyword)
//  3. Fallback to "execute" (backward compatible)
func deriveAction(toolName string, params map[string]interface{}) string {
	// (1) Check explicit params["action"]
	if actionVal, ok := params["action"]; ok {
		if s, ok := actionVal.(string); ok && s != "" {
			return s
		}
	}

	// (2) Check tool name for known patterns
	lower := strings.ToLower(toolName)
	for _, p := range toolNamePatterns {
		if strings.Contains(lower, p.pattern) {
			return p.action
		}
	}

	// (3) Fallback
	return "execute"
}
