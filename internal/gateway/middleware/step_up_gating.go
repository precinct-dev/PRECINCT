// Step-Up Gating Middleware - RFA-qq0.17
// Implements synchronous step-up gating for high-risk tool calls (Section 7.7).
// Position in middleware chain: step 9 (after session context at step 8, before deep scan at step 10).
//
// Risk scoring rubric: 4 dimensions (Impact, Reversibility, Exposure, Novelty), 0-3 each, total 0-12.
// Gating thresholds:
//
//	0-3:   Fast path (no friction)
//	4-6:   Step-up gating (destination allowlist + guard model)
//	7-9:   Approval capability required
//	10-12: Deny by default (HTTP 403)
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"
)

// RiskDimension represents a single dimension of the risk scoring rubric
type RiskDimension struct {
	Impact        int `json:"impact"`        // 0-3: cosmetic/read-only to financial/legal/irreversible
	Reversibility int `json:"reversibility"` // 0-3: fully reversible to irreversible
	Exposure      int `json:"exposure"`      // 0-3: no data to external egress/PII/secrets
	Novelty       int `json:"novelty"`       // 0-3: known tool+dest to unknown/unvalidated
}

// Total returns the sum of all dimensions (0-12)
func (rd RiskDimension) Total() int {
	return rd.Impact + rd.Reversibility + rd.Exposure + rd.Novelty
}

// RiskThresholds holds configurable gating thresholds
type RiskThresholds struct {
	FastPathMax int `yaml:"fast_path_max"` // scores <= this are fast path
	StepUpMax   int `yaml:"step_up_max"`   // scores <= this get step-up
	ApprovalMax int `yaml:"approval_max"`  // scores <= this need approval
}

// GuardThresholds holds guard model probability thresholds
type GuardThresholds struct {
	InjectionThreshold float64 `yaml:"injection_threshold"`
	JailbreakThreshold float64 `yaml:"jailbreak_threshold"`
}

// UnknownToolDefaults holds default risk scores for tools not in the registry
type UnknownToolDefaults struct {
	Impact        int `yaml:"impact"`
	Reversibility int `yaml:"reversibility"`
	Exposure      int `yaml:"exposure"`
	Novelty       int `yaml:"novelty"`
}

// DLPPolicy holds the per-category block/flag policy for the DLP regex scanner.
// Valid values for each field: "block" or "flag".
// "block" returns HTTP 403 immediately; "flag" adds to safezone_flags and continues.
type DLPPolicy struct {
	Credentials string `yaml:"credentials"` // "block" (default) or "flag"
	Injection   string `yaml:"injection"`   // "block" or "flag" (default)
	PII         string `yaml:"pii"`         // "block" or "flag" (default)
}

// DefaultDLPPolicy returns the default DLP policy matching historical behavior:
// credentials=block, injection=flag, pii=flag.
func DefaultDLPPolicy() DLPPolicy {
	return DLPPolicy{
		Credentials: "block",
		Injection:   "flag",
		PII:         "flag",
	}
}

// Normalize ensures all fields have valid values, defaulting to the historical
// behavior if a field is empty or invalid.
func (p *DLPPolicy) Normalize() {
	if p.Credentials != "block" && p.Credentials != "flag" {
		p.Credentials = "block"
	}
	if p.Injection != "block" && p.Injection != "flag" {
		p.Injection = "flag"
	}
	if p.PII != "block" && p.PII != "flag" {
		p.PII = "flag"
	}
}

// RiskConfig holds the complete risk configuration loaded from YAML
type RiskConfig struct {
	Thresholds          RiskThresholds      `yaml:"thresholds"`
	Guard               GuardThresholds     `yaml:"guard"`
	UnknownToolDefaults UnknownToolDefaults `yaml:"unknown_tool_defaults"`
	DLP                 DLPPolicy           `yaml:"dlp"`
}

// DestinationAllowlist holds the set of allowed destinations
type DestinationAllowlist struct {
	Allowed []string `yaml:"allowed_destinations"`
}

// StepUpGatingResult represents the outcome of step-up gating evaluation
type StepUpGatingResult struct {
	Allowed     bool          `json:"allowed"`
	RiskScore   RiskDimension `json:"risk_score"`
	TotalScore  int           `json:"total_score"`
	Gate        string        `json:"gate"`   // "fast_path", "step_up", "approval", "deny"
	Reason      string        `json:"reason"` // human-readable reason for the decision
	GuardResult *GuardResult  `json:"guard_result,omitempty"`
}

// GuardResult holds the result from the guard model check
type GuardResult struct {
	InjectionProb float64 `json:"injection_probability"`
	JailbreakProb float64 `json:"jailbreak_probability"`
	Blocked       bool    `json:"blocked"`
	Error         string  `json:"error,omitempty"`
}

const openAICompatChatCompletionsPath = "/openai/v1/chat/completions"
const openAICompatResponsesPath = "/openai/v1/responses"
const anthropicMessagesPath = "/v1/messages"
const openClawResponsesPath = "/v1/responses"

// GuardModelClient is the interface for calling the guard model
type GuardModelClient interface {
	ClassifyContent(ctx context.Context, content string) (*GuardResult, error)
}

// GroqGuardClient is an alias for backward compatibility
type GroqGuardClient = GuardModelClient

// GroqGuardHTTPClient implements GuardModelClient using any OpenAI-compatible API
type GroqGuardHTTPClient struct {
	apiKey     string
	baseURL    string
	modelName  string
	httpClient *http.Client
}

// NewGroqGuardClient creates a new guard model client with the given endpoint and model name.
// Both baseURL and modelName are configurable to support any OpenAI-compatible provider.
func NewGroqGuardClient(apiKey string, timeout time.Duration, opts ...func(*GroqGuardHTTPClient)) *GroqGuardHTTPClient {
	c := &GroqGuardHTTPClient{
		apiKey:    apiKey,
		baseURL:   "https://api.groq.com/openai/v1",
		modelName: "meta-llama/llama-prompt-guard-2-86m",
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithGuardEndpoint sets the base URL for the guard model API
func WithGuardEndpoint(url string) func(*GroqGuardHTTPClient) {
	return func(c *GroqGuardHTTPClient) {
		if url != "" {
			c.baseURL = url
		}
	}
}

// WithGuardModelName sets the model name for classification requests
func WithGuardModelName(name string) func(*GroqGuardHTTPClient) {
	return func(c *GroqGuardHTTPClient) {
		if name != "" {
			c.modelName = name
		}
	}
}

// HasAPIKey returns true if the client has a configured API key
func (g *GroqGuardHTTPClient) HasAPIKey() bool {
	return g.apiKey != ""
}

// ClassifyContent calls Groq Prompt Guard 2 86M to classify content
func (g *GroqGuardHTTPClient) ClassifyContent(ctx context.Context, content string) (*GuardResult, error) {
	if g.apiKey == "" {
		return nil, fmt.Errorf("no Groq API key configured")
	}

	reqBody := map[string]interface{}{
		"model": g.modelName,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": content,
			},
		},
		"max_tokens":  10,
		"temperature": 0.0,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", g.baseURL+"/chat/completions", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+g.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Groq API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("groq API returned status %d: %s", resp.StatusCode, string(body))
	}

	var groqResp GroqClassificationResponse
	if err := json.NewDecoder(resp.Body).Decode(&groqResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(groqResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	scoreStr := groqResp.Choices[0].Message.Content
	var score float64
	if _, err := fmt.Sscanf(scoreStr, "%f", &score); err != nil {
		return nil, fmt.Errorf("failed to parse score from content %q: %w", scoreStr, err)
	}

	if score < 0.0 {
		score = 0.0
	} else if score > 1.0 {
		score = 1.0
	}

	return &GuardResult{
		InjectionProb: score,
		JailbreakProb: score,
		Blocked:       false, // caller determines blocking based on thresholds
	}, nil
}

// LoadRiskConfig loads risk configuration from YAML file
func LoadRiskConfig(path string) (*RiskConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read risk config: %w", err)
	}

	var config RiskConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse risk config: %w", err)
	}

	// RFA-sd7: Normalize DLP policy so missing/invalid values get safe defaults.
	config.DLP.Normalize()

	return &config, nil
}

// DefaultRiskConfig returns the default risk configuration
func DefaultRiskConfig() *RiskConfig {
	return &RiskConfig{
		Thresholds: RiskThresholds{
			FastPathMax: 3,
			StepUpMax:   6,
			ApprovalMax: 9,
		},
		Guard: GuardThresholds{
			InjectionThreshold: 0.30,
			JailbreakThreshold: 0.30,
		},
		UnknownToolDefaults: UnknownToolDefaults{
			Impact:        2,
			Reversibility: 2,
			Exposure:      2,
			Novelty:       3,
		},
		DLP: DefaultDLPPolicy(),
	}
}

// LoadDestinationAllowlist loads destination allowlist from YAML file
func LoadDestinationAllowlist(path string) (*DestinationAllowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read destinations config: %w", err)
	}

	var allowlist DestinationAllowlist
	if err := yaml.Unmarshal(data, &allowlist); err != nil {
		return nil, fmt.Errorf("failed to parse destinations config: %w", err)
	}

	return &allowlist, nil
}

// DefaultDestinationAllowlist returns an empty allowlist (blocks all destinations by default)
func DefaultDestinationAllowlist() *DestinationAllowlist {
	return &DestinationAllowlist{
		Allowed: []string{
			"localhost",
			"127.0.0.1",
			"host.docker.internal",
		},
	}
}

// IsAllowed checks if a destination is on the allowlist
// Supports exact match and wildcard prefix (e.g., "*.tavily.com")
func (dal *DestinationAllowlist) IsAllowed(destination string) bool {
	if destination == "" {
		// No destination means internal call, always allowed
		return true
	}

	dest := strings.ToLower(strings.TrimSpace(destination))
	for _, pattern := range dal.Allowed {
		p := strings.ToLower(strings.TrimSpace(pattern))
		if p == dest {
			return true
		}
		// Wildcard match: "*.example.com" matches "sub.example.com"
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".example.com"
			if strings.HasSuffix(dest, suffix) {
				return true
			}
		}
	}
	return false
}

// ComputeRiskScore computes the 4-dimensional risk score for a tool call.
//
// OC-h4m7: accepts optional reversibility override and principal level for
// automatic step-up escalation of irreversible actions. When rev is non-nil
// and rev.Score >= 2, the Reversibility dimension is overridden. When
// rev.Score == 3 (irreversible) and principalLevel > 1 (non-owner), the
// total score is forced into the approval range (>= 7). When rev.Score == 3
// and the session's EscalationScore exceeds EscalationWarningThreshold, the
// total is forced into the deny range (>= 10).
//
// OC-d77k: Also checks session.EscalationScore against Critical (25) and
// Emergency (40) thresholds. At Critical: +3 to Impact dimension (fast_path
// actions become step_up, step_up becomes approval). At Emergency: all
// dimensions set to max (3), forcing deny gate for ALL actions.
func ComputeRiskScore(
	toolDef *ToolDefinition,
	session *AgentSession,
	destination string,
	isExternal bool,
	registry *ToolRegistry,
	allowlist *DestinationAllowlist,
	defaults UnknownToolDefaults,
	opts ...RiskScoreOption,
) RiskDimension {

	// Apply options
	var rso riskScoreOptions
	for _, o := range opts {
		o(&rso)
	}

	// If tool is unknown, use defaults with max novelty
	if toolDef == nil {
		rd := RiskDimension(defaults)
		applyReversibilityOverrides(&rd, session, &rso)
		applyEscalationOverrides(&rd, session)
		return rd
	}

	// --- Impact dimension (0-3) ---
	impact := computeImpact(toolDef)

	// --- Reversibility dimension (0-3) ---
	reversibility := computeReversibility(toolDef)

	// --- Exposure dimension (0-3) ---
	exposure := computeExposure(toolDef, isExternal, session)

	// --- Novelty dimension (0-3) ---
	novelty := computeNovelty(toolDef, destination, allowlist)

	rd := RiskDimension{
		Impact:        impact,
		Reversibility: reversibility,
		Exposure:      exposure,
		Novelty:       novelty,
	}

	// OC-h4m7: Apply reversibility-aware overrides
	applyReversibilityOverrides(&rd, session, &rso)

	// OC-d77k: Apply escalation-based overrides
	applyEscalationOverrides(&rd, session)

	return rd
}

// applyEscalationOverrides applies OC-d77k escalation-based gate elevation.
//
// At Emergency (>= 40): all dimensions are set to 3, forcing total=12 (deny gate).
// At Critical (>= 25): +3 is added to Impact (capped at 3), elevating the gate
// by one or more bands.
func applyEscalationOverrides(rd *RiskDimension, session *AgentSession) {
	if session == nil {
		return
	}

	if session.EscalationScore >= EscalationEmergencyThreshold {
		rd.Impact = 3
		rd.Reversibility = 3
		rd.Exposure = 3
		rd.Novelty = 3
		return
	}

	if session.EscalationScore >= EscalationCriticalThreshold {
		rd.Impact += 3
		if rd.Impact > 3 {
			rd.Impact = 3
		}
	}
}

// RiskScoreOption is a functional option for ComputeRiskScore (OC-h4m7).
type RiskScoreOption func(*riskScoreOptions)

type riskScoreOptions struct {
	reversibility  *ActionReversibility
	principalLevel int // 0=system, 1=owner, 2=operator, 3=agent, 4=external
}

// WithReversibility injects a pre-computed reversibility classification into risk scoring.
func WithReversibility(rev ActionReversibility) RiskScoreOption {
	return func(o *riskScoreOptions) {
		o.reversibility = &rev
	}
}

// WithPrincipalLevelOption injects the principal trust level into risk scoring.
func WithPrincipalLevelOption(level int) RiskScoreOption {
	return func(o *riskScoreOptions) {
		o.principalLevel = level
	}
}

// applyReversibilityOverrides applies OC-h4m7 reversibility-aware gate escalation.
func applyReversibilityOverrides(rd *RiskDimension, session *AgentSession, opts *riskScoreOptions) {
	if opts.reversibility == nil {
		return
	}
	rev := opts.reversibility

	// Override Reversibility dimension when classifier score exceeds current value
	if rev.Score >= 2 && rev.Score > rd.Reversibility {
		rd.Reversibility = rev.Score
	}

	// Force approval gate for irreversible actions by non-owners (Level > 1)
	if rev.Score == 3 && opts.principalLevel > 1 {
		forceMinTotal(rd, 7)
	}

	// Force deny gate for irreversible actions in escalated sessions
	if rev.Score == 3 && session != nil && session.EscalationScore > EscalationWarningThreshold {
		forceMinTotal(rd, 10)
	}
}

// forceMinTotal raises the total risk score to at least minTotal by incrementing
// dimensions in priority order: Impact, then Exposure, then Novelty. Each
// dimension is capped at 3 (the maximum per-dimension value).
func forceMinTotal(rd *RiskDimension, minTotal int) {
	dims := []*int{&rd.Impact, &rd.Exposure, &rd.Novelty}
	for _, dim := range dims {
		for rd.Total() < minTotal && *dim < 3 {
			*dim++
		}
		if rd.Total() >= minTotal {
			return
		}
	}
}

// computeImpact determines the impact score based on tool metadata
func computeImpact(toolDef *ToolDefinition) int {
	switch toolDef.RiskLevel {
	case "critical":
		return 3 // Financial / legal / irreversible
	case "high":
		return 2 // User-visible change
	case "medium":
		return 1 // Minor internal change
	case "low":
		return 0 // Cosmetic / read-only
	default:
		return 2 // Unknown risk level defaults to medium-high
	}
}

// computeReversibility determines reversibility score
func computeReversibility(toolDef *ToolDefinition) int {
	switch toolDef.RiskLevel {
	case "critical":
		return 3 // Irreversible or costly to undo
	case "high":
		return 2 // Partially reversible
	case "medium":
		return 1 // Mostly reversible
	case "low":
		return 0 // Fully reversible
	default:
		return 2
	}
}

// computeExposure determines exposure score based on tool, external target, and session context
func computeExposure(toolDef *ToolDefinition, isExternal bool, session *AgentSession) int {
	score := 0

	// External egress = higher exposure
	if isExternal {
		score = 2 // Sensitive data category
	}

	// Check session context for data classifications
	if session != nil {
		for _, class := range session.DataClassifications {
			if class == "sensitive" {
				if isExternal {
					score = 3 // External egress + PII/secrets
				} else {
					score = 2
				}
				break
			}
		}
	}

	// Critical tools always have elevated exposure
	if toolDef.RiskLevel == "critical" {
		if score < 2 {
			score = 2
		}
	}

	return score
}

// computeNovelty determines novelty score based on tool+destination combination
func computeNovelty(toolDef *ToolDefinition, destination string, allowlist *DestinationAllowlist) int {
	if destination == "" {
		// Known tool, no destination -> score 0
		return 0
	}

	// Check if destination is in tool's allowed destinations
	for _, allowed := range toolDef.AllowedDestinations {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		dest := strings.ToLower(strings.TrimSpace(destination))
		if allowed == dest {
			return 0 // Known tool + known destination
		}
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:]
			if strings.HasSuffix(dest, suffix) {
				return 0
			}
		}
	}

	// Destination is not in tool's allowed list
	// Check global allowlist
	if allowlist.IsAllowed(destination) {
		return 1 // Known tool, new-ish destination (on global allowlist)
	}

	return 2 // Known tool, unknown destination
}

// DetermineGate returns the gate name based on total risk score and thresholds
func DetermineGate(totalScore int, thresholds RiskThresholds) string {
	switch {
	case totalScore <= thresholds.FastPathMax:
		return "fast_path"
	case totalScore <= thresholds.StepUpMax:
		return "step_up"
	case totalScore <= thresholds.ApprovalMax:
		return "approval"
	default:
		return "deny"
	}
}

// Context key for step-up gating result
const contextKeyStepUpResult contextKey = "step_up_gating_result"

// WithStepUpResult adds step-up gating result to context
func WithStepUpResult(ctx context.Context, result *StepUpGatingResult) context.Context {
	return context.WithValue(ctx, contextKeyStepUpResult, result)
}

// GetStepUpResult retrieves step-up gating result from context
func GetStepUpResult(ctx context.Context) *StepUpGatingResult {
	if v := ctx.Value(contextKeyStepUpResult); v != nil {
		return v.(*StepUpGatingResult)
	}
	return nil
}

// StepUpGating creates the step-up gating middleware
// Position: Step 9 in the middleware chain (after session context, before deep scan)
//
// Parameters:
//   - next: the next handler in the chain
//   - guardClient: Groq guard model client (may be nil if no API key)
//   - allowlist: destination allowlist
//   - riskConfig: risk scoring thresholds and defaults
//   - registry: tool registry for looking up tool metadata
//   - auditor: auditor for logging step-up decisions
func StepUpGating(
	next http.Handler,
	guardClient GroqGuardClient,
	allowlist *DestinationAllowlist,
	riskConfig *RiskConfig,
	registry *ToolRegistry,
	auditor *Auditor,
	approvalVerifier ...ApprovalCapabilityVerifier,
) http.Handler {
	var verifier ApprovalCapabilityVerifier
	if len(approvalVerifier) > 0 {
		verifier = approvalVerifier[0]
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.2: Create OTel span for step 9
		ctx, span := tracer.Start(r.Context(), "gateway.step_up_gating",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 9),
				attribute.String("mcp.gateway.middleware", "step_up_gating"),
			),
		)
		defer span.End()

		// Parse tool call from request body
		body := GetRequestBody(ctx)
		if len(body) == 0 {
			// No body, pass through (fast path)
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "no body"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// OpenAI-compatible model route: require step-up approval capability for
		// explicit high-risk model operations.
		if requiresModelApproval(r, body) {
			model := extractModelName(body)
			if model == "" {
				model = "unknown-model"
			}
			scope := ApprovalScope{
				Action:        "model.call",
				Resource:      model,
				ActorSPIFFEID: GetSPIFFEID(ctx),
				SessionID:     expectedApprovalSessionID(r, ctx),
			}
			result := &StepUpGatingResult{
				Allowed:    false,
				TotalScore: riskConfig.Thresholds.ApprovalMax,
				Gate:       "approval",
				Reason:     "human approval required",
			}
			token := strings.TrimSpace(r.Header.Get("X-Step-Up-Token"))
			if token == "" {
				result.Reason = "human approval required"
			} else if verifier == nil {
				result.Reason = "approval capability verifier unavailable"
			} else {
				claims, err := verifier.ValidateAndConsume(token, scope)
				if err != nil {
					result.Reason = approvalFailureReason(err)
				} else {
					result.Allowed = true
					result.Reason = "step-up approval capability validated"
					r.Header.Set("X-Step-Up-Approved", "true")
					if claims != nil {
						r.Header.Set("X-Approval-Marker", claims.RequestID)
					}
				}
			}

			span.SetAttributes(
				attribute.String("gate", result.Gate),
				attribute.Int("total_score", result.TotalScore),
				attribute.String("guard_result", ""),
				attribute.String("mcp.stepup.action", scope.Action),
				attribute.String("mcp.stepup.resource", scope.Resource),
			)
			if result.Allowed {
				span.SetAttributes(
					attribute.String("mcp.result", "allowed"),
					attribute.String("mcp.reason", result.Reason),
				)
			} else {
				span.SetAttributes(
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", result.Reason),
				)
			}

			ctx = WithStepUpResult(ctx, result)
			if auditor != nil {
				auditor.Log(AuditEvent{
					SessionID:  GetSessionID(ctx),
					DecisionID: GetDecisionID(ctx),
					TraceID:    GetTraceID(ctx),
					SPIFFEID:   GetSPIFFEID(ctx),
					Action:     "step_up_gating",
					Result:     fmt.Sprintf("gate=%s allowed=%v total_score=%d action=model.call resource=%s reason=%s", result.Gate, result.Allowed, result.TotalScore, scope.Resource, result.Reason),
					Method:     r.Method,
					Path:       r.URL.Path,
				})
			}

			if !result.Allowed {
				errCode := ErrStepUpApprovalRequired
				if token != "" && verifier != nil {
					errCode = ErrStepUpDenied
				}
				WriteGatewayError(w, r.WithContext(ctx), http.StatusForbidden, GatewayError{
					Code:           errCode,
					Message:        result.Reason,
					Middleware:     "step_up_gating",
					MiddlewareStep: 9,
					Details: map[string]any{
						"gate":       result.Gate,
						"risk_score": result.TotalScore,
						"action":     scope.Action,
						"resource":   scope.Resource,
					},
					Remediation: "Obtain a valid approval capability token for this high-risk model operation.",
				})
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		parsed, err := ParseMCPRequestBody(body)
		if err != nil {
			// Not a valid MCP request, pass through
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "not MCP request"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// RFA-6fse.2: MCP protocol methods must not be risk-scored as "unknown tools".
		// Otherwise they hit unknown_tool_defaults (total=9) and are blocked at the
		// approval gate. Protocol methods include tools/list, resources/read, prompts/*,
		// ping, initialize, and notifications/*.
		//
		// UI-specific resources/read (ui://) is governed by the gateway handler's
		// UI capability gating + response-side resource controls. We allow the
		// request to reach that logic by bypassing step-up gating for protocol methods.
		if parsed.IsNotification() ||
			parsed.IsToolsList() ||
			parsed.IsResourcesRead() ||
			parsed.IsResourcesList() ||
			parsed.IsPromptsList() ||
			parsed.IsPromptsGet() ||
			parsed.IsSamplingCreateMessage() ||
			parsed.IsInitialize() ||
			parsed.IsPing() {
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "protocol method passthrough"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		toolName, toolErr := parsed.EffectiveToolName()
		params := parsed.EffectiveToolParams()
		if toolErr != nil {
			// Malformed tools/call should be rejected by earlier middleware.
			// Step-up gating is fail-open here to avoid double-emitting different errors.
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "unable to extract effective tool name"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if toolName == "" {
			// No tool identified, pass through
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "no tool identified"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Look up tool definition
		var toolDef *ToolDefinition
		if def, exists := registry.GetToolDefinition(toolName); exists {
			toolDef = &def
		}

		// Determine if external target and destination
		isExternal, destination := isExternalTarget(toolName, params)

		// Also check params for explicit destination field
		if dest, ok := params["destination"].(string); ok && destination == "" {
			destination = dest
			if destination != "" {
				isExternal = true
			}
		}

		// Get session context (set by step 8)
		session := GetSessionContextData(ctx)

		// OC-h4m7: Classify reversibility from tool name, action, and params.
		// The tool name itself often encodes the action (e.g., "delete_resource"),
		// so we pass it as the action parameter for keyword matching.
		rev := ClassifyReversibility(toolName, toolName, params, toolDef)
		// OC-h4m7: Read principal level from the struct-based PrincipalRole set by
		// PrincipalHeaders middleware (OC-t7go). Fall back to the int-based key
		// (set by legacy or direct WithPrincipalLevel callers) so both paths work.
		principalLevel := GetPrincipalRole(ctx).Level
		if principalLevel == 0 {
			if l := GetPrincipalLevel(ctx); l != 0 {
				principalLevel = l
			}
		}

		// OC-h4m7: Inject X-Precinct-Reversibility header into proxied request
		// and response (so callers know the classification even on denials).
		r.Header.Set("X-Precinct-Reversibility", rev.Category)
		w.Header().Set("X-Precinct-Reversibility", rev.Category)
		if rev.RequiresBackup {
			// Advisory header: set on response for all requests with Score>=2.
			// X-Precinct-Backup-Recommended on the request is set later (only when allowed).
			w.Header().Set("X-Precinct-Backup-Recommended", "true")
		}

		// Compute risk score with reversibility-aware overrides
		riskScore := ComputeRiskScore(toolDef, session, destination, isExternal, registry, allowlist, riskConfig.UnknownToolDefaults,
			WithReversibility(rev),
			WithPrincipalLevelOption(principalLevel),
		)
		totalScore := riskScore.Total()

		// Determine which gate applies
		gate := DetermineGate(totalScore, riskConfig.Thresholds)

		result := &StepUpGatingResult{
			RiskScore:  riskScore,
			TotalScore: totalScore,
			Gate:       gate,
		}

		// Apply gate logic
		switch gate {
		case "fast_path":
			// No friction, proceed
			result.Allowed = true
			result.Reason = "low risk - fast path"

		case "step_up":
			// Step-up gating: destination check + guard model
			stepUpResult := applyStepUpControls(ctx, destination, body, allowlist, guardClient, riskConfig)
			result.Allowed = stepUpResult.Allowed
			result.Reason = stepUpResult.Reason
			result.GuardResult = stepUpResult.GuardResult

		case "approval":
			// High-risk operations require a bounded approval capability token.
			result.Allowed = false
			result.Reason = "human approval required"
			token := strings.TrimSpace(r.Header.Get("X-Step-Up-Token"))
			if token == "" {
				break
			}
			if verifier == nil {
				result.Reason = "approval capability verifier unavailable"
				break
			}

			scope := ApprovalScope{
				Action:        "tool.call",
				Resource:      toolName,
				ActorSPIFFEID: GetSPIFFEID(ctx),
				SessionID:     expectedApprovalSessionID(r, ctx),
			}
			claims, err := verifier.ValidateAndConsume(token, scope)
			if err != nil {
				result.Reason = approvalFailureReason(err)
				break
			}
			result.Allowed = true
			result.Reason = "step-up approval capability validated"
			r.Header.Set("X-Step-Up-Approved", "true")
			if claims != nil {
				r.Header.Set("X-Approval-Marker", claims.RequestID)
			}

		case "deny":
			// Deny by default
			result.Allowed = false
			result.Reason = "risk score exceeds maximum threshold - denied by default"
		}

		// OC-lmzm: Set X-Precinct-Backup-Recommended advisory header when
		// the action requires a pre-execution state snapshot (Score >= 2) AND
		// the action is allowed. Denied actions won't execute, so no snapshot needed.
		if rev.RequiresBackup && result.Allowed {
			r.Header.Set("X-Precinct-Backup-Recommended", "true")

			// OC-lmzm: Record authorized destructive action in session context.
			if session != nil {
				session.DestructiveActionsAuthorized++
			}
		}

		// RFA-m6j.2: Set per-middleware span attributes
		guardResultStr := ""
		if result.GuardResult != nil {
			if result.GuardResult.Error != "" {
				guardResultStr = "error: " + result.GuardResult.Error
			} else if result.GuardResult.Blocked {
				guardResultStr = "blocked"
			} else {
				guardResultStr = "passed"
			}
		}
		// OC-d77k: Include escalation score and state in span attributes
		var escalationScore float64
		var escalationState string
		if session != nil {
			escalationScore = session.EscalationScore
			escalationState = EscalationState(session.EscalationScore)
		}
		span.SetAttributes(
			attribute.String("gate", gate),
			attribute.Int("total_score", totalScore),
			attribute.Int("impact", riskScore.Impact),
			attribute.Int("reversibility", riskScore.Reversibility),
			attribute.Int("exposure", riskScore.Exposure),
			attribute.Int("novelty", riskScore.Novelty),
			attribute.String("guard_result", guardResultStr),
			attribute.Int("reversibility_score", rev.Score),
			attribute.String("reversibility_category", rev.Category),
			attribute.Bool("backup_recommended", rev.RequiresBackup && result.Allowed),
			attribute.Float64("escalation_score", escalationScore),
			attribute.String("escalation_state", escalationState),
		)
		if result.Allowed {
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", result.Reason),
			)
		} else {
			span.SetAttributes(
				attribute.String("mcp.result", "denied"),
				attribute.String("mcp.reason", result.Reason),
			)
		}

		// Store result in context for audit
		ctx = WithStepUpResult(ctx, result)

		// Log audit event for step-up decision (OC-h4m7: includes reversibility classification)
		// OC-d77k: includes escalation_score and escalation_state
		if auditor != nil {
			secAudit := &SecurityAudit{
				ReversibilityScore:    rev.Score,
				ReversibilityCategory: rev.Category,
				BackupRecommended:     rev.RequiresBackup && result.Allowed,
			}
			if session != nil {
				secAudit.EscalationScore = session.EscalationScore
				secAudit.EscalationState = EscalationState(session.EscalationScore)
			}
			auditor.Log(AuditEvent{
				SessionID:  GetSessionID(ctx),
				DecisionID: GetDecisionID(ctx),
				TraceID:    GetTraceID(ctx),
				SPIFFEID:   GetSPIFFEID(ctx),
				Action:     "step_up_gating",
				Result:     fmt.Sprintf("gate=%s allowed=%v total_score=%d impact=%d reversibility=%d exposure=%d novelty=%d reason=%s", gate, result.Allowed, totalScore, riskScore.Impact, riskScore.Reversibility, riskScore.Exposure, riskScore.Novelty, result.Reason),
				Method:     r.Method,
				Path:       r.URL.Path,
				Security:   secAudit,
			})
		}

		// Block if not allowed
		if !result.Allowed {
			// Map gate to specific error code
			errCode := ErrStepUpDenied
			statusCode := http.StatusForbidden
			remediation := "Reduce risk score or obtain step-up approval."
			switch {
			case result.Gate == "approval":
				errCode = ErrStepUpApprovalRequired
			case result.GuardResult != nil && result.GuardResult.Blocked:
				errCode = ErrStepUpGuardBlocked
			case strings.Contains(strings.ToLower(result.Reason), "guard unavailable"):
				errCode = ErrStepUpUnavailableFailClosed
				statusCode = http.StatusServiceUnavailable
				remediation = "Restore guard model availability; strict runtime requires the guard check."
			case strings.Contains(result.Reason, "destination not allowed"):
				errCode = ErrStepUpDestinationBlocked
			}
			WriteGatewayError(w, r.WithContext(ctx), statusCode, GatewayError{
				Code:           errCode,
				Message:        result.Reason,
				Middleware:     "step_up_gating",
				MiddlewareStep: 9,
				Details: map[string]any{
					"gate":       result.Gate,
					"risk_score": result.TotalScore,
					"risk_breakdown": map[string]int{
						"impact":        riskScore.Impact,
						"reversibility": riskScore.Reversibility,
						"exposure":      riskScore.Exposure,
						"novelty":       riskScore.Novelty,
					},
				},
				Remediation: remediation,
			})
			return
		}

		// Continue to next middleware
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requiresModelApproval(r *http.Request, body []byte) bool {
	if r == nil {
		return false
	}
	if r.Method != http.MethodPost || r.URL == nil {
		return false
	}
	switch r.URL.Path {
	case openAICompatChatCompletionsPath,
		openAICompatResponsesPath,
		anthropicMessagesPath,
		openClawResponsesPath:
		// model proxy paths -- continue to check approval requirements
	default:
		return false
	}

	ctx := r.Context()
	// Strict runtime defaults to explicit approval requirement for model routes.
	if IsStrictRuntimeProfile(ctx) {
		return true
	}

	// Trusted session context is the authority for risk posture. If missing, fail
	// safe by requiring approval (no caller-controlled downgrade path).
	session := GetSessionContextData(ctx)
	if session == nil || len(session.DataClassifications) == 0 {
		return true
	}

	// Regulated/sensitive classifications always require approval.
	for _, class := range session.DataClassifications {
		switch strings.ToLower(strings.TrimSpace(class)) {
		case "phi", "pii", "sensitive", "regulated", "confidential":
			return true
		}
	}

	// Elevated session risk requires approval even without explicit classification.
	if session.RiskScore >= 0.5 {
		return true
	}

	// Trusted model policy defaults: certain model/provider classes always require
	// explicit approval even when session context is otherwise low-risk.
	model := strings.ToLower(strings.TrimSpace(extractModelName(body)))
	if strings.HasPrefix(model, "gpt-4") {
		return true
	}
	provider := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Model-Provider")))
	if provider == "openai" || provider == "azure_openai" {
		return true
	}

	// Public/internal session context can proceed without mandatory approval.
	return false
}

func extractModelName(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	model, _ := payload["model"].(string)
	return strings.TrimSpace(model)
}

func approvalFailureReason(err error) string {
	switch {
	case errors.Is(err, ErrApprovalTokenExpired):
		return "approval capability token expired"
	case errors.Is(err, ErrApprovalTokenConsumed):
		return "approval capability token already consumed"
	case errors.Is(err, ErrApprovalScopeMismatch), errors.Is(err, ErrApprovalIdentityMismatch):
		return "approval capability scope does not match operation"
	default:
		return "approval capability token invalid"
	}
}

func expectedApprovalSessionID(r *http.Request, ctx context.Context) string {
	if r != nil {
		if raw := strings.TrimSpace(r.Header.Get("X-Session-ID")); raw != "" {
			return raw
		}
	}
	return GetSessionID(ctx)
}

// applyStepUpControls runs the step-up controls for scores 4-6
// 1. Destination allowlist check
// 2. Prompt Guard 2 via Groq API
func applyStepUpControls(
	ctx context.Context,
	destination string,
	body []byte,
	allowlist *DestinationAllowlist,
	guardClient GroqGuardClient,
	riskConfig *RiskConfig,
) *StepUpGatingResult {
	result := &StepUpGatingResult{
		Allowed: true,
		Reason:  "step-up controls passed",
	}
	strictRuntime := IsStrictRuntimeProfile(ctx)

	// Control 1: Destination allowlist check
	if destination != "" && !allowlist.IsAllowed(destination) {
		result.Allowed = false
		result.Reason = "destination not allowed"
		return result
	}

	// Control 2: Guard model check (Prompt Guard 2 via Groq)
	if guardClient == nil {
		if strictRuntime {
			result.Allowed = false
			result.GuardResult = &GuardResult{Error: "guard model not configured"}
			result.Reason = "step-up guard unavailable in strict runtime (fail closed)"
			return result
		}
		// No guard client configured - skip for step-up range (4-6)
		// Fail open for medium risk since we have destination check as backstop
		result.Reason = "step-up controls passed (guard model not configured)"
		return result
	}

	guardResult, err := guardClient.ClassifyContent(ctx, string(body))
	if err != nil {
		if strictRuntime {
			result.Allowed = false
			result.GuardResult = &GuardResult{
				Error: err.Error(),
			}
			result.Reason = "step-up guard unavailable in strict runtime (fail closed)"
			return result
		}
		// Guard model unavailable - for step-up range (4-6), skip the guard check
		// (fail open for medium risk; high risk fails closed in the approval/deny gates)
		result.GuardResult = &GuardResult{
			Error: err.Error(),
		}
		result.Reason = "step-up controls passed (guard model unavailable - fail open for medium risk)"
		return result
	}

	result.GuardResult = guardResult

	// Check thresholds
	if guardResult.InjectionProb > riskConfig.Guard.InjectionThreshold {
		guardResult.Blocked = true
		result.Allowed = false
		result.Reason = fmt.Sprintf("injection probability %.2f exceeds threshold %.2f",
			guardResult.InjectionProb, riskConfig.Guard.InjectionThreshold)
		return result
	}

	if guardResult.JailbreakProb > riskConfig.Guard.JailbreakThreshold {
		guardResult.Blocked = true
		result.Allowed = false
		result.Reason = fmt.Sprintf("jailbreak probability %.2f exceeds threshold %.2f",
			guardResult.JailbreakProb, riskConfig.Guard.JailbreakThreshold)
		return result
	}

	return result
}

// IsAppDrivenHighRisk returns true when an app-driven tool call targets a
// high or critical risk tool. In this case, step-up gating is ALWAYS required
// regardless of the computed risk score (RFA-j2d.4, Section 7.9.5).
//
// Rationale: buttons create dangerously low-friction paths to high-impact actions.
// A single click should not silently trigger a critical operation.
//
// Parameters:
//   - callOrigin: "app" or "agent" (from context or mediator)
//   - riskLevel: the tool's risk_level from the registry
//   - forceStepUpEnabled: from UIConfig.AppToolCalls.ForceStepUpForHighRisk
func IsAppDrivenHighRisk(callOrigin, riskLevel string, forceStepUpEnabled bool) bool {
	if callOrigin != "app" {
		return false
	}
	if !forceStepUpEnabled {
		return false
	}
	return riskLevel == "high" || riskLevel == "critical"
}
