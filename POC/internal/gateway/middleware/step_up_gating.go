// Step-Up Gating Middleware - RFA-qq0.17
// Implements synchronous step-up gating for high-risk tool calls (Section 7.7).
// Position in middleware chain: step 9 (after session context at step 8, before deep scan at step 10).
//
// Risk scoring rubric: 4 dimensions (Impact, Reversibility, Exposure, Novelty), 0-3 each, total 0-12.
// Gating thresholds:
//
//	0-3:   Fast path (no friction)
//	4-6:   Step-up gating (destination allowlist + guard model)
//	7-9:   Approval required (HTTP 403 stub)
//	10-12: Deny by default (HTTP 403)
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

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

// RiskConfig holds the complete risk configuration loaded from YAML
type RiskConfig struct {
	Thresholds          RiskThresholds      `yaml:"thresholds"`
	Guard               GuardThresholds     `yaml:"guard"`
	UnknownToolDefaults UnknownToolDefaults `yaml:"unknown_tool_defaults"`
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

// GroqGuardClient is the interface for calling the guard model
type GroqGuardClient interface {
	ClassifyContent(ctx context.Context, content string) (*GuardResult, error)
}

// GroqGuardHTTPClient implements GroqGuardClient using the Groq API
type GroqGuardHTTPClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewGroqGuardClient creates a new Groq guard client
func NewGroqGuardClient(apiKey string, timeout time.Duration) *GroqGuardHTTPClient {
	return &GroqGuardHTTPClient{
		apiKey:  apiKey,
		baseURL: "https://api.groq.com/openai/v1",
		httpClient: &http.Client{
			Timeout: timeout,
		},
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
		"model": "meta-llama/llama-prompt-guard-2-86m",
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

// ComputeRiskScore computes the 4-dimensional risk score for a tool call
func ComputeRiskScore(
	toolDef *ToolDefinition,
	session *AgentSession,
	destination string,
	isExternal bool,
	registry *ToolRegistry,
	allowlist *DestinationAllowlist,
	defaults UnknownToolDefaults,
) RiskDimension {

	// If tool is unknown, use defaults with max novelty
	if toolDef == nil {
		return RiskDimension{
			Impact:        defaults.Impact,
			Reversibility: defaults.Reversibility,
			Exposure:      defaults.Exposure,
			Novelty:       defaults.Novelty,
		}
	}

	// --- Impact dimension (0-3) ---
	impact := computeImpact(toolDef)

	// --- Reversibility dimension (0-3) ---
	reversibility := computeReversibility(toolDef)

	// --- Exposure dimension (0-3) ---
	exposure := computeExposure(toolDef, isExternal, session)

	// --- Novelty dimension (0-3) ---
	novelty := computeNovelty(toolDef, destination, allowlist)

	return RiskDimension{
		Impact:        impact,
		Reversibility: reversibility,
		Exposure:      exposure,
		Novelty:       novelty,
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
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Parse tool call from request body
		body := GetRequestBody(ctx)
		if len(body) == 0 {
			// No body, pass through (fast path)
			next.ServeHTTP(w, r)
			return
		}

		var mcpReq MCPRequest
		if err := json.Unmarshal(body, &mcpReq); err != nil {
			// Not a valid MCP request, pass through
			next.ServeHTTP(w, r)
			return
		}

		// Extract tool name
		toolName := mcpReq.Method
		if toolName == "" {
			if tn, ok := mcpReq.Params["tool"]; ok {
				if toolNameStr, ok := tn.(string); ok {
					toolName = toolNameStr
				}
			}
		}

		if toolName == "" {
			// No tool identified, pass through
			next.ServeHTTP(w, r)
			return
		}

		// Look up tool definition
		var toolDef *ToolDefinition
		if def, exists := registry.GetToolDefinition(toolName); exists {
			toolDef = &def
		}

		// Determine if external target and destination
		isExternal, destination := isExternalTarget(toolName, mcpReq.Params)

		// Also check params for explicit destination field
		if dest, ok := mcpReq.Params["destination"].(string); ok && destination == "" {
			destination = dest
			if destination != "" {
				isExternal = true
			}
		}

		// Get session context (set by step 8)
		session := GetSessionContextData(ctx)

		// Compute risk score
		riskScore := ComputeRiskScore(toolDef, session, destination, isExternal, registry, allowlist, riskConfig.UnknownToolDefaults)
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
			// Human approval required (stub for POC)
			result.Allowed = false
			result.Reason = "human approval required"

		case "deny":
			// Deny by default
			result.Allowed = false
			result.Reason = "risk score exceeds maximum threshold - denied by default"
		}

		// Store result in context for audit
		ctx = WithStepUpResult(ctx, result)

		// Log audit event for step-up decision
		if auditor != nil {
			auditor.Log(AuditEvent{
				SessionID:  GetSessionID(ctx),
				DecisionID: GetDecisionID(ctx),
				TraceID:    GetTraceID(ctx),
				SPIFFEID:   GetSPIFFEID(ctx),
				Action:     "step_up_gating",
				Result:     fmt.Sprintf("gate=%s allowed=%v total_score=%d impact=%d reversibility=%d exposure=%d novelty=%d reason=%s", gate, result.Allowed, totalScore, riskScore.Impact, riskScore.Reversibility, riskScore.Exposure, riskScore.Novelty, result.Reason),
				Method:     r.Method,
				Path:       r.URL.Path,
			})
		}

		// Block if not allowed
		if !result.Allowed {
			w.Header().Set("Content-Type", "application/json")

			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":      "step_up_gating_denied",
				"reason":     result.Reason,
				"gate":       result.Gate,
				"risk_score": result.TotalScore,
				"risk_breakdown": map[string]int{
					"impact":        riskScore.Impact,
					"reversibility": riskScore.Reversibility,
					"exposure":      riskScore.Exposure,
					"novelty":       riskScore.Novelty,
				},
			})
			return
		}

		// Continue to next middleware
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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

	// Control 1: Destination allowlist check
	if destination != "" && !allowlist.IsAllowed(destination) {
		result.Allowed = false
		result.Reason = "destination not allowed"
		return result
	}

	// Control 2: Guard model check (Prompt Guard 2 via Groq)
	if guardClient == nil {
		// No guard client configured - skip for step-up range (4-6)
		// Fail open for medium risk since we have destination check as backstop
		result.Reason = "step-up controls passed (guard model not configured)"
		return result
	}

	guardResult, err := guardClient.ClassifyContent(ctx, string(body))
	if err != nil {
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
