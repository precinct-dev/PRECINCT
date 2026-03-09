package agw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client is a minimal HTTP client for calling the gateway API.
// Walking skeleton scope (RFA-qq5f): only GET /health.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// Health is the subset of /health response we care about for status output.
type Health struct {
	Status              string
	CircuitBreakerState string
	Raw                 map[string]any
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (c *Client) GetHealth(ctx context.Context) (*Health, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway unhealthy: status_code=%d", resp.StatusCode)
	}

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode /health JSON: %w", err)
	}

	h := &Health{
		Raw: raw,
	}
	if v, ok := raw["status"].(string); ok {
		h.Status = v
	}
	if cb, ok := raw["circuit_breaker"].(map[string]any); ok {
		if state, ok := cb["state"].(string); ok {
			h.CircuitBreakerState = state
		}
	}

	return h, nil
}

type CircuitBreakerEntry struct {
	Tool            string     `json:"tool"`
	State           string     `json:"state"`
	Failures        int        `json:"failures"`
	Threshold       int        `json:"threshold"`
	ResetTimeoutSec int        `json:"reset_timeout_seconds"`
	LastStateChange *time.Time `json:"last_state_change"`
}

type circuitBreakersResponse struct {
	CircuitBreakers []CircuitBreakerEntry `json:"circuit_breakers"`
}

type CircuitBreakerResetEntry struct {
	Tool          string `json:"tool"`
	PreviousState string `json:"previous_state"`
	NewState      string `json:"new_state"`
}

type CircuitBreakersResetOutput struct {
	Reset []CircuitBreakerResetEntry `json:"reset"`
}

type circuitBreakersResetResponse struct {
	Reset []CircuitBreakerResetEntry `json:"reset"`
}

type PolicyReloadOutput struct {
	Status         string `json:"status"`
	Timestamp      string `json:"timestamp"`
	RegistryTools  int    `json:"registry_tools"`
	OPAPolicies    int    `json:"opa_policies"`
	CosignVerified bool   `json:"cosign_verified"`
}

type policyReloadErrorResponse struct {
	Status         string `json:"status"`
	Error          string `json:"error"`
	CosignVerified bool   `json:"cosign_verified"`
}

type DLPRuleset struct {
	Version            string   `json:"version"`
	Digest             string   `json:"digest"`
	State              string   `json:"state"`
	Approved           bool     `json:"approved"`
	Signed             bool     `json:"signed"`
	Approver           string   `json:"approver,omitempty"`
	CredentialPatterns []string `json:"credential_patterns,omitempty"`
	PIIPatterns        []string `json:"pii_patterns,omitempty"`
	SuspiciousPatterns []string `json:"suspicious_patterns,omitempty"`
}

type DLPRulesetsOutput struct {
	Status   string       `json:"status"`
	Error    string       `json:"error,omitempty"`
	Active   *DLPRuleset  `json:"active,omitempty"`
	Rulesets []DLPRuleset `json:"rulesets,omitempty"`
}

type DLPRulesetUpsertInput struct {
	Version            string   `json:"version"`
	CredentialPatterns []string `json:"credential_patterns,omitempty"`
	PIIPatterns        []string `json:"pii_patterns,omitempty"`
	SuspiciousPatterns []string `json:"suspicious_patterns,omitempty"`
}

type LoopImmutableLimits struct {
	MaxSteps             int     `json:"max_steps"`
	MaxToolCalls         int     `json:"max_tool_calls"`
	MaxModelCalls        int     `json:"max_model_calls"`
	MaxWallTimeMS        int     `json:"max_wall_time_ms"`
	MaxEgressBytes       int     `json:"max_egress_bytes"`
	MaxModelCostUSD      float64 `json:"max_model_cost_usd"`
	MaxProviderFailovers int     `json:"max_provider_failovers"`
	MaxRiskScore         float64 `json:"max_risk_score"`
}

type LoopUsageSnapshot struct {
	Steps             int     `json:"steps"`
	ToolCalls         int     `json:"tool_calls"`
	ModelCalls        int     `json:"model_calls"`
	WallTimeMS        int     `json:"wall_time_ms"`
	EgressBytes       int     `json:"egress_bytes"`
	ModelCostUSD      float64 `json:"model_cost_usd"`
	ProviderFailovers int     `json:"provider_failovers"`
	RiskScore         float64 `json:"risk_score"`
}

type LoopRunStatus struct {
	RunID          string              `json:"run_id"`
	SessionID      string              `json:"session_id"`
	Tenant         string              `json:"tenant"`
	State          string              `json:"state"`
	HaltReason     string              `json:"halt_reason"`
	Limits         LoopImmutableLimits `json:"limits"`
	Usage          LoopUsageSnapshot   `json:"usage"`
	LastDecisionID string              `json:"last_decision_id"`
	LastTraceID    string              `json:"last_trace_id"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
}

type LoopRunsOutput struct {
	Status string          `json:"status"`
	Error  string          `json:"error,omitempty"`
	Run    *LoopRunStatus  `json:"run,omitempty"`
	Runs   []LoopRunStatus `json:"runs,omitempty"`
}

func (c *Client) GetCircuitBreakers(ctx context.Context) ([]CircuitBreakerEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/admin/circuit-breakers", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned status_code=%d", resp.StatusCode)
	}

	var parsed circuitBreakersResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode /admin/circuit-breakers JSON: %w", err)
	}
	return parsed.CircuitBreakers, nil
}

func (c *Client) GetCircuitBreaker(ctx context.Context, tool string) (*CircuitBreakerEntry, error) {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return nil, fmt.Errorf("tool is empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/admin/circuit-breakers/"+tool, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("tool %q not found", tool)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned status_code=%d", resp.StatusCode)
	}

	var parsed circuitBreakersResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode /admin/circuit-breakers/<tool> JSON: %w", err)
	}
	if len(parsed.CircuitBreakers) != 1 {
		return nil, fmt.Errorf("unexpected circuit_breakers length=%d", len(parsed.CircuitBreakers))
	}
	return &parsed.CircuitBreakers[0], nil
}

func (c *Client) ResetCircuitBreakers(ctx context.Context, tool string) (CircuitBreakersResetOutput, error) {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return CircuitBreakersResetOutput{}, fmt.Errorf("tool is empty")
	}

	reqBody, err := json.Marshal(map[string]string{"tool": tool})
	if err != nil {
		return CircuitBreakersResetOutput{}, fmt.Errorf("marshal reset request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/circuit-breakers/reset", bytes.NewReader(reqBody))
	if err != nil {
		return CircuitBreakersResetOutput{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return CircuitBreakersResetOutput{}, fmt.Errorf("gateway request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if strings.TrimSpace(apiErr.Error) != "" {
			return CircuitBreakersResetOutput{}, fmt.Errorf("gateway returned status_code=%d: %s", resp.StatusCode, apiErr.Error)
		}
		return CircuitBreakersResetOutput{}, fmt.Errorf("gateway returned status_code=%d", resp.StatusCode)
	}

	var parsed circuitBreakersResetResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return CircuitBreakersResetOutput{}, fmt.Errorf("decode /admin/circuit-breakers/reset JSON: %w", err)
	}
	return CircuitBreakersResetOutput(parsed), nil
}

func (c *Client) ReloadPolicy(ctx context.Context) (PolicyReloadOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/policy/reload", nil)
	if err != nil {
		return PolicyReloadOutput{}, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return PolicyReloadOutput{}, fmt.Errorf("gateway request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		var apiErr policyReloadErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if strings.TrimSpace(apiErr.Error) != "" {
			return PolicyReloadOutput{}, fmt.Errorf("gateway returned status_code=%d: %s", resp.StatusCode, apiErr.Error)
		}
		return PolicyReloadOutput{}, fmt.Errorf("gateway returned status_code=%d", resp.StatusCode)
	}

	var out PolicyReloadOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return PolicyReloadOutput{}, fmt.Errorf("decode /admin/policy/reload JSON: %w", err)
	}
	return out, nil
}

func (c *Client) ListDLPRulesets(ctx context.Context) (DLPRulesetsOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/admin/dlp/rulesets", nil)
	if err != nil {
		return DLPRulesetsOutput{}, fmt.Errorf("create request: %w", err)
	}
	return c.doDLPRulesetRequest(req)
}

func (c *Client) GetActiveDLPRuleset(ctx context.Context) (DLPRulesetsOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/admin/dlp/rulesets/active", nil)
	if err != nil {
		return DLPRulesetsOutput{}, fmt.Errorf("create request: %w", err)
	}
	return c.doDLPRulesetRequest(req)
}

func (c *Client) UpsertDLPRuleset(ctx context.Context, in DLPRulesetUpsertInput) (DLPRulesetsOutput, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return DLPRulesetsOutput{}, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/dlp/rulesets", bytes.NewReader(body))
	if err != nil {
		return DLPRulesetsOutput{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doDLPRulesetRequest(req)
}

func (c *Client) ApproveDLPRuleset(ctx context.Context, version, approver, signature string) (DLPRulesetsOutput, error) {
	body, err := json.Marshal(map[string]string{
		"approver":  approver,
		"signature": signature,
	})
	if err != nil {
		return DLPRulesetsOutput{}, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/dlp/rulesets/"+version+"/approve", bytes.NewReader(body))
	if err != nil {
		return DLPRulesetsOutput{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doDLPRulesetRequest(req)
}

func (c *Client) PromoteDLPRuleset(ctx context.Context, version string) (DLPRulesetsOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/dlp/rulesets/"+version+"/promote", nil)
	if err != nil {
		return DLPRulesetsOutput{}, fmt.Errorf("create request: %w", err)
	}
	return c.doDLPRulesetRequest(req)
}

func (c *Client) RollbackDLPRuleset(ctx context.Context, targetVersion string) (DLPRulesetsOutput, error) {
	body, err := json.Marshal(map[string]string{
		"target_version": strings.TrimSpace(targetVersion),
	})
	if err != nil {
		return DLPRulesetsOutput{}, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/dlp/rulesets/rollback", bytes.NewReader(body))
	if err != nil {
		return DLPRulesetsOutput{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doDLPRulesetRequest(req)
}

func (c *Client) ListLoopRuns(ctx context.Context) (LoopRunsOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/admin/loop/runs", nil)
	if err != nil {
		return LoopRunsOutput{}, fmt.Errorf("create request: %w", err)
	}
	return c.doLoopRunsRequest(req)
}

func (c *Client) GetLoopRun(ctx context.Context, runID string) (LoopRunsOutput, error) {
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return LoopRunsOutput{}, fmt.Errorf("run_id is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/admin/loop/runs/"+runID, nil)
	if err != nil {
		return LoopRunsOutput{}, fmt.Errorf("create request: %w", err)
	}
	return c.doLoopRunsRequest(req)
}

func (c *Client) doDLPRulesetRequest(req *http.Request) (DLPRulesetsOutput, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return DLPRulesetsOutput{}, fmt.Errorf("gateway request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var out DLPRulesetsOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return DLPRulesetsOutput{}, fmt.Errorf("decode dlp ruleset response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if strings.TrimSpace(out.Error) != "" {
			return DLPRulesetsOutput{}, fmt.Errorf("gateway returned status_code=%d: %s", resp.StatusCode, out.Error)
		}
		return DLPRulesetsOutput{}, fmt.Errorf("gateway returned status_code=%d", resp.StatusCode)
	}
	return out, nil
}

func (c *Client) doLoopRunsRequest(req *http.Request) (LoopRunsOutput, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return LoopRunsOutput{}, fmt.Errorf("gateway request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var out LoopRunsOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return LoopRunsOutput{}, fmt.Errorf("decode loop runs response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if strings.TrimSpace(out.Error) != "" {
			return LoopRunsOutput{}, fmt.Errorf("gateway returned status_code=%d: %s", resp.StatusCode, out.Error)
		}
		return LoopRunsOutput{}, fmt.Errorf("gateway returned status_code=%d", resp.StatusCode)
	}
	return out, nil
}
