package precinctcli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client is a minimal HTTP client for calling the gateway API.
// Walking skeleton scope (RFA-qq5f): only GET /health.
type Client struct {
	baseURL       string
	controlURL    string
	httpClient    *http.Client
	adminSPIFFEID string
}

// Health is the subset of /health response we care about for status output.
type Health struct {
	Status              string
	CircuitBreakerState string
	Raw                 map[string]any
}

func NewClient(baseURL string) *Client {
	adminSPIFFEID := strings.TrimSpace(os.Getenv("PRECINCT_GATEWAY_SPIFFE_ID"))
	if adminSPIFFEID == "" {
		adminSPIFFEID = "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		controlURL: deriveControlURL(baseURL),
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
		adminSPIFFEID: adminSPIFFEID,
	}
}

func deriveControlURL(baseURL string) string {
	override := strings.TrimSpace(os.Getenv("PRECINCT_CONTROL_URL"))
	if override != "" {
		return strings.TrimRight(override, "/")
	}

	controlURL := strings.TrimRight(baseURL, "/")
	replacements := [][2]string{
		{"://precinct-gateway:9090", "://precinct-control:9090"},
		{"://localhost:9090", "://localhost:9091"},
		{"://127.0.0.1:9090", "://127.0.0.1:9091"},
	}
	for _, replacement := range replacements {
		if strings.Contains(controlURL, replacement[0]) {
			return strings.Replace(controlURL, replacement[0], replacement[1], 1)
		}
	}
	return controlURL
}

func (c *Client) applyAdminHeaders(req *http.Request) {
	if req == nil {
		return
	}
	if c != nil && strings.TrimSpace(c.adminSPIFFEID) != "" {
		req.Header.Set("X-SPIFFE-ID", c.adminSPIFFEID)
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

func (c *Client) GetCircuitBreakers(ctx context.Context) ([]CircuitBreakerEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.controlURL+"/admin/circuit-breakers", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	c.applyAdminHeaders(req)

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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.controlURL+"/admin/circuit-breakers/"+tool, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	c.applyAdminHeaders(req)

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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.controlURL+"/admin/circuit-breakers/reset", bytes.NewReader(reqBody))
	if err != nil {
		return CircuitBreakersResetOutput{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyAdminHeaders(req)

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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.controlURL+"/admin/policy/reload", nil)
	if err != nil {
		return PolicyReloadOutput{}, fmt.Errorf("create request: %w", err)
	}
	c.applyAdminHeaders(req)

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
