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
	defer resp.Body.Close()

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

func (c *Client) GetCircuitBreakers(ctx context.Context) ([]CircuitBreakerEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/admin/circuit-breakers", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway request failed: %w", err)
	}
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	return CircuitBreakersResetOutput{Reset: parsed.Reset}, nil
}
