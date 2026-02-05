package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	SPIFFEID string `json:"spiffe_id"`
	Tool     string `json:"tool"`
	Action   string `json:"action"`
	Method   string `json:"method"`
	Path     string `json:"path"`
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

// OPAPolicy middleware enforces OPA authorization
func OPAPolicy(next http.Handler, opa *OPAClient) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Extract tool name from request body
		body := GetRequestBody(ctx)
		toolName := ""
		if len(body) > 0 {
			var mcpReq MCPRequest
			if err := json.Unmarshal(body, &mcpReq); err == nil {
				toolName = mcpReq.Method
				if toolName == "" {
					if tn, ok := mcpReq.Params["tool"]; ok {
						if toolNameStr, ok := tn.(string); ok {
							toolName = toolNameStr
						}
					}
				}
			}
		}

		// Build OPA input
		input := OPAInput{
			SPIFFEID: GetSPIFFEID(ctx),
			Tool:     toolName,
			Action:   "execute",
			Method:   r.Method,
			Path:     r.URL.Path,
		}

		// Evaluate policy
		allowed, reason, err := opa.Evaluate(input)
		if err != nil {
			http.Error(w, fmt.Sprintf("Policy evaluation failed: %v", err), http.StatusInternalServerError)
			return
		}

		if !allowed {
			http.Error(w, fmt.Sprintf("Policy denied: %s", reason), http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
