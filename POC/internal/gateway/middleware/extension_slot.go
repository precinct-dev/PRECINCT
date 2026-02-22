// Extension Slot middleware -- dispatches to external HTTP sidecar extensions
// at named positions in the middleware chain.
//
// Each ExtensionSlot middleware instance handles one slot (e.g., post_authz).
// Within a slot, extensions execute in priority order (lower = first).
//
// Extension protocol: HTTP POST with ExtensionRequest, expects ExtensionResponse.
// Decisions: allow (pass through), block (deny with GatewayError), flag (append
// to SecurityFlagsCollector and continue).
package middleware

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ExtensionRequest is the JSON payload POSTed to extension sidecars.
type ExtensionRequest struct {
	Version   string                  `json:"version"`
	RequestID string                  `json:"request_id"`
	TraceID   string                  `json:"trace_id"`
	Timestamp string                  `json:"timestamp"`
	Slot      ExtensionSlotName       `json:"slot"`
	Request   ExtensionRequestPayload `json:"request"`
}

// ExtensionRequestPayload contains the subset of request data configured for
// inclusion via the extension's request_fields settings.
type ExtensionRequestPayload struct {
	Method        string   `json:"method,omitempty"`
	ToolName      string   `json:"tool_name,omitempty"`
	Body          string   `json:"body,omitempty"` // base64-encoded
	SPIFFEID      string   `json:"spiffe_id,omitempty"`
	SecurityFlags []string `json:"security_flags,omitempty"`
	SessionID     string   `json:"session_id,omitempty"`
}

// ExtensionResponse is the expected JSON response from extension sidecars.
type ExtensionResponse struct {
	Version    string   `json:"version"`
	Decision   string   `json:"decision"` // "allow", "block", or "flag"
	Flags      []string `json:"flags,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	HTTPStatus int      `json:"http_status,omitempty"`
	ErrorCode  string   `json:"error_code,omitempty"`
}

// extensionCircuitBreaker tracks failures for a single extension sidecar.
type extensionCircuitBreaker struct {
	mu               sync.Mutex
	failures         int
	lastFailure      time.Time
	open             bool
	failureThreshold int
	resetTimeout     time.Duration
}

func newExtensionCircuitBreaker(config *ExtensionCBConfig) *extensionCircuitBreaker {
	if config == nil {
		return nil
	}
	return &extensionCircuitBreaker{
		failureThreshold: config.FailureThreshold,
		resetTimeout:     time.Duration(config.ResetTimeoutMs) * time.Millisecond,
	}
}

func (cb *extensionCircuitBreaker) allow() bool {
	if cb == nil {
		return true
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if !cb.open {
		return true
	}
	// Check if reset timeout has elapsed.
	if time.Since(cb.lastFailure) >= cb.resetTimeout {
		cb.open = false
		cb.failures = 0
		return true
	}
	return false
}

func (cb *extensionCircuitBreaker) recordSuccess() {
	if cb == nil {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.open = false
}

func (cb *extensionCircuitBreaker) recordFailure() {
	if cb == nil {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()
	if cb.failures >= cb.failureThreshold {
		cb.open = true
	}
}

// ExtensionSlot creates a middleware that dispatches to extension sidecars
// registered for the given slot. If no extensions are configured for the slot,
// the middleware is a zero-cost pass-through.
func ExtensionSlot(next http.Handler, registry *ExtensionRegistry, slot ExtensionSlotName, auditor *Auditor) http.Handler {
	// Pre-build circuit breakers for each extension in this slot.
	// These persist across requests for the lifetime of the handler.
	var circuitBreakers map[string]*extensionCircuitBreaker
	if exts := registry.ExtensionsForSlot(slot); len(exts) > 0 {
		circuitBreakers = make(map[string]*extensionCircuitBreaker, len(exts))
		for _, ext := range exts {
			circuitBreakers[ext.Name] = newExtensionCircuitBreaker(ext.CircuitBreaker)
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extensions := registry.ExtensionsForSlot(slot)
		if len(extensions) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()

		// Create parent OTel span for this extension slot.
		ctx, slotSpan := tracer.Start(ctx, fmt.Sprintf("gateway.extension_slot.%s", slot),
			trace.WithAttributes(
				attribute.String("extension.slot", string(slot)),
				attribute.Int("extension.count", len(extensions)),
			),
		)
		defer slotSpan.End()

		// Extract request metadata once for all extensions in this slot.
		body := GetRequestBody(ctx)
		parsed, _ := ParseMCPRequestBody(body)
		mcpMethod := ""
		toolName := ""
		if parsed != nil {
			mcpMethod = parsed.RPCMethod
			if effective, err := parsed.EffectiveToolName(); err == nil {
				toolName = effective
			}
		}

		for _, ext := range extensions {
			if !ext.MatchesRequest(mcpMethod, toolName) {
				continue
			}

			// Check per-extension circuit breaker.
			cb := circuitBreakers[ext.Name]
			if !cb.allow() {
				slog.Warn("extension circuit breaker open, skipping",
					"extension", ext.Name, "slot", string(slot))
				if ext.FailMode == "fail_closed" {
					slotSpan.SetAttributes(
						attribute.String("extension.result", "circuit_breaker_open_fail_closed"),
						attribute.String("extension.name", ext.Name),
					)
					WriteGatewayError(w, r.WithContext(ctx), http.StatusServiceUnavailable, GatewayError{
						Code:       ErrExtensionUnavailableFailClosed,
						Message:    fmt.Sprintf("Extension %q circuit breaker is open", ext.Name),
						Middleware: "extension_slot",
						Details: map[string]any{
							"extension": ext.Name,
							"slot":      string(slot),
						},
						Remediation: "The extension sidecar has exceeded its failure threshold. It will recover after the reset timeout.",
					})
					return
				}
				// fail_open: skip this extension.
				continue
			}

			// Create child span for this specific extension call.
			_, extSpan := tracer.Start(ctx, fmt.Sprintf("gateway.extension.%s", ext.Name),
				trace.WithAttributes(
					attribute.String("extension.name", ext.Name),
					attribute.String("extension.slot", string(slot)),
					attribute.String("extension.endpoint", ext.Endpoint),
					attribute.Int("extension.priority", ext.Priority),
				),
			)

			resp, err := callExtension(ctx, ext, r, body, slot)
			if err != nil {
				cb.recordFailure()
				extSpan.SetAttributes(attribute.String("extension.error", err.Error()))
				extSpan.End()

				if auditor != nil {
					auditor.Log(AuditEvent{
						SessionID:  GetSessionID(ctx),
						DecisionID: GetDecisionID(ctx),
						TraceID:    GetTraceID(ctx),
						SPIFFEID:   GetSPIFFEID(ctx),
						Action:     fmt.Sprintf("extension_%s_error", ext.Name),
						Result:     fmt.Sprintf("slot=%s error=%s fail_mode=%s", slot, err.Error(), ext.FailMode),
					})
				}

				if ext.FailMode == "fail_closed" {
					slotSpan.SetAttributes(
						attribute.String("extension.result", "error_fail_closed"),
						attribute.String("extension.name", ext.Name),
					)
					WriteGatewayError(w, r.WithContext(ctx), http.StatusServiceUnavailable, GatewayError{
						Code:       ErrExtensionUnavailableFailClosed,
						Message:    fmt.Sprintf("Extension %q unavailable (fail_closed)", ext.Name),
						Middleware: "extension_slot",
						Details: map[string]any{
							"extension": ext.Name,
							"slot":      string(slot),
							"error":     err.Error(),
						},
						Remediation: "The extension sidecar is unreachable. Check that the sidecar is running and accessible.",
					})
					return
				}
				// fail_open: log and continue to next extension.
				continue
			}

			cb.recordSuccess()

			extSpan.SetAttributes(
				attribute.String("extension.decision", resp.Decision),
				attribute.String("extension.reason", resp.Reason),
			)
			extSpan.End()

			switch resp.Decision {
			case "block":
				httpStatus := http.StatusForbidden
				if resp.HTTPStatus > 0 {
					httpStatus = resp.HTTPStatus
				}
				errorCode := ErrExtensionBlocked
				if resp.ErrorCode != "" {
					errorCode = resp.ErrorCode
				}

				slotSpan.SetAttributes(
					attribute.String("extension.result", "blocked"),
					attribute.String("extension.name", ext.Name),
				)

				if auditor != nil {
					auditor.Log(AuditEvent{
						SessionID:  GetSessionID(ctx),
						DecisionID: GetDecisionID(ctx),
						TraceID:    GetTraceID(ctx),
						SPIFFEID:   GetSPIFFEID(ctx),
						Action:     fmt.Sprintf("extension_%s_blocked", ext.Name),
						Result:     fmt.Sprintf("slot=%s reason=%s", slot, resp.Reason),
					})
				}

				WriteGatewayError(w, r.WithContext(ctx), httpStatus, GatewayError{
					Code:       errorCode,
					Message:    fmt.Sprintf("Extension %q blocked request: %s", ext.Name, resp.Reason),
					Middleware: "extension_slot",
					Details: map[string]any{
						"extension": ext.Name,
						"slot":      string(slot),
						"reason":    resp.Reason,
					},
					Remediation: "The request was denied by an extension sidecar. Check the extension's documentation for resolution.",
				})
				return

			case "flag":
				if collector := GetFlagsCollector(ctx); collector != nil && len(resp.Flags) > 0 {
					collector.AppendAll(resp.Flags)
				}
				slotSpan.SetAttributes(
					attribute.String("extension.result", "flagged"),
					attribute.String("extension.name", ext.Name),
				)
				if auditor != nil {
					auditor.Log(AuditEvent{
						SessionID:  GetSessionID(ctx),
						DecisionID: GetDecisionID(ctx),
						TraceID:    GetTraceID(ctx),
						SPIFFEID:   GetSPIFFEID(ctx),
						Action:     fmt.Sprintf("extension_%s_flagged", ext.Name),
						Result:     fmt.Sprintf("slot=%s flags=%v reason=%s", slot, resp.Flags, resp.Reason),
					})
				}

			case "allow":
				slotSpan.SetAttributes(
					attribute.String("extension.result", "allowed"),
					attribute.String("extension.name", ext.Name),
				)

			default:
				// Unknown decision -- treat as allow with a warning.
				slog.Warn("extension returned unknown decision, treating as allow",
					"extension", ext.Name, "decision", resp.Decision)
				slotSpan.SetAttributes(
					attribute.String("extension.result", "unknown_decision_allow"),
					attribute.String("extension.name", ext.Name),
				)
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// callExtension makes an HTTP POST to an extension sidecar and parses the response.
func callExtension(ctx context.Context, ext ExtensionDefinition, r *http.Request, body []byte, slot ExtensionSlotName) (*ExtensionResponse, error) {
	// Build the request payload based on configured request_fields.
	payload := ExtensionRequestPayload{
		SessionID: GetSessionID(ctx),
	}
	if ext.RequestFields.IncludeBody && len(body) > 0 {
		payload.Body = base64.StdEncoding.EncodeToString(body)
	}
	if ext.RequestFields.IncludeSPIFFEID {
		payload.SPIFFEID = GetSPIFFEID(ctx)
	}
	if ext.RequestFields.IncludeSecurityFlags {
		payload.SecurityFlags = GetSecurityFlags(ctx)
	}

	// Extract MCP method and tool name for the payload.
	parsed, _ := ParseMCPRequestBody(body)
	if parsed != nil {
		payload.Method = parsed.RPCMethod
		if ext.RequestFields.IncludeToolName {
			if tn, err := parsed.EffectiveToolName(); err == nil {
				payload.ToolName = tn
			}
		}
	}

	extReq := ExtensionRequest{
		Version:   "1",
		RequestID: GetDecisionID(ctx),
		TraceID:   GetTraceID(ctx),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Slot:      slot,
		Request:   payload,
	}

	reqBody, err := json.Marshal(extReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal extension request: %w", err)
	}

	timeout := time.Duration(ext.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	client := &http.Client{Timeout: timeout}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ext.Endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request to extension %q failed: %w", ext.Name, err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read extension response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("extension %q returned HTTP %d: %s", ext.Name, httpResp.StatusCode, string(respBody))
	}

	var extResp ExtensionResponse
	if err := json.Unmarshal(respBody, &extResp); err != nil {
		return nil, fmt.Errorf("failed to parse extension response: %w", err)
	}

	return &extResp, nil
}
