// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// Compile-time check: *Gateway implements PortGatewayServices.
var _ PortGatewayServices = (*Gateway)(nil)

// BuildModelPlaneRequest delegates to the private buildModelPlaneRequestFromOpenAI.
func (g *Gateway) BuildModelPlaneRequest(r *http.Request, payload map[string]any) PlaneRequestV2 {
	return g.buildModelPlaneRequestFromOpenAI(r, payload)
}

// EvaluateModelPlaneDecision delegates to the private evaluateModelPlaneDecision.
func (g *Gateway) EvaluateModelPlaneDecision(r *http.Request, req PlaneRequestV2) (Decision, ReasonCode, int, map[string]any) {
	return g.evaluateModelPlaneDecision(r, req)
}

// ExecuteModelEgress delegates to the private executeModelEgress, converting the result.
func (g *Gateway) ExecuteModelEgress(ctx context.Context, attrs map[string]any, payload map[string]any, authHeader string) (*ModelEgressResult, error) {
	result, err := g.executeModelEgress(ctx, attrs, payload, authHeader)
	if err != nil {
		return nil, err
	}
	return &ModelEgressResult{
		StatusCode:        result.statusCode,
		ResponseBody:      result.responseBody,
		ResponseHeaders:   result.responseHeaders,
		Reason:            result.reason,
		ProviderUsed:      result.providerUsed,
		UpstreamStatus:    result.upstreamStatus,
		FallbackAttempted: result.fallbackAttempted,
	}, nil
}

// ShouldApplyPolicyIntentProjection delegates to the private shouldApplyPolicyIntentProjection.
func (g *Gateway) ShouldApplyPolicyIntentProjection() bool {
	return g.shouldApplyPolicyIntentProjection()
}

// EvaluateToolRequest delegates to the private tool policy, converting the result.
func (g *Gateway) EvaluateToolRequest(req PlaneRequestV2) ToolPlaneEvalResult {
	policy := g.toolPolicy
	if policy == nil {
		policy = newToolPlanePolicyEngine("")
	}
	eval := policy.evaluate(req)
	return ToolPlaneEvalResult{
		Decision:      eval.Decision,
		Reason:        eval.Reason,
		HTTPStatus:    eval.HTTPStatus,
		RequireStepUp: eval.RequireStepUp,
		Metadata:      eval.Metadata,
	}
}

// LogPlaneDecision delegates to the private logPlaneDecision.
func (g *Gateway) LogPlaneDecision(r *http.Request, decision PlaneDecisionV2, httpStatus int) {
	g.logPlaneDecision(r, decision, httpStatus)
}

// AuditLog writes an audit event via the gateway's auditor.
func (g *Gateway) AuditLog(event middleware.AuditEvent) {
	if g != nil && g.auditor != nil {
		g.auditor.Log(event)
	}
}

// WriteGatewayError writes a structured v24 gateway error response.
func (g *Gateway) WriteGatewayError(w http.ResponseWriter, r *http.Request, httpCode int, errorCode string, message string, middlewareName string, reason ReasonCode, details map[string]any) {
	writeV24GatewayError(w, r, httpCode, errorCode, message, middlewareName, reason, details)
}

// ValidateAndConsumeApproval validates and consumes a step-up approval token.
func (g *Gateway) ValidateAndConsumeApproval(token string, scope middleware.ApprovalScope) (*middleware.ApprovalCapabilityClaims, error) {
	return g.approvalCapabilities.ValidateAndConsume(token, scope)
}

// HasApprovalService returns true if the approval capabilities service is available.
func (g *Gateway) HasApprovalService() bool {
	return g.approvalCapabilities != nil
}

// ExecuteMessagingEgress delegates to the private executeMessagingEgress.
func (g *Gateway) ExecuteMessagingEgress(ctx context.Context, attrs map[string]string, payload []byte, authHeader string) (*MessagingEgressResult, error) {
	return g.executeMessagingEgress(ctx, attrs, payload, authHeader)
}

// RedeemSPIKESecret parses and redeems a SPIKE token string, returning
// the resolved secret value. Used by port adapters for per-message
// token resolution (WS frames bypass the HTTP middleware chain).
func (g *Gateway) RedeemSPIKESecret(ctx context.Context, tokenStr string) (string, error) {
	token, err := middleware.ParseSPIKEToken(tokenStr)
	if err != nil {
		return "", err
	}
	if g.spikeRedeemer == nil {
		return "", fmt.Errorf("no SPIKE redeemer configured")
	}
	secret, err := g.spikeRedeemer.RedeemSecret(ctx, token)
	if err != nil {
		return "", err
	}
	return secret.Value, nil
}

// ValidateConnector checks connector conformance via the CCA runtime check.
// Returns (allowed, reason). If no CCA is configured, all connectors are allowed.
func (g *Gateway) ValidateConnector(connectorID, signature string) (bool, string) {
	if g.cca == nil {
		return true, "no_cca_configured"
	}
	allowed, reason, _ := g.cca.runtimeCheck(connectorID, signature)
	return allowed, reason
}

// ScanContent delegates to the DLP scanner, exposing it to port adapters
// for inbound content scanning (OC-di1n).
func (g *Gateway) ScanContent(content string) middleware.ScanResult {
	if g.dlpScanner == nil {
		return middleware.ScanResult{}
	}
	return g.dlpScanner.Scan(content)
}

// TrustedAgentDLPProvider is an optional interface that port adapters can
// implement to register SPIFFE IDs whose system prompt content should bypass
// DLP scanning. User messages are always scanned.
// OC-xj4w: Port-scoped trusted agent DLP bypass.
type TrustedAgentDLPProvider interface {
	TrustedAgentDLPEntries() []middleware.TrustedAgentDLPEntry
}

// RegisterPort adds a PortAdapter to the gateway's dispatch chain and injects
// the adapter's route authorizations into the OPA engine's data store.
func (g *Gateway) RegisterPort(adapter PortAdapter) {
	g.portAdapters = append(g.portAdapters, adapter)

	// Inject port route authorizations into the OPA engine so the core policy
	// can grant destination_allowed for port-claimed routes.
	if routes := adapter.RouteAuthorizations(); len(routes) > 0 {
		opaRoutes := make([]middleware.PortRouteAuth, len(routes))
		for i, r := range routes {
			opaRoutes[i] = middleware.PortRouteAuth{
				Path:       r.Path,
				PathPrefix: r.PathPrefix,
				Methods:    r.Methods,
				AuthModel:  r.AuthModel,
			}
		}
		if err := g.opa.RegisterPortRouteAuthorizations(opaRoutes); err != nil {
			slog.Warn("failed to register port route authorizations",
				"port", adapter.Name(), "error", err)
		}
	}

	// OC-xj4w: Collect trusted agent DLP entries from port adapters that
	// implement the TrustedAgentDLPProvider interface. These entries allow
	// system prompt content to bypass DLP scanning for trusted SPIFFE IDs.
	if provider, ok := adapter.(TrustedAgentDLPProvider); ok {
		entries := provider.TrustedAgentDLPEntries()
		if len(entries) > 0 {
			if g.trustedAgentDLP == nil {
				g.trustedAgentDLP = &middleware.TrustedAgentDLPConfig{}
			}
			g.trustedAgentDLP.Agents = append(g.trustedAgentDLP.Agents, entries...)
			slog.Info("registered trusted agent DLP entries",
				"port", adapter.Name(), "count", len(entries))
		}
	}
}
