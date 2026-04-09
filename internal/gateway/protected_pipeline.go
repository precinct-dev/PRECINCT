// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

func (g *Gateway) protectedHandler() http.Handler {
	proxyWithResponseFirewall := middleware.ResponseFirewall(
		g.proxyHandler(),
		g.registry,
		g.handleStore,
		g.config.HandleTTL,
	)

	return g.buildProtectedPipeline(proxyWithResponseFirewall)
}

func (g *Gateway) buildProtectedPipeline(inner http.Handler) http.Handler {
	handler := http.Handler(inner)

	// Apply middleware in reverse order (innermost first).
	handler = middleware.TokenSubstitution(handler, g.spikeRedeemer, g.auditor, middleware.NewToolRegistryScopeResolver(g.registry))
	handler = middleware.CircuitBreakerMiddleware(handler, g.circuitBreaker)
	handler = middleware.RateLimitMiddleware(handler, g.rateLimiter)
	handler = middleware.DeepScanMiddleware(handler, g.deepScanner, g.riskConfig, g.trustedAgentDLP)

	if g.extensionRegistry != nil {
		handler = middleware.ExtensionSlot(handler, g.extensionRegistry, middleware.SlotPostAnalysis, g.auditor)
	}

	handler = middleware.StepUpGating(handler, g.groqGuardClient, g.destinationAllowlist, g.riskConfig, g.registry, g.auditor, g.approvalCapabilities)
	handler = middleware.SessionContextMiddleware(handler, g.sessionContext)

	if g.extensionRegistry != nil {
		handler = middleware.ExtensionSlot(handler, g.extensionRegistry, middleware.SlotPostInspection, g.auditor)
	}

	if g.trustedAgentDLP != nil && len(g.trustedAgentDLP.Agents) > 0 {
		handler = middleware.DLPMiddlewareWithTrustedAgents(handler, g.dlpScanner, g.trustedAgentDLP, g.dlpPolicy())
	} else {
		handler = middleware.DLPMiddleware(handler, g.dlpScanner, g.dlpPolicy())
	}

	handler = middleware.OPAPolicy(handler, g.opa)

	if g.extensionRegistry != nil {
		handler = middleware.ExtensionSlot(handler, g.extensionRegistry, middleware.SlotPostAuthz, g.auditor)
	}

	handler = middleware.ToolRegistryVerify(
		handler,
		g.registry,
		g.observedToolHashes,
		g.toolHashRefresher(),
		g.toolRegistryVerifyOptions()...,
	)
	handler = middleware.AuditLog(handler, g.auditor)
	handler = middleware.PrincipalHeaders(handler, g.config.SPIFFETrustDomain, g.config.SPIFFEMode)
	handler = middleware.SPIFFEAuth(handler, g.config.SPIFFEMode, g.spiffeAuthOptions()...)
	handler = middleware.BodyCapture(handler)
	handler = middleware.RequestSizeLimit(handler, g.config.MaxRequestSizeBytes)
	handler = middleware.RequestMetrics(handler)
	handler = middleware.RuntimeProfile(handler, g.config.SPIFFEMode, g.config.EnforcementProfile)

	return handler
}

func (g *Gateway) toolHashRefresher() middleware.ObservedToolHashRefresher {
	if g.config.MCPTransportMode == "mcp" {
		return g.refreshObservedToolHashes
	}
	return nil
}

func (g *Gateway) toolRegistryVerifyOptions() []middleware.ToolRegistryVerifyOption {
	failClosedObservedHash := g.enforcementProfile != nil && g.enforcementProfile.StartupGateMode == "strict"
	dsPolicy := g.config.UnknownDataSourcePolicy
	if dsPolicy == "" {
		dsPolicy = "flag"
	}

	return []middleware.ToolRegistryVerifyOption{
		middleware.WithObservedHashFailClosed(failClosedObservedHash),
		middleware.WithDataSourceVerification(newHTTPDataSourceFetcher(g.destinationAllowlist), dsPolicy),
	}
}

func (g *Gateway) spiffeAuthOptions() []middleware.SPIFFEAuthOption {
	var opts []middleware.SPIFFEAuthOption

	if g.oauthJWTConfig != nil {
		opts = append(opts, middleware.WithOAuthJWTConfig(g.oauthJWTConfig, g.config.SPIFFETrustDomain))
	}

	if g.tokenExchangeConfig != nil {
		signingKey := g.tokenExchangeConfig.signingKey
		opts = append(opts, middleware.WithExchangeTokenValidator(
			func(token string) (*middleware.ExchangeTokenClaims, error) {
				claims, err := ValidateExchangeToken(token, signingKey)
				if err != nil {
					return nil, err
				}
				return &middleware.ExchangeTokenClaims{
					Sub:        claims.Sub,
					AuthMethod: claims.PrecinctAuthMethod,
				}, nil
			},
		))
	}

	return opts
}
