package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/mcpclient"
	"github.com/example/agentic-security-poc/internal/gateway/middleware"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Gateway represents the MCP security gateway
type Gateway struct {
	config                     *Config
	proxy                      *httputil.ReverseProxy
	auditor                    *middleware.Auditor
	opa                        *middleware.OPAEngine
	registry                   *middleware.ToolRegistry
	dlpScanner                 middleware.DLPScanner
	deepScanner                *middleware.DeepScanner
	sessionContext             *middleware.SessionContext
	rateLimiter                *middleware.RateLimiter
	circuitBreaker             *middleware.CircuitBreaker
	handleStore                *HandleStore                     // RFA-qq0.16: response firewall data handle cache
	groqGuardClient            middleware.GroqGuardClient       // RFA-qq0.17: guard model client for step-up gating
	destinationAllowlist       *middleware.DestinationAllowlist // RFA-qq0.17: destination allowlist
	riskConfig                 *middleware.RiskConfig           // RFA-qq0.17: risk scoring thresholds
	approvalCapabilities       *middleware.ApprovalCapabilityService
	uiCapabilityGating         *UICapabilityGating               // RFA-j2d.1: MCP-UI capability gating
	uiResourceControls         *UIResourceControls               // RFA-j2d.2: UI resource content controls
	uiResponseProcessor        *UIResponseProcessor              // RFA-j2d.6: UI response processing pipeline
	observedToolHashes         *middleware.ObservedToolHashCache // RFA-6fse.4: gateway-owned observed tool metadata hashes
	spikeRedeemer              middleware.SecretRedeemer         // RFA-a2y.1: SPIKE Nexus or POC secret redeemer
	sessionStore               middleware.SessionStore           // RFA-hh5.1: session persistence store (InMemory or KeyDB)
	spiffeTLS                  *SPIFFETLSConfig                  // RFA-8z8.1: SPIFFE mTLS config (nil in dev mode)
	registryStop               func()                            // RFA-dh9: stop function for registry fsnotify watcher
	mcpTransport               mcpclient.Transport               // RFA-0dz: MCP transport (lazy init, auto-detected: Streamable HTTP or Legacy SSE)
	mcpTransportMu             sync.Mutex                        // RFA-9ol: protects lazy initialization of mcpTransport
	mcpRequestIDCounter        uint64                            // RFA-l6h6.7.3: monotonic fallback JSON-RPC request ID generator
	modelPlanePolicy           *modelPlanePolicyEngine           // RFA-owgw.2: model plane policy enforcement
	ingressPolicy              *ingressPlanePolicyEngine         // RFA-owgw.3: ingress plane admission controls
	contextPolicy              *contextPlanePolicyEngine         // RFA-owgw.5: context and memory admission governance
	loopPolicy                 *loopPlanePolicyEngine            // RFA-owgw.4: loop plane immutable external limits
	toolPolicy                 *toolPlanePolicyEngine            // RFA-owgw.6: tool plane protocol adapters and capability registry v2
	rlmPolicy                  *rlmGovernanceEngine              // RFA-owgw.11: recursive language model governance
	breakGlass                 *breakGlassManager                // RFA-l6h6.1.5: bounded break-glass emergency overrides
	enforcementProfile         *enforcementProfileRuntime        // RFA-l6h6.1.6: startup-constrained runtime enforcement profile
	dlpRuleOps                 *dlpRuleOpsManager                // RFA-owgw.7: DLP RuleOps lifecycle manager
	cca                        *connectorConformanceAuthority    // RFA-l6h6.1.2: connector conformance authority
	ingressReplayGuard         *ingressReplayGuard               // RFA-l6h6.2.2: ingress replay/freshness guard
	adminAuthzAllowedSPIFFEIDs map[string]struct{}               // explicit SPIFFE allowlist for /admin/* authorization
}

// New creates a new gateway instance
func New(cfg *Config) (*Gateway, error) {
	enforcementProfile, err := resolveEnforcementProfile(cfg)
	if err != nil {
		return nil, err
	}
	if err := enforcementProfile.export(cfg.ProfileMetadataExportPath); err != nil {
		return nil, fmt.Errorf("failed to export enforcement profile metadata: %w", err)
	}

	// Parse upstream URL
	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	// Create components
	auditor, err := middleware.NewAuditor(cfg.AuditLogPath, cfg.OPAPolicyPath, cfg.ToolRegistryConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create auditor: %w", err)
	}
	opa, err := middleware.NewOPAEngine(cfg.OPAPolicyDir, middleware.OPAEngineConfig{
		AllowedBasePath: cfg.AllowedBasePath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA engine: %w", err)
	}
	registry, err := middleware.NewToolRegistry(cfg.ToolRegistryConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create tool registry: %w", err)
	}
	dlpRuleOps, dlpScanner, err := newDLPRuleOpsManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DLP RuleOps manager: %w", err)
	}
	deepScanner := middleware.NewDeepScannerWithConfig(middleware.DeepScannerConfig{
		APIKey:       cfg.GuardAPIKey,
		Timeout:      time.Duration(cfg.DeepScanTimeout) * time.Second,
		FallbackMode: cfg.DeepScanFallback,
		Auditor:      auditor,
		Endpoint:     cfg.GuardModelEndpoint,
		ModelName:    cfg.GuardModelName,
	})
	observedToolHashes := middleware.NewObservedToolHashCache(5 * time.Minute)
	// RFA-hh5.1: Select session store based on KeyDB availability.
	// RFA-hh5.2: Also select rate limit store. Both share the same redis client
	// when KeyDB is available, enabling distributed session persistence and
	// distributed rate limiting from a single connection pool.
	// RFA-8z8.2: In SPIFFE_MODE=prod, the KeyDB client uses TLS on port 6380.
	// The URL is converted from redis:// to rediss:// and port 6379 to 6380.
	// TLS config uses the same SPIRE X509Source as the gateway's server TLS
	// (set later by EnableSPIFFETLS). In New(), we use the converted URL; the
	// TLS config is applied in EnableKeyDBTLS() after SPIRE is connected.
	var sessionStore middleware.SessionStore
	var rateLimitStore middleware.RateLimitStore
	if cfg.KeyDBURL != "" {
		keyDBURL := KeyDBURLForMode(cfg.KeyDBURL, cfg.SPIFFEMode)
		redisClient := middleware.NewKeyDBClient(keyDBURL, cfg.KeyDBPoolMin, cfg.KeyDBPoolMax)
		sessionStore = middleware.NewKeyDBStoreFromClient(redisClient, cfg.SessionTTL)
		rateLimitStore = middleware.NewKeyDBRateLimitStore(redisClient)
	} else {
		sessionStore = middleware.NewInMemoryStore()
		rateLimitStore = middleware.NewInMemoryRateLimitStore()
	}
	sessionContext := middleware.NewSessionContext(sessionStore)
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimitRPM, cfg.RateLimitBurst, rateLimitStore)

	// Create circuit breaker with audit logging for state transitions
	circuitBreaker := middleware.NewCircuitBreaker(middleware.CircuitBreakerConfig{
		FailureThreshold: cfg.CircuitFailureThreshold,
		ResetTimeout:     time.Duration(cfg.CircuitResetTimeout) * time.Second,
		SuccessThreshold: cfg.CircuitSuccessThreshold,
	}, func(from, to middleware.CircuitState) {
		auditor.Log(middleware.AuditEvent{
			Action: "circuit_breaker_transition",
			Result: fmt.Sprintf("%s->%s", from, to),
		})
	})

	// RFA-qq0.16: Create handle store for response firewall
	handleStore := NewHandleStore(time.Duration(cfg.HandleTTL) * time.Second)

	// RFA-qq0.17: Create step-up gating components
	groqGuardClient := middleware.NewGroqGuardClient(cfg.GroqAPIKey, time.Duration(cfg.DeepScanTimeout)*time.Second)

	// Load destination allowlist (fall back to defaults if file not found)
	var destinationAllowlist *middleware.DestinationAllowlist
	if cfg.DestinationsConfigPath != "" {
		dal, err := middleware.LoadDestinationAllowlist(cfg.DestinationsConfigPath)
		if err != nil {
			// Fall back to defaults if config file not found
			log.Printf("WARNING: failed to load destination allowlist from %s: %v (using built-in defaults)", cfg.DestinationsConfigPath, err)
			destinationAllowlist = middleware.DefaultDestinationAllowlist()
		} else {
			log.Printf(
				"Destination allowlist loaded from %s (entries=%d, api.groq.com_allowed=%t)",
				cfg.DestinationsConfigPath,
				len(dal.Allowed),
				dal.IsAllowed("api.groq.com"),
			)
			destinationAllowlist = dal
		}
	} else {
		log.Printf("WARNING: DESTINATIONS_CONFIG_PATH is empty; using built-in destination allowlist defaults")
		destinationAllowlist = middleware.DefaultDestinationAllowlist()
	}

	// Load risk thresholds (fall back to defaults if file not found)
	var riskConfig *middleware.RiskConfig
	if cfg.RiskThresholdsPath != "" {
		rc, err := middleware.LoadRiskConfig(cfg.RiskThresholdsPath)
		if err != nil {
			// Fall back to defaults if config file not found
			riskConfig = middleware.DefaultRiskConfig()
		} else {
			riskConfig = rc
		}
	} else {
		riskConfig = middleware.DefaultRiskConfig()
	}
	approvalCapabilities := middleware.NewApprovalCapabilityService(
		cfg.ApprovalSigningKey,
		time.Duration(cfg.ApprovalDefaultTTL)*time.Second,
		time.Duration(cfg.ApprovalMaxTTL)*time.Second,
		auditor,
	)

	// RFA-j2d.1: Ensure UIConfig exists (default to secure defaults if nil)
	uiConfig := cfg.UI
	if uiConfig == nil {
		uiConfig = UIConfigDefaults()
	}

	// RFA-j2d.1: Create UI capability gating
	uiCapabilityGating := NewUICapabilityGating(uiConfig, cfg.UICapabilityGrantsPath)

	// RFA-j2d.2: Create UI resource controls
	uiResourceControls := NewUIResourceControls(uiConfig)

	// RFA-j2d.6: Create UI response processor (integrates j2d.1, j2d.2, j2d.3, j2d.5)
	uiResponseProcessor := NewUIResponseProcessor(
		uiCapabilityGating,
		uiResourceControls,
		registry,
		uiConfig,
		auditor,
	)

	// RFA-a2y.1 + RFA-uln: Create secret redeemer (SPIKE Nexus for production, POC for dev/test).
	// SPIKE Nexus requires mTLS for ALL endpoints (including secret get/put).
	// When SPIFFE_ENDPOINT_SOCKET is set (Docker Compose), we create an X509Source
	// from the SPIRE Workload API so the redeemer presents a valid client cert.
	// NOTE: If SPIKE_NEXUS_URL is configured, we require SPIRE Workload API access.
	// Falling back to InsecureSkipVerify breaks SPIKE's mTLS security model and
	// will deterministically fail with 401 (no client cert presented).
	var spikeRedeemer middleware.SecretRedeemer
	if cfg.SPIKENexusURL != "" {
		if os.Getenv("SPIFFE_ENDPOINT_SOCKET") == "" {
			return nil, fmt.Errorf("SPIKE_NEXUS_URL is set but SPIFFE_ENDPOINT_SOCKET is empty; cannot perform SPIKE Nexus mTLS")
		}

		var spikeX509 *workloadapi.X509Source

		// Obtain an X509Source for SPIKE Nexus mTLS. We keep the source for the
		// gateway lifetime (closed via redeemer.Close()) so SVID rotation continues.
		//
		// NewX509Source can return before a workload SVID is available; wait up to
		// a bounded timeout for the first SVID so startup failures are clear.
		x509Src, err := workloadapi.NewX509Source(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to create X509Source for SPIKE Nexus mTLS: %w", err)
		}
		start := time.Now()
		for {
			if svid, err := x509Src.GetX509SVID(); err == nil {
				log.Printf("SPIKE Nexus mTLS: using client SVID %s", svid.ID)
				break
			}
			if time.Since(start) > 30*time.Second {
				_ = x509Src.Close()
				return nil, fmt.Errorf("SPIKE Nexus mTLS: timed out waiting for SPIRE workload SVID (30s)")
			}
			time.Sleep(250 * time.Millisecond)
		}
		spikeX509 = x509Src
		log.Printf("SPIKE Nexus: mTLS configured via SPIRE X509Source")

		// devMode=true when x509Source is nil (no SPIRE agent) -- auto-populate OwnerID.
		// Even with mTLS, SPIKE Nexus v0.8.0 may not return owner metadata,
		// so devMode is always true in the Docker Compose POC.
		spikeRedeemer = middleware.NewSPIKENexusRedeemer(cfg.SPIKENexusURL, spikeX509, true)
	} else {
		// Fallback to POC redeemer (Phase 1 behavior with deterministic mock secrets).
		// NOTE (RFA-7ct): Without SPIKE Nexus, the POC redeemer does not populate
		// OwnerID, so ValidateTokenOwnership will reject tokens with empty OwnerID.
		// This is intentional - production deployments MUST configure SPIKE_NEXUS_URL.
		spikeRedeemer = middleware.NewPOCSecretRedeemer()
	}

	// RFA-lo1.4: Configure cosign-blob attestation for registry hot-reload.
	// When TOOL_REGISTRY_PUBLIC_KEY is set, it should be a path to a PEM file
	// containing an Ed25519 public key. Registry updates will require a valid
	// companion .sig file. When empty (default for dev), updates are accepted
	// without signature verification.
	if cfg.ToolRegistryPublicKey != "" {
		pemData, err := os.ReadFile(cfg.ToolRegistryPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read registry public key from %s: %w", cfg.ToolRegistryPublicKey, err)
		}
		if err := registry.SetPublicKey(pemData); err != nil {
			return nil, fmt.Errorf("failed to set registry public key: %w", err)
		}
		log.Printf("[tool-registry] attestation configured with public key from %s", cfg.ToolRegistryPublicKey)
	}
	if enforcementProfile.StartupGateMode == "strict" {
		reloadResult, err := registry.Reload()
		if err != nil {
			return nil, fmt.Errorf("strict tool registry attestation verification failed: %w", err)
		}
		if !reloadResult.CosignVerified {
			return nil, fmt.Errorf("strict tool registry attestation verification failed: signature verification is mandatory")
		}
		log.Printf("[tool-registry] strict startup attestation passed: %d tools, %d ui_resources",
			reloadResult.ToolCount, reloadResult.UIResourceCount)
	}

	// RFA-dh9: Start fsnotify watcher on tool registry YAML for hot-reload.
	// The watcher runs in a background goroutine and reloads the registry
	// atomically when the file changes. Stop function is stored for Close().
	registryStop, err := registry.Watch()
	if err != nil {
		return nil, fmt.Errorf("failed to start tool registry watcher: %w", err)
	}

	// RFA-m6j.3: Wrap the reverse proxy transport with trace context propagation.
	// This injects traceparent/tracestate headers into every outbound request
	// to the MCP server, enabling cross-service distributed tracing.
	// The base transport is either the default or will be replaced later by
	// EnableSPIFFETLS (which re-wraps with TracingTransport -- see below).
	proxy.Transport = NewTracingTransport(proxy.Transport)

	// RFA-8z8.1: Log which SPIFFE mode is active at startup (AC5)
	log.Printf("SPIFFE mode: %s", cfg.SPIFFEMode)
	log.Printf("enforcement profile: %s (mediation_gate=%t hipaa_prompt_safety_gate=%t)",
		enforcementProfile.Name,
		enforcementProfile.Controls.EnforceModelMediationGate,
		enforcementProfile.Controls.EnforceHIPAAPromptSafety,
	)

	// Start deep scan result processor in background
	go deepScanner.ResultProcessor(context.Background())

	// RFA-0dz: MCP transport creation is deferred to first request (lazy init).
	// DetectTransport will try Streamable HTTP first, then fall back to
	// Legacy SSE, with a deprecation warning for SSE.
	// No transport is created at startup to handle Docker Compose ordering
	// where upstream may not be ready yet.
	modelPlanePolicy := newModelPlanePolicyEngineWithControls(
		enforcementProfile.Controls.EnforceModelMediationGate,
		enforcementProfile.Controls.EnforceHIPAAPromptSafety,
	)
	if err := modelPlanePolicy.loadProviderCatalog(cfg.ModelProviderCatalogPath, cfg.ModelProviderCatalogPublicKey); err != nil {
		if auditor != nil {
			auditor.Log(middleware.AuditEvent{
				Action: "model.provider_catalog.load",
				Result: fmt.Sprintf("status=fail path=%s error=%s", cfg.ModelProviderCatalogPath, err.Error()),
			})
		}
		return nil, fmt.Errorf("failed to load model provider catalog: %w", err)
	}
	if err := verifyGuardArtifactIntegrity(cfg, enforcementProfile.Name, auditor); err != nil {
		return nil, err
	}
	if auditor != nil {
		meta := modelPlanePolicy.catalogMetadata()
		auditor.Log(middleware.AuditEvent{
			Action: "model.provider_catalog.load",
			Result: fmt.Sprintf(
				"status=pass version=%v digest=%v signature_verified=%v path=%s",
				meta["provider_catalog_version"],
				meta["provider_catalog_digest"],
				meta["provider_catalog_signature_verified"],
				cfg.ModelProviderCatalogPath,
			),
		})
	}

	adminAllowlist := cfg.AdminAuthzAllowedSPIFFEIDs
	if len(adminAllowlist) == 0 {
		adminAllowlist = defaultAdminAuthzAllowedSPIFFEIDs()
	}

	return &Gateway{
		config:                     cfg,
		proxy:                      proxy,
		auditor:                    auditor,
		opa:                        opa,
		registry:                   registry,
		dlpScanner:                 dlpScanner,
		deepScanner:                deepScanner,
		sessionContext:             sessionContext,
		rateLimiter:                rateLimiter,
		circuitBreaker:             circuitBreaker,
		handleStore:                handleStore,
		groqGuardClient:            groqGuardClient,
		destinationAllowlist:       destinationAllowlist,
		riskConfig:                 riskConfig,
		approvalCapabilities:       approvalCapabilities,
		uiCapabilityGating:         uiCapabilityGating,
		uiResourceControls:         uiResourceControls,
		uiResponseProcessor:        uiResponseProcessor,
		observedToolHashes:         observedToolHashes,
		spikeRedeemer:              spikeRedeemer,
		sessionStore:               sessionStore,
		registryStop:               registryStop,
		modelPlanePolicy:           modelPlanePolicy,
		ingressPolicy:              newIngressPlanePolicyEngine(),
		contextPolicy:              newContextPlanePolicyEngine(),
		loopPolicy:                 newLoopPlanePolicyEngine(),
		toolPolicy:                 newToolPlanePolicyEngine(cfg.CapabilityRegistryV2Path),
		rlmPolicy:                  newRLMGovernanceEngine(),
		breakGlass:                 newBreakGlassManager(auditor),
		enforcementProfile:         enforcementProfile,
		dlpRuleOps:                 dlpRuleOps,
		cca:                        newConnectorConformanceAuthority(),
		ingressReplayGuard:         newIngressReplayGuard(5*time.Minute, 15*time.Second),
		adminAuthzAllowedSPIFFEIDs: normalizeAdminAuthzAllowlist(adminAllowlist),
	}, nil
}

// Handler returns the HTTP handler with middleware chain
func (g *Gateway) Handler() http.Handler {
	// Build middleware chain in order:
	// 1. Request size limit
	// 2. Body capture
	// 3. SPIFFE auth
	// 4. Audit log
	// 5. Tool registry verify
	// 6. OPA policy
	// 7. DLP scanning
	// 8. Session context (RFA-qq0.15)
	// 9. Step-up gating (RFA-qq0.17: risk scoring + destination check + guard model)
	// 10. Deep scan dispatch (async, after step-up gating)
	// 11. Rate limiting (per-agent token bucket)
	// 12. Circuit breaker (protect upstream from cascading failures)
	// 13. Token substitution hook (SECURITY: LAST before proxy - no middleware sees real secrets)
	// 14. Response firewall (RFA-qq0.16: wraps proxy, intercepts responses before return)
	// 15. Proxy to upstream

	// RFA-qq0.16: Wrap proxy handler with response firewall
	// The response firewall intercepts responses AFTER they come back from upstream
	// but BEFORE they flow back through the middleware chain to the agent
	proxyWithResponseFirewall := middleware.ResponseFirewall(
		g.proxyHandler(),
		g.registry,
		g.handleStore,
		g.config.HandleTTL,
	)

	handler := http.Handler(proxyWithResponseFirewall)

	// Apply middleware in reverse order (innermost first)
	handler = middleware.TokenSubstitution(handler, g.spikeRedeemer, g.auditor, middleware.NewToolRegistryScopeResolver(g.registry))                   // 13 - LAST before proxy (RFA-0gr: dynamic scope)
	handler = middleware.CircuitBreakerMiddleware(handler, g.circuitBreaker)                                                                           // 12
	handler = middleware.RateLimitMiddleware(handler, g.rateLimiter)                                                                                   // 11
	handler = middleware.DeepScanMiddleware(handler, g.deepScanner, g.riskConfig)                                                                      // 10
	handler = middleware.StepUpGating(handler, g.groqGuardClient, g.destinationAllowlist, g.riskConfig, g.registry, g.auditor, g.approvalCapabilities) // 9
	handler = middleware.SessionContextMiddleware(handler, g.sessionContext)                                                                           // 8
	handler = middleware.DLPMiddleware(handler, g.dlpScanner, g.dlpPolicy())                                                                           // 7
	handler = middleware.OPAPolicy(handler, g.opa)                                                                                                     // 6
	var toolHashRefresher middleware.ObservedToolHashRefresher
	if g.config.MCPTransportMode == "mcp" {
		toolHashRefresher = g.refreshObservedToolHashes
	}
	failClosedObservedHash := g.enforcementProfile != nil && g.enforcementProfile.StartupGateMode == "strict"
	handler = middleware.ToolRegistryVerify(
		handler,
		g.registry,
		g.observedToolHashes,
		toolHashRefresher,
		middleware.WithObservedHashFailClosed(failClosedObservedHash),
	) // 5
	handler = middleware.AuditLog(handler, g.auditor)                            // 4
	handler = middleware.SPIFFEAuth(handler, g.config.SPIFFEMode)                // 3
	handler = middleware.BodyCapture(handler)                                    // 2
	handler = middleware.RequestSizeLimit(handler, g.config.MaxRequestSizeBytes) // 1

	// Add endpoints
	mux := http.NewServeMux()
	mux.Handle("/health", http.HandlerFunc(g.healthHandler))
	// Demo-only: allow the demo runner/clients to toggle upstream rugpull mode
	// without direct network access to tool pods (keeps tools ingress restricted
	// to the gateway namespace in k8s). Disabled by default.
	mux.Handle("/__demo__/rugpull/on", http.HandlerFunc(g.demoRugpullToggleHandler(true)))
	mux.Handle("/__demo__/rugpull/off", http.HandlerFunc(g.demoRugpullToggleHandler(false)))
	// RFA-qq0.16: Handle dereference endpoint
	mux.Handle("/data/dereference", g.dataHandleDereferenceHandler())
	mux.Handle("/", handler)

	return mux
}

// proxyHandler proxies requests to upstream MCP server with UI response processing.
// RFA-j2d.1: Capability gating (strip _meta.ui for denied/unapproved servers/tools)
// RFA-j2d.3: CSP and permissions mediation (rewrite _meta.ui.csp and _meta.ui.permissions)
// RFA-j2d.2: Resource controls (content-type, size, scan, hash verification)
// RFA-j2d.5: Registry verification for ui:// resources
// RFA-j2d.6: Unified response processing pipeline (processUpstreamResponse)
//
// This handler intercepts MCP traffic based on request type:
//   - tools/list responses: captured after upstream returns, then processed through
//     processUpstreamResponse which applies capability gating + CSP/permissions mediation
//   - resources/read for ui:// URIs: checked BEFORE proxying via checkUIResourceReadAllowed;
//     on the response path, resource controls and registry verification are applied
//   - all other requests: proxied unchanged
//
// Server and tenant are identified via X-MCP-Server and X-Tenant request headers.
// If not set, "default" is used for both (fail-closed: no grant match = deny mode).
func (g *Gateway) proxyHandler() http.Handler {
	// RFA-m6j.2: Create tracer for proxy span (gateway package)
	proxyTracer := otel.Tracer("mcp-security-gateway", trace.WithInstrumentationVersion("2.0.0"))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.2: Create OTel span for proxy
		ctx, span := proxyTracer.Start(r.Context(), "gateway.proxy",
			trace.WithAttributes(
				attribute.String("mcp.gateway.middleware", "proxy"),
				attribute.String("upstream_url", g.config.UpstreamURL),
			),
		)
		defer span.End()

		// Wrap response writer to capture status code for span and internal route handling.
		proxyRW := &proxyResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Demo-only, fast-path endpoint for deterministic rate-limit proofs.
		//
		// This path is intentionally handled inside the normal middleware chain
		// (see Handler()) so requests still pass through Step 11 rate limiting.
		// We gate it behind the same secure-by-default demo toggle used for rugpull
		// admin endpoints so it is not exposed accidentally in non-demo runs.
		if r.URL.Path == "/__demo__/ratelimit" {
			if g.config == nil || !g.config.DemoRugpullAdminEnabled || g.config.SPIFFEMode != "dev" {
				http.NotFound(w, r)
				span.SetAttributes(
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "demo endpoints disabled"),
				)
				return
			}
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				span.SetAttributes(
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "method not allowed"),
				)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			span.SetAttributes(
				attribute.Int("status_code", http.StatusOK),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "demo ratelimit endpoint"),
			)
			return
		}

		if g.handleConnectorAuthorityEntry(proxyRW, r.WithContext(ctx)) {
			result := "allowed"
			if proxyRW.statusCode >= 400 {
				result = "denied"
			}
			span.SetAttributes(
				attribute.Int("status_code", proxyRW.statusCode),
				attribute.String("mcp.result", result),
				attribute.String("mcp.reason", "connector_conformance_entry"),
				attribute.String("mcp.gateway.middleware", v24MiddlewareConnectorAuth),
				attribute.Int("mcp.gateway.step", v24MiddlewareStep),
				attribute.String("mcp.v24.endpoint", r.URL.Path),
			)
			return
		}

		if g.handleV24AdminEntry(proxyRW, r.WithContext(ctx)) {
			result := "allowed"
			if proxyRW.statusCode >= 400 {
				result = "denied"
			}
			adminMiddleware := adminMiddlewareForPath(r.URL.Path)
			span.SetAttributes(
				attribute.Int("status_code", proxyRW.statusCode),
				attribute.String("mcp.result", result),
				attribute.String("mcp.reason", "v24_admin_entry"),
				attribute.String("mcp.gateway.middleware", adminMiddleware),
				attribute.Int("mcp.gateway.step", v24MiddlewareStep),
				attribute.String("mcp.v24.endpoint", r.URL.Path),
			)
			return
		}

		if g.handleOpenClawWSEntry(proxyRW, r.WithContext(ctx)) {
			result := "allowed"
			if proxyRW.statusCode >= 400 {
				result = "denied"
			}
			span.SetAttributes(
				attribute.Int("status_code", proxyRW.statusCode),
				attribute.String("mcp.result", result),
				attribute.String("mcp.reason", "openclaw_ws_wrapper"),
				attribute.String("mcp.gateway.middleware", v24MiddlewareOpenClawWS),
				attribute.Int("mcp.gateway.step", v24MiddlewareStep),
				attribute.String("mcp.v24.endpoint", r.URL.Path),
			)
			return
		}

		if g.handleOpenClawHTTPEntry(proxyRW, r.WithContext(ctx)) {
			result := "allowed"
			if proxyRW.statusCode >= 400 {
				result = "denied"
			}
			span.SetAttributes(
				attribute.Int("status_code", proxyRW.statusCode),
				attribute.String("mcp.result", result),
				attribute.String("mcp.reason", "openclaw_http_wrapper"),
				attribute.String("mcp.gateway.middleware", v24MiddlewareOpenClawHTTP),
				attribute.Int("mcp.gateway.step", v24MiddlewareStep),
				attribute.String("mcp.v24.endpoint", r.URL.Path),
			)
			return
		}

		// Phase 3 walking skeleton: internal plane entry points are served
		// from the gateway boundary under /v1/* and still pass the full middleware chain.
		if g.handlePhase3PlaneEntry(proxyRW, r.WithContext(ctx)) {
			result := "allowed"
			if proxyRW.statusCode >= 400 {
				result = "denied"
			}
			span.SetAttributes(
				attribute.Int("status_code", proxyRW.statusCode),
				attribute.String("mcp.result", result),
				attribute.String("mcp.reason", "phase3_plane_entry"),
				attribute.String("mcp.gateway.middleware", v24MiddlewarePhase3Plane),
				attribute.Int("mcp.gateway.step", v24MiddlewareStep),
				attribute.String("mcp.v24.endpoint", r.URL.Path),
			)
			return
		}
		// OpenAI-compatible model egress path. This route keeps external model calls
		// inside UASGS policy controls while remaining SDK/framework friendly.
		if g.handleModelCompatEntry(proxyRW, r.WithContext(ctx)) {
			result := "allowed"
			if proxyRW.statusCode >= 400 {
				result = "denied"
			}
			span.SetAttributes(
				attribute.Int("status_code", proxyRW.statusCode),
				attribute.String("mcp.result", result),
				attribute.String("mcp.reason", "phase3_model_egress"),
				attribute.String("mcp.gateway.middleware", v24MiddlewareModelCompat),
				attribute.Int("mcp.gateway.step", v24MiddlewareStep),
				attribute.String("mcp.v24.endpoint", r.URL.Path),
			)
			return
		}

		// Extract MCP method from request body (already captured by BodyCapture middleware)
		mcpMethod, mcpParams, mcpRequestID := g.extractMCPMethodAndParams(ctx)
		reqInfo := NewMCPRequestInfo(mcpMethod, mcpParams)

		server := r.Header.Get("X-MCP-Server")
		if server == "" {
			server = "default"
		}
		tenant := r.Header.Get("X-Tenant")
		if tenant == "" {
			tenant = "default"
		}

		// RFA-9ol: Branch on transport mode.
		// "mcp" uses the MCP Streamable HTTP transport for JSON-RPC.
		// Any other value (including "proxy" and empty string) uses the legacy
		// httputil.ReverseProxy path with full UI processing for backward compat.
		if g.config.MCPTransportMode == "mcp" {
			// MCP path: translate SDK request -> MCP JSON-RPC -> upstream -> response
			g.handleMCPRequest(proxyRW, r.WithContext(ctx), mcpMethod, mcpParams, mcpRequestID, server, tenant)
		} else {
			// Legacy path: full UI response processing pipeline
			g.processUpstreamResponse(proxyRW, r.WithContext(ctx), reqInfo, server, tenant)
		}

		span.SetAttributes(
			attribute.Int("status_code", proxyRW.statusCode),
			attribute.String("mcp.result", "allowed"),
			attribute.String("mcp.reason", "proxied"),
		)
	})
}

// proxyResponseWriter wraps http.ResponseWriter to capture status code for proxy span
type proxyResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (prw *proxyResponseWriter) WriteHeader(code int) {
	if !prw.written {
		prw.statusCode = code
		prw.written = true
	}
	prw.ResponseWriter.WriteHeader(code)
}

func (prw *proxyResponseWriter) Write(b []byte) (int, error) {
	if !prw.written {
		prw.statusCode = http.StatusOK
		prw.written = true
	}
	return prw.ResponseWriter.Write(b)
}

func (prw *proxyResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(prw.ResponseWriter).Hijack()
}

func (prw *proxyResponseWriter) Flush() {
	_ = http.NewResponseController(prw.ResponseWriter).Flush()
}

// handleMCPRequest translates an SDK-format request into an MCP JSON-RPC request,
// sends it via the auto-detected Transport, and writes the response back as JSON.
// RFA-9ol: Walking skeleton -- handles tools/call and any other MCP method.
// RFA-0dz: Uses Transport interface (Streamable HTTP or Legacy SSE).
// RFA-xhr: Adds per-request timeouts, retry with backoff on session loss,
// response validation, and size limits.
//
// Lazy initialization: the MCP transport is initialized on the first request,
// not at startup, to handle Docker Compose ordering where upstream may not be
// ready yet.
//
// ALL errors use middleware.WriteGatewayError() with proper GatewayError structs.
func (g *Gateway) handleMCPRequest(
	w http.ResponseWriter,
	r *http.Request,
	method string,
	params map[string]interface{},
	clientRequestID *int,
	server, tenant string,
) {
	ctx := r.Context()

	// RFA-6fse.2: Request-side enforcement for ui:// resource reads MUST occur
	// before *any* upstream contact (including MCP transport initialization).
	var resourceURI string
	isUIResourceRead := false
	if method == "resources/read" && params != nil {
		if uriRaw, ok := params["uri"]; ok {
			if uri, ok := uriRaw.(string); ok && strings.HasPrefix(uri, "ui://") {
				resourceURI = uri
				isUIResourceRead = true
				if !g.checkUIResourceReadAllowed(server, tenant, resourceURI) {
					middleware.WriteGatewayError(w, r, http.StatusForbidden, middleware.GatewayError{
						Code:        middleware.ErrUICapabilityDenied,
						Message:     "UI resource reads are not permitted for this server/tenant.",
						Middleware:  "ui_capability_gating",
						Remediation: "Grant UI capabilities for this server/tenant in ui_capability_grants.yaml.",
					})
					return
				}
			}
		}
	}

	// Lazy init: ensure MCP transport is initialized
	if err := g.ensureMCPTransportInitialized(ctx); err != nil {
		middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
			Code:        middleware.ErrMCPTransportFailed,
			Message:     fmt.Sprintf("MCP transport initialization failed: %v", err),
			Middleware:  "mcp_transport",
			Remediation: "Ensure the upstream MCP server is running and accessible at " + g.config.UpstreamURL,
		})
		return
	}

	rpcID := g.nextMCPRequestID()
	if clientRequestID != nil {
		rpcID = *clientRequestID
	}

	// Build JSON-RPC request from the extracted method and params
	rpcReq := &mcpclient.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      rpcID,
		Method:  method,
		Params:  params,
	}

	// RFA-xhr: Apply per-request timeout (default 30s when config is zero)
	requestTimeoutSec := g.config.MCPRequestTimeout
	if requestTimeoutSec <= 0 {
		requestTimeoutSec = 30
	}
	requestTimeout := time.Duration(requestTimeoutSec) * time.Second
	sendCtx, sendCancel := context.WithTimeout(ctx, requestTimeout)
	defer sendCancel()

	// RFA-xhr: Send with retry and backoff on session loss.
	// The reinitFn re-initializes the transport after session loss.
	retryCfg := mcpclient.DefaultRetryConfig()
	reinitFn := func(retryCtx context.Context) error {
		g.mcpTransportMu.Lock()
		g.mcpTransport = nil
		g.mcpTransportMu.Unlock()
		return g.ensureMCPTransportInitialized(retryCtx)
	}

	rpcResp, err := mcpclient.SendWithRetry(sendCtx, g.mcpTransport, rpcReq, retryCfg, reinitFn)
	if err != nil {
		middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
			Code:        middleware.ErrMCPTransportFailed,
			Message:     fmt.Sprintf("MCP request failed: %v", err),
			Middleware:  "mcp_transport",
			Remediation: "Check upstream MCP server availability and network connectivity.",
		})
		return
	}

	// RFA-xhr: Validate response structure
	if validationErr := mcpclient.ValidateResponse(rpcReq, rpcResp); validationErr != nil {
		middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
			Code:        middleware.ErrMCPInvalidResponse,
			Message:     fmt.Sprintf("Invalid MCP response: %v", validationErr),
			Middleware:  "mcp_transport",
			Remediation: "The upstream MCP server returned an invalid JSON-RPC response.",
		})
		return
	}

	// Check for JSON-RPC error in the response
	if rpcResp.Error != nil {
		middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
			Code:    middleware.ErrMCPRequestFailed,
			Message: fmt.Sprintf("MCP server error: code=%d message=%s", rpcResp.Error.Code, rpcResp.Error.Message),
			Details: map[string]any{
				"jsonrpc_error_code": rpcResp.Error.Code,
				"jsonrpc_error_msg":  rpcResp.Error.Message,
			},
			Middleware:  "mcp_transport",
			Remediation: "The upstream MCP server returned an error. Check the error details.",
		})
		return
	}

	// RFA-xhr: Enforce response size limit using MaxRequestSizeBytes
	if rpcResp.Result != nil && int64(len(rpcResp.Result)) > g.config.MaxRequestSizeBytes {
		middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
			Code:    middleware.ErrMCPInvalidResponse,
			Message: fmt.Sprintf("MCP response result exceeds maximum size of %d bytes (got %d bytes)", g.config.MaxRequestSizeBytes, len(rpcResp.Result)),
			Details: map[string]any{
				"max_bytes":    g.config.MaxRequestSizeBytes,
				"actual_bytes": len(rpcResp.Result),
			},
			Middleware:  "mcp_transport",
			Remediation: "The upstream MCP server returned a response larger than MAX_REQUEST_SIZE_BYTES.",
		})
		return
	}

	// RFA-6fse.2: Response-side UI enforcement in MCP transport mode.
	// For tools/list: apply full tools/list processing pipeline to the JSON-RPC response.
	// For resources/read ui://: apply UI resource controls + registry verification to the
	// extracted resource content and block on failure.
	if method == "tools/list" {
		raw, err := json.Marshal(rpcResp)
		if err != nil {
			middleware.WriteGatewayError(w, r, http.StatusInternalServerError, middleware.GatewayError{
				Code:        middleware.ErrMCPInvalidResponse,
				Message:     fmt.Sprintf("Failed to serialize MCP response: %v", err),
				Middleware:  "mcp_transport",
				Remediation: "This is an internal error. Check gateway logs for details.",
			})
			return
		}
		// RFA-6fse.4: Apply rug-pull stripping + seed observed hash cache in MCP transport mode too.
		raw = g.filterAndCacheToolsListResponse(r, raw, server)

		respBytes := g.uiResponseProcessor.ProcessToolsListResponse(raw, server, tenant)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
		return
	}

	if isUIResourceRead {
		content, contentType, err := extractUIResourceFromMCPResult(rpcResp.Result, resourceURI)
		if err != nil {
			middleware.WriteGatewayError(w, r, http.StatusBadGateway, middleware.GatewayError{
				Code:        middleware.ErrMCPInvalidResponse,
				Message:     fmt.Sprintf("Invalid resources/read result: %v", err),
				Middleware:  "mcp_transport",
				Remediation: "The upstream MCP server returned an invalid resources/read result.",
			})
			return
		}

		allowed, reason, _ := g.uiResponseProcessor.ProcessUIResourceResponse(
			content, contentType, server, tenant, resourceURI,
		)
		if !allowed {
			middleware.WriteGatewayError(w, r, http.StatusForbidden, middleware.GatewayError{
				Code:        middleware.ErrUIResourceBlocked,
				Message:     fmt.Sprintf("UI resource blocked: %s", reason),
				Middleware:  "ui_resource_controls",
				Details:     map[string]any{"reason": reason},
				Remediation: "Ensure the resource passes content-type, size, scan, and hash verification.",
			})
			return
		}
	}

	// Write the JSON-RPC response back to the client
	w.Header().Set("Content-Type", "application/json")
	respBytes, err := json.Marshal(rpcResp)
	if err != nil {
		middleware.WriteGatewayError(w, r, http.StatusInternalServerError, middleware.GatewayError{
			Code:        middleware.ErrMCPInvalidResponse,
			Message:     fmt.Sprintf("Failed to serialize MCP response: %v", err),
			Middleware:  "mcp_transport",
			Remediation: "This is an internal error. Check gateway logs for details.",
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

// extractUIResourceFromMCPResult extracts resource content bytes and mimeType from a
// resources/read JSON-RPC result. For MCP spec 2025-03-26, resources/read returns:
//
//	{"contents":[{"uri":"ui://...","mimeType":"text/html;profile=mcp-app","text":"..."}]}
//
// The gateway uses the extracted bytes + mimeType to run the same UI resource
// controls used by proxy mode.
func extractUIResourceFromMCPResult(result json.RawMessage, resourceURI string) ([]byte, string, error) {
	if len(result) == 0 {
		return nil, "", fmt.Errorf("missing result")
	}

	type resourceContent struct {
		URI      string  `json:"uri"`
		MimeType string  `json:"mimeType"`
		Text     *string `json:"text,omitempty"`
		Blob     *string `json:"blob,omitempty"`
	}
	var rr map[string]any
	if err := json.Unmarshal(result, &rr); err != nil {
		return nil, "", fmt.Errorf("failed to parse result: %w", err)
	}

	// Extract mimeType (may exist at top-level or per entry).
	mimeType, _ := rr["mimeType"].(string)

	// Spec-conformant: result.contents = []{ uri, mimeType, text|blob }
	var contents []resourceContent
	if raw, ok := rr["contents"]; ok {
		b, _ := json.Marshal(raw)
		_ = json.Unmarshal(b, &contents)
	} else if raw, ok := rr["content"]; ok {
		// Permissive fallback: some implementations may use "content" instead of "contents".
		b, _ := json.Marshal(raw)
		_ = json.Unmarshal(b, &contents)
	}

	// Prefer an entry whose uri matches the requested resourceURI.
	var chosen *resourceContent
	for i := range contents {
		if contents[i].URI != "" && contents[i].URI == resourceURI {
			chosen = &contents[i]
			break
		}
	}
	if chosen == nil && len(contents) > 0 {
		chosen = &contents[0]
	}

	if chosen != nil && chosen.MimeType != "" {
		mimeType = chosen.MimeType
	}

	if chosen != nil {
		if chosen.Text != nil {
			return []byte(*chosen.Text), mimeType, nil
		}
		if chosen.Blob != nil {
			decoded, err := base64.StdEncoding.DecodeString(*chosen.Blob)
			if err != nil {
				return nil, mimeType, fmt.Errorf("invalid base64 blob: %w", err)
			}
			return decoded, mimeType, nil
		}
	}

	// Non-spec fallbacks (best-effort)
	if txt, ok := rr["text"].(string); ok && txt != "" {
		return []byte(txt), mimeType, nil
	}
	if blob, ok := rr["blob"].(string); ok && blob != "" {
		decoded, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			return nil, mimeType, fmt.Errorf("invalid base64 blob: %w", err)
		}
		return decoded, mimeType, nil
	}
	if content, ok := rr["content"].(string); ok && content != "" {
		return []byte(content), mimeType, nil
	}

	return nil, mimeType, fmt.Errorf("no resource contents found")
}

// refreshObservedToolHashes performs an internal tools/list call upstream and
// computes per-tool hashes over (description + canonicalized input schema).
//
// RFA-6fse.4: Used by ToolRegistryVerify to enforce rug-pull protection without
// requiring client-supplied tool_hash.
func (g *Gateway) refreshObservedToolHashes(ctx context.Context, server string) (map[string]string, error) {
	if err := g.ensureMCPTransportInitialized(ctx); err != nil {
		return nil, err
	}

	rpcReq := &mcpclient.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      g.nextMCPRequestID(),
		Method:  "tools/list",
		Params:  map[string]any{},
	}

	retryCfg := mcpclient.DefaultRetryConfig()
	reinitFn := func(retryCtx context.Context) error {
		g.mcpTransportMu.Lock()
		g.mcpTransport = nil
		g.mcpTransportMu.Unlock()
		return g.ensureMCPTransportInitialized(retryCtx)
	}

	rpcResp, err := mcpclient.SendWithRetry(ctx, g.mcpTransport, rpcReq, retryCfg, reinitFn)
	if err != nil {
		return nil, err
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("upstream tools/list error: code=%d message=%s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	var result struct {
		Tools []struct {
			Name        string                 `json:"name"`
			Description string                 `json:"description"`
			InputSchema map[string]interface{} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to decode tools/list result: %w", err)
	}

	hashes := make(map[string]string, len(result.Tools))
	for _, t := range result.Tools {
		if t.Name == "" {
			continue
		}
		hashes[t.Name] = middleware.ComputeHash(t.Description, t.InputSchema)
	}

	g.observedToolHashes.SetMany(server, hashes)
	return hashes, nil
}

// ensureMCPTransportInitialized performs lazy initialization of the MCP transport.
// Thread-safe: only the first caller initializes; subsequent callers wait.
//
// RFA-0dz: Uses DetectTransport for auto-detection. On first request, tries
// Streamable HTTP first, falls back to Legacy SSE with deprecation warning.
// RFA-xhr: Uses DetectTransportWithConfig for per-probe and overall timeouts.
func (g *Gateway) ensureMCPTransportInitialized(ctx context.Context) error {
	if g.config.MCPTransportMode != "mcp" {
		return fmt.Errorf("MCP transport not configured (MCPTransportMode=%q)", g.config.MCPTransportMode)
	}

	// Fast path: already initialized
	if g.mcpTransport != nil {
		return nil
	}

	g.mcpTransportMu.Lock()
	defer g.mcpTransportMu.Unlock()

	// Double-check after acquiring lock
	if g.mcpTransport != nil {
		return nil
	}

	// RFA-xhr: Use configured timeouts for detection, with safe defaults
	// when config values are zero (e.g., tests that create Config{} directly).
	detectCfg := mcpclient.DefaultDetectConfig()
	if g.config.MCPProbeTimeout > 0 {
		detectCfg.ProbeTimeout = time.Duration(g.config.MCPProbeTimeout) * time.Second
	}
	if g.config.MCPDetectTimeout > 0 {
		detectCfg.OverallTimeout = time.Duration(g.config.MCPDetectTimeout) * time.Second
	}

	httpClient, err := g.mcpTransportHTTPClient()
	if err != nil {
		return err
	}

	transport, err := mcpclient.DetectTransportWithConfig(ctx, g.config.UpstreamURL, httpClient, detectCfg)
	if err != nil {
		return err
	}

	g.mcpTransport = transport
	return nil
}

// mcpTransportHTTPClient returns the HTTP client used by MCP transport detection.
// In strict profiles, MCP transport must use the SPIFFE mTLS transport and must
// never fall back to default plaintext HTTP client behavior.
func (g *Gateway) mcpTransportHTTPClient() (*http.Client, error) {
	isStrict := g.enforcementProfile != nil && g.enforcementProfile.StartupGateMode == "strict"
	if g.spiffeTLS != nil && g.spiffeTLS.UpstreamTransport != nil {
		return &http.Client{
			Transport: NewTracingTransport(g.spiffeTLS.UpstreamTransport),
		}, nil
	}
	if isStrict {
		return nil, fmt.Errorf("strict MCP transport requires SPIFFE mTLS upstream transport to be initialized")
	}
	return nil, nil
}

// processUpstreamResponse routes MCP responses through the appropriate UI
// control pipeline based on request type. This is the central dispatch for
// UI-specific response processing (Reference Architecture Section 7.9.7).
//
// Routing:
//   - tools/list -> capability gating + CSP/permissions mediation
//   - resources/read + ui:// -> request-side capability check + response-side resource controls
//   - everything else -> proxy unchanged
func (g *Gateway) processUpstreamResponse(
	w http.ResponseWriter,
	r *http.Request,
	reqInfo MCPRequestInfo,
	server, tenant string,
) {
	switch {
	case reqInfo.IsResourceRead() && reqInfo.IsUIResource():
		g.handleUIResourceRead(w, r, reqInfo, server, tenant)

	case reqInfo.IsToolsList():
		g.handleToolsListResponse(w, r, server, tenant)

	default:
		// Standard request - proxy unchanged
		g.proxy.ServeHTTP(w, r)
	}
}

// handleToolsListResponse captures the upstream tools/list response and applies
// the full UI processing pipeline: capability gating + CSP/permissions mediation.
func (g *Gateway) handleToolsListResponse(
	w http.ResponseWriter,
	r *http.Request,
	server, tenant string,
) {
	// Capture upstream response for processing
	capture := &uiResponseCapture{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
	}
	g.proxy.ServeHTTP(capture, r)

	responseBody := capture.body.Bytes()

	// RFA-6fse.4: Gateway-owned rug-pull protection for discovery.
	// Strip tools whose observed tools/list metadata hash mismatches the registry baseline.
	// Also seed the observed hash cache for subsequent tools/call verification.
	responseBody = g.filterAndCacheToolsListResponse(r, responseBody, server)

	// RFA-j2d.6: Apply full tools/list processing pipeline
	// (capability gating from j2d.1 + CSP/permissions mediation from j2d.3)
	processedBody := g.uiResponseProcessor.ProcessToolsListResponse(responseBody, server, tenant)

	// Forward captured headers, then write the processed body
	w.Header().Del("Content-Length") // Body size may have changed
	w.WriteHeader(capture.statusCode)
	_, _ = w.Write(processedBody)
}

// filterAndCacheToolsListResponse seeds the observed tool hash cache from a tools/list
// response and strips tools that mismatch the registry baseline hash.
//
// This is client-visible (discovery) protection. Invocation-time protection is
// enforced by ToolRegistryVerify using the same observed hash cache.
func (g *Gateway) filterAndCacheToolsListResponse(r *http.Request, responseBody []byte, server string) []byte {
	if len(responseBody) == 0 || g.registry == nil || g.observedToolHashes == nil {
		return responseBody
	}

	// Parse JSON-RPC response envelope.
	var env map[string]any
	if err := json.Unmarshal(responseBody, &env); err != nil {
		return responseBody
	}
	rawResult, ok := env["result"]
	if !ok {
		return responseBody
	}

	// Parse tools list result.
	var result struct {
		Tools []map[string]any `json:"tools"`
	}
	b, _ := json.Marshal(rawResult)
	if err := json.Unmarshal(b, &result); err != nil {
		return responseBody
	}

	filtered := make([]map[string]any, 0, len(result.Tools))
	observedHashes := make(map[string]string, len(result.Tools))

	for _, tool := range result.Tools {
		name, _ := tool["name"].(string)
		desc, _ := tool["description"].(string)
		schema, _ := tool["inputSchema"].(map[string]any)
		if schema == nil {
			// Some servers may omit inputSchema. Use empty schema in hash computation.
			schema = map[string]any{}
		}

		if name != "" {
			observedHash := middleware.ComputeHash(desc, schema)
			observedHashes[name] = observedHash

			// Only enforce stripping for tools that exist in the baseline registry.
			allowed, expectedHash := g.registry.VerifyTool(name, "")
			if allowed && expectedHash != "" && observedHash != expectedHash {
				// Audit: do not log description or schema (payload may be malicious).
				if g.auditor != nil {
					g.auditor.Log(middleware.AuditEvent{
						SessionID:  middleware.GetSessionID(r.Context()),
						DecisionID: middleware.GetDecisionID(r.Context()),
						TraceID:    middleware.GetTraceID(r.Context()),
						SPIFFEID:   middleware.GetSPIFFEID(r.Context()),
						Action:     "tool_registry_rugpull_stripped",
						Result:     fmt.Sprintf("server=%s tool=%s expected_hash=%s observed_hash=%s", server, name, expectedHash, observedHash),
					})
				}
				continue // strip
			}
		}

		filtered = append(filtered, tool)
	}

	// Seed cache for invocation-time enforcement.
	g.observedToolHashes.SetMany(server, observedHashes)

	// Rewrite response result.tools with filtered list.
	env["result"] = map[string]any{"tools": filtered}
	out, err := json.Marshal(env)
	if err != nil {
		return responseBody
	}
	return out
}

// handleUIResourceRead handles ui:// resource reads with both request-side
// capability checks and response-side resource controls.
func (g *Gateway) handleUIResourceRead(
	w http.ResponseWriter,
	r *http.Request,
	reqInfo MCPRequestInfo,
	server, tenant string,
) {
	resourceURI := reqInfo.ResourceURI()

	// RFA-j2d.1: Block ui:// resource reads for denied servers BEFORE proxying
	if !g.checkUIResourceReadAllowed(server, tenant, resourceURI) {
		middleware.WriteGatewayError(w, r, http.StatusForbidden, middleware.GatewayError{
			Code:        middleware.ErrUICapabilityDenied,
			Message:     "UI resource reads are not permitted for this server/tenant.",
			Middleware:  "ui_capability_gating",
			Remediation: "Grant UI capabilities for this server/tenant in ui_capability_grants.yaml.",
		})
		return
	}

	// Proxy to upstream and capture the response for resource controls
	capture := &uiResponseCapture{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
	}
	g.proxy.ServeHTTP(capture, r)

	responseContent := capture.body.Bytes()
	contentType := capture.Header().Get("Content-Type")

	// RFA-j2d.6: Apply resource controls (j2d.2) + registry verification (j2d.5)
	allowed, reason, _ := g.uiResponseProcessor.ProcessUIResourceResponse(
		responseContent, contentType, server, tenant, resourceURI,
	)

	if !allowed {
		// Resource blocked by controls - return error instead of upstream content
		middleware.WriteGatewayError(w, r, http.StatusForbidden, middleware.GatewayError{
			Code:        middleware.ErrUIResourceBlocked,
			Message:     fmt.Sprintf("UI resource blocked: %s", reason),
			Middleware:  "ui_resource_controls",
			Details:     map[string]any{"reason": reason},
			Remediation: "Ensure the resource passes content-type, size, scan, and hash verification.",
		})
		return
	}

	// Resource passed all controls - forward the upstream response
	w.Header().Del("Content-Length")
	w.WriteHeader(capture.statusCode)
	_, _ = w.Write(responseContent)
}

// uiResponseCapture captures the upstream response so UI capability gating can
// modify it before sending to the client. Follows the same pattern as
// responseCapture in the response firewall (middleware/response_firewall.go).
type uiResponseCapture struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	written    bool
}

func (c *uiResponseCapture) WriteHeader(code int) {
	c.statusCode = code
	c.written = true
	// Capture status but do not forward yet -- we may modify the body
}

func (c *uiResponseCapture) Write(b []byte) (int, error) {
	if !c.written {
		c.statusCode = http.StatusOK
		c.written = true
	}
	return c.body.Write(b)
}

// extractMCPMethodAndParams parses the MCP JSON-RPC method and params from the
// request body already captured in context by BodyCapture middleware.
func (g *Gateway) extractMCPMethodAndParams(ctx context.Context) (string, map[string]interface{}, *int) {
	body := middleware.GetRequestBody(ctx)
	if len(body) == 0 {
		return "", nil, nil
	}
	var req struct {
		Method string                 `json:"method"`
		Params map[string]interface{} `json:"params"`
		ID     interface{}            `json:"id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", nil, nil
	}

	switch v := req.ID.(type) {
	case float64:
		id := int(v)
		if v == float64(id) {
			return req.Method, req.Params, &id
		}
	}

	return req.Method, req.Params, nil
}

func (g *Gateway) nextMCPRequestID() int {
	next := atomic.AddUint64(&g.mcpRequestIDCounter, 1)
	return int(next)
}

// dataHandleDereferenceHandler returns approved views of handle-ized data (RFA-qq0.16)
// POST /data/dereference with JSON body: {"handle_ref": "<ref>"}
// Validates:
//   - Handle exists and hasn't expired (410 Gone if expired/missing)
//   - SPIFFE ID matches the original requester (403 Forbidden if mismatch)
//
// Returns approved views only (for POC: the raw data wrapped in an approved_view envelope)
func (g *Gateway) dataHandleDereferenceHandler() http.Handler {
	// Wrap with SPIFFE auth so we can validate the caller's identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request body
		var req struct {
			HandleRef string `json:"handle_ref"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.HandleRef == "" {
			http.Error(w, "Missing handle_ref", http.StatusBadRequest)
			return
		}

		// Look up handle
		entry := g.handleStore.Get(req.HandleRef)
		if entry == nil {
			// Handle not found or expired
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGone)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":  "handle_expired_or_not_found",
				"detail": "The data handle has expired or does not exist.",
			})
			return
		}

		// Validate SPIFFE ID matches
		callerSPIFFEID := middleware.GetSPIFFEID(r.Context())
		if callerSPIFFEID != entry.SPIFFEID {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":  "spiffe_id_mismatch",
				"detail": "You are not authorized to dereference this handle.",
			})
			return
		}

		// Return approved view
		// In production, this would apply view transformations:
		// aggregates, top-N, redacted rows, etc.
		// For POC, we return the raw data wrapped in an approved_view envelope.
		approvedView := map[string]interface{}{
			"view_type":  "approved_view",
			"tool":       entry.ToolName,
			"created_at": entry.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			"data":       json.RawMessage(entry.RawData),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(approvedView)
	})

	// Apply SPIFFE auth middleware to the dereference endpoint
	return middleware.SPIFFEAuth(inner, g.config.SPIFFEMode)
}

// healthHandler returns gateway health status including circuit breaker state
func (g *Gateway) healthHandler(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status": "ok",
		"circuit_breaker": map[string]interface{}{
			"state": g.circuitBreaker.State().String(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(health)
}

// demoRugpullToggleHandler is a demo-only endpoint that forwards a rugpull toggle
// to the upstream MCP server. This keeps the k8s NetworkPolicy invariant that
// tool pods only accept ingress from the gateway namespace.
func (g *Gateway) demoRugpullToggleHandler(enable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Hide endpoint when not explicitly enabled.
		if g.config == nil || !g.config.DemoRugpullAdminEnabled || g.config.SPIFFEMode != "dev" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		up, err := url.Parse(g.config.UpstreamURL)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"invalid upstream url"}`))
			return
		}
		if enable {
			up.Path = "/__demo__/rugpull/on"
		} else {
			up.Path = "/__demo__/rugpull/off"
		}
		up.RawQuery = ""
		up.Fragment = ""

		transport := g.proxy.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		client := &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
		}
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, up.String(), nil)
		resp, err := client.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"failed to reach upstream demo endpoint"}`))
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}
}

type circuitBreakerEntry struct {
	Tool               string     `json:"tool"`
	State              string     `json:"state"`
	Failures           int        `json:"failures"`
	Threshold          int        `json:"threshold"`
	ResetTimeoutSec    int        `json:"reset_timeout_seconds"`
	LastStateChangeUTC *time.Time `json:"last_state_change"`
}

type circuitBreakersResponse struct {
	CircuitBreakers []circuitBreakerEntry `json:"circuit_breakers"`
}

type circuitBreakerResetRequest struct {
	Tool string `json:"tool"`
}

type circuitBreakerResetEntry struct {
	Tool          string `json:"tool"`
	PreviousState string `json:"previous_state"`
	NewState      string `json:"new_state"`
}

type circuitBreakersResetResponse struct {
	Reset []circuitBreakerResetEntry `json:"reset"`
}

type policyReloadResponse struct {
	Status         string `json:"status"`
	Timestamp      string `json:"timestamp,omitempty"`
	RegistryTools  int    `json:"registry_tools,omitempty"`
	OPAPolicies    int    `json:"opa_policies,omitempty"`
	CosignVerified bool   `json:"cosign_verified"`
	Error          string `json:"error,omitempty"`
}

// adminCircuitBreakersHandler serves:
//   - GET /admin/circuit-breakers
//   - GET /admin/circuit-breakers/<tool>
func (g *Gateway) adminCircuitBreakersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	tool := strings.TrimPrefix(r.URL.Path, "/admin/circuit-breakers")
	tool = strings.TrimPrefix(tool, "/")

	tools := g.registry.ToolNames()

	// Single-tool view
	if tool != "" {
		found := false
		for _, t := range tools {
			if t == tool {
				found = true
				break
			}
		}
		if !found {
			http.NotFound(w, r)
			return
		}

		snap := g.circuitBreaker.Snapshot()
		resetSec := int(snap.ResetTimeout.Seconds())
		if snap.ResetTimeout > 0 && resetSec == 0 {
			resetSec = 1
		}
		entry := circuitBreakerEntry{
			Tool:               tool,
			State:              snap.State.String(),
			Failures:           snap.Failures,
			Threshold:          snap.Threshold,
			ResetTimeoutSec:    resetSec,
			LastStateChangeUTC: snap.LastStateChange,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(circuitBreakersResponse{CircuitBreakers: []circuitBreakerEntry{entry}})
		return
	}

	// All tools
	snap := g.circuitBreaker.Snapshot()
	resetSec := int(snap.ResetTimeout.Seconds())
	if snap.ResetTimeout > 0 && resetSec == 0 {
		resetSec = 1
	}
	out := make([]circuitBreakerEntry, 0, len(tools))
	for _, t := range tools {
		out = append(out, circuitBreakerEntry{
			Tool:               t,
			State:              snap.State.String(),
			Failures:           snap.Failures,
			Threshold:          snap.Threshold,
			ResetTimeoutSec:    resetSec,
			LastStateChangeUTC: snap.LastStateChange,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(circuitBreakersResponse{CircuitBreakers: out})
}

// adminCircuitBreakersResetHandler serves:
//   - POST /admin/circuit-breakers/reset
func (g *Gateway) adminCircuitBreakersResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req circuitBreakerResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if req.Tool == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "tool is required"})
		return
	}

	tools := g.registry.ToolNames()
	targetTools := make([]string, 0, len(tools))
	if req.Tool == "*" {
		targetTools = append(targetTools, tools...)
	} else {
		found := false
		for _, t := range tools {
			if t == req.Tool {
				found = true
				break
			}
		}
		if !found {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("unknown tool: %s", req.Tool)})
			return
		}
		targetTools = append(targetTools, req.Tool)
	}

	before := g.circuitBreaker.Snapshot()
	previousState := before.State.String()
	g.circuitBreaker.Reset()

	after := g.circuitBreaker.Snapshot()
	newState := after.State.String()

	result := make([]circuitBreakerResetEntry, 0, len(targetTools))
	for _, t := range targetTools {
		result = append(result, circuitBreakerResetEntry{
			Tool:          t,
			PreviousState: previousState,
			NewState:      newState,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(circuitBreakersResetResponse{Reset: result})
}

// adminPolicyReloadHandler serves:
//   - POST /admin/policy/reload
//
// It triggers an explicit hot-reload for both tool registry and OPA policies
// through the same public reload paths used by their fsnotify watchers.
func (g *Gateway) adminPolicyReloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	registryResult, err := g.registry.Reload()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(policyReloadResponse{
			Status:         "failed",
			Error:          err.Error(),
			CosignVerified: false,
		})
		return
	}

	opaResult, err := g.opa.Reload()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(policyReloadResponse{
			Status:         "failed",
			Error:          err.Error(),
			CosignVerified: registryResult.CosignVerified,
		})
		return
	}

	_ = json.NewEncoder(w).Encode(policyReloadResponse{
		Status:         "reloaded",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		RegistryTools:  registryResult.ToolCount,
		OPAPolicies:    opaResult.PolicyCount,
		CosignVerified: registryResult.CosignVerified,
	})
}

// checkUIResourceReadAllowed checks whether a ui:// resource read is permitted.
// RFA-j2d.1: Called from the response processing path for resources/read of ui:// URIs.
// RFA-j2d.8: Emits UI audit events via EmitUIEvent for hash chain integration.
// Returns true if the read should proceed, false if it should be blocked with 403.
func (g *Gateway) checkUIResourceReadAllowed(server, tenant, resourceURI string) bool {
	allowed, event := g.uiCapabilityGating.CheckUIResourceReadAllowed(server, tenant, resourceURI)

	if event != nil {
		// RFA-j2d.8: Emit structured UI audit event
		g.auditor.EmitUIEvent(middleware.UIAuditEventParams{
			EventType: event.EventType,
			UI: &middleware.UIAuditData{
				ResourceURI:         resourceURI,
				CapabilityGrantMode: event.Mode,
			},
		})
	}

	return allowed
}

// dlpPolicy returns the effective DLP policy by merging the YAML config with
// the DLP_INJECTION_POLICY env var override. The env var takes precedence over
// the YAML value for the injection category only.
func (g *Gateway) dlpPolicy() middleware.DLPPolicy {
	p := g.riskConfig.DLP
	// RFA-sd7: DLP_INJECTION_POLICY env var overrides dlp.injection YAML config.
	if g.config.DLPInjectionPolicy == "block" || g.config.DLPInjectionPolicy == "flag" {
		p.Injection = g.config.DLPInjectionPolicy
	}
	return p
}

// Close cleans up gateway resources
func (g *Gateway) Close() error {
	// RFA-9ol: Close MCP transport session
	if g.mcpTransport != nil {
		_ = g.mcpTransport.Close(context.Background())
	}
	// RFA-dh9: Stop the registry file watcher
	if g.registryStop != nil {
		g.registryStop()
	}
	if g.handleStore != nil {
		g.handleStore.Close()
	}
	// RFA-j2d.6: Clean up UI resource controls cache
	if g.uiResourceControls != nil {
		g.uiResourceControls.Close()
	}
	// RFA-a2y.1: Close SPIKE Nexus redeemer (releases X.509 source if present)
	if closer, ok := g.spikeRedeemer.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	// RFA-hh5.1: Close KeyDB session store if applicable
	if closer, ok := g.sessionStore.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	// RFA-8z8.1: Close SPIFFE TLS config (releases X509Source)
	if g.spiffeTLS != nil {
		_ = g.spiffeTLS.Close()
	}
	if g.opa != nil {
		return g.opa.Close()
	}
	return nil
}

// EnableSPIFFETLS initializes SPIFFE-based mTLS for the gateway (RFA-8z8.1).
// In prod mode, this connects to the SPIRE Agent, obtains an X.509 SVID, and
// configures both the server's TLS listener and the reverse proxy's upstream
// transport for mutual TLS.
//
// RFA-8z8.2: Also configures the KeyDB client for TLS when KeyDB is in use.
// The same X509Source provides mTLS for KeyDB, upstream proxy, and server TLS.
//
// This method must be called AFTER New() and BEFORE starting the HTTP server.
// It is separated from New() because SPIRE connectivity is an infrastructure
// dependency that should fail loudly at startup, not silently during config.
func (g *Gateway) EnableSPIFFETLS(ctx context.Context) error {
	upstreamAuthzAllowedSPIFFEIDs := g.config.UpstreamAuthzAllowedSPIFFEIDs
	keyDBAuthzAllowedSPIFFEIDs := g.config.KeyDBAuthzAllowedSPIFFEIDs
	if g.enforcementProfile != nil && g.enforcementProfile.StartupGateMode == "strict" {
		if len(upstreamAuthzAllowedSPIFFEIDs) == 0 {
			upstreamAuthzAllowedSPIFFEIDs = defaultUpstreamAuthzAllowedSPIFFEIDs(g.config.SPIFFETrustDomain)
		}
		if len(keyDBAuthzAllowedSPIFFEIDs) == 0 {
			keyDBAuthzAllowedSPIFFEIDs = defaultKeyDBAuthzAllowedSPIFFEIDs(g.config.SPIFFETrustDomain)
		}
	}

	spiffeTLS, err := NewSPIFFETLSConfig(ctx, upstreamAuthzAllowedSPIFFEIDs)
	if err != nil {
		return fmt.Errorf("failed to initialize SPIFFE TLS: %w", err)
	}

	g.spiffeTLS = spiffeTLS

	// RFA-8z8.1 AC3: Configure the reverse proxy transport for mTLS to upstream.
	// This replaces the default HTTP transport with one that presents the
	// gateway's SVID and validates the upstream's certificate.
	// RFA-m6j.3: Wrap with TracingTransport to propagate trace context
	// over the mTLS connection to upstream MCP servers.
	g.proxy.Transport = NewTracingTransport(spiffeTLS.UpstreamTransport)

	// RFA-8z8.2 AC2: Configure the KeyDB client for TLS if KeyDB is in use.
	// The KeyDB client needs the same X509Source for mTLS to KeyDB.
	if g.config.KeyDBURL != "" {
		if err := g.enableKeyDBTLS(spiffeTLS, keyDBAuthzAllowedSPIFFEIDs); err != nil {
			if g.enforcementProfile != nil && g.enforcementProfile.StartupGateMode == "strict" {
				return fmt.Errorf("failed to enable keydb TLS in strict profile: %w", err)
			}
			log.Printf("WARNING: Failed to enable KeyDB TLS: %v (non-strict profile fallback)", err)
			// Non-strict profiles keep transition compatibility. Strict profiles
			// fail-fast above so production posture remains fail-closed.
		}
	}

	log.Printf("SPIFFE mTLS: server TLS configured, upstream proxy transport set to mTLS")

	return nil
}

// enableKeyDBTLS configures the KeyDB session store and rate limiter clients
// with TLS from the SPIRE X509Source. This replaces the plain redis client
// created in New() with a TLS-enabled one.
//
// RFA-8z8.2: KeyDB does not speak SPIRE Workload API natively. It receives
// filesystem-based certs via an init script (scripts/keydb-svid-refresh.sh).
// The gateway connects to it using the same X509Source as other mTLS connections.
func (g *Gateway) enableKeyDBTLS(spiffeTLS *SPIFFETLSConfig, keyDBAuthzAllowedSPIFFEIDs []string) error {
	keyDBTLSCfg, err := NewKeyDBTLSConfigFromSPIRE(spiffeTLS.x509Source, keyDBAuthzAllowedSPIFFEIDs)
	if err != nil {
		return fmt.Errorf("failed to create KeyDB TLS config: %w", err)
	}

	// Create a new TLS-enabled redis client and replace the stores
	keyDBURL := KeyDBURLForMode(g.config.KeyDBURL, g.config.SPIFFEMode)
	redisClient := NewKeyDBClientTLS(keyDBURL, g.config.KeyDBPoolMin, g.config.KeyDBPoolMax, keyDBTLSCfg.TLSConfig)

	// Close old stores before replacing
	if closer, ok := g.sessionStore.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	// Create new stores with TLS client
	g.sessionStore = middleware.NewKeyDBStoreFromClient(redisClient, g.config.SessionTTL)
	rateLimitStore := middleware.NewKeyDBRateLimitStore(redisClient)

	// Update the session context and rate limiter with new stores
	g.sessionContext = middleware.NewSessionContext(g.sessionStore)
	g.rateLimiter = middleware.NewRateLimiter(g.config.RateLimitRPM, g.config.RateLimitBurst, rateLimitStore)

	log.Printf("SPIFFE mTLS: KeyDB client configured with TLS (URL: %s)", keyDBURL)

	return nil
}

// SPIFFETLSEnabled returns true if the gateway is configured for SPIFFE mTLS.
func (g *Gateway) SPIFFETLSEnabled() bool {
	return g.spiffeTLS != nil
}

// ServerTLSConfig returns the TLS configuration for the HTTPS listener.
// Returns nil when in dev mode (HTTP only).
func (g *Gateway) ServerTLSConfig() *tls.Config {
	if g.spiffeTLS != nil {
		return g.spiffeTLS.ServerTLS
	}
	return nil
}
