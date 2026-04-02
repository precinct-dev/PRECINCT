package openclaw

import (
	"net/http"
	"os"
	"strings"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/precinct-dev/precinct/ports/openclaw/protocol"
)

const openClawWSPath = "/openclaw/ws"

// Adapter implements gateway.PortAdapter for the OpenClaw third-party agent.
type Adapter struct {
	gw                 gateway.PortGatewayServices
	internalGatewayURL string
}

// NewAdapter creates a new OpenClaw port adapter backed by the given gateway services.
// The internal gateway URL for webhook loopback is read from GATEWAY_INTERNAL_URL
// (default: http://localhost:8443).
func NewAdapter(gw gateway.PortGatewayServices) *Adapter {
	gwURL := os.Getenv("GATEWAY_INTERNAL_URL")
	if gwURL == "" {
		gwURL = "http://localhost:8443"
	}
	return &Adapter{gw: gw, internalGatewayURL: gwURL}
}

// NewAdapterWithLoopbackURL creates an adapter with an explicit internal gateway URL.
// This is primarily for testing where the loopback target is a local httptest server.
func NewAdapterWithLoopbackURL(gw gateway.PortGatewayServices, loopbackURL string) *Adapter {
	return &Adapter{gw: gw, internalGatewayURL: loopbackURL}
}

// Name returns the port identifier.
func (a *Adapter) Name() string { return "openclaw" }

// TryServeHTTP dispatches to the WS or HTTP handler if the path matches.
func (a *Adapter) TryServeHTTP(w http.ResponseWriter, r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}

	// WS path
	if r.URL.Path == openClawWSPath {
		a.handleWSEntry(w, r)
		return true
	}

	// Webhook paths
	if strings.HasPrefix(r.URL.Path, webhookBasePath) {
		a.handleWebhook(w, r)
		return true
	}

	// HTTP paths
	switch r.URL.Path {
	case protocol.ResponsesPath:
		a.handleResponses(w, r)
		return true
	case protocol.ToolsInvokePath:
		a.handleToolsInvoke(w, r)
		return true
	default:
		return false
	}
}

// RouteAuthorizations declares the OPA route authorization rules for this port.
// These are injected into the OPA data store so the core policy can grant
// destination_allowed without hardcoding OpenClaw-specific paths.
func (a *Adapter) RouteAuthorizations() []gateway.PortRouteAuth {
	return []gateway.PortRouteAuth{
		{
			Path:      protocol.ResponsesPath, // /v1/responses
			Methods:   []string{"POST"},
			AuthModel: "model_plane",
		},
		{
			PathPrefix: webhookBasePath + "/", // /openclaw/webhooks/
			Methods:    []string{"POST"},
			AuthModel:  "webhook_inbound",
		},
	}
}

const (
	// OpenClawComposeSPIFFEID is the legacy Compose identity used by the OpenClaw port.
	OpenClawComposeSPIFFEID = "spiffe://poc.local/openclaw"
	// OpenClawK8sBridgeSPIFFEID is the local-K8s bridge identity used to preserve
	// the demo trust-domain while keeping OpenClaw in the agent principal hierarchy.
	OpenClawK8sBridgeSPIFFEID = "spiffe://poc.local/agents/ports/openclaw/dev"
	// OpenClawK8sSPIFFEID is the Kubernetes service-account identity used by the OpenClaw port.
	OpenClawK8sSPIFFEID = "spiffe://precinct.poc/ns/openclaw/sa/openclaw"
)

// TrustedAgentDLPEntries returns the trusted agent DLP entries for the
// OpenClaw port. System prompt content (role=system) from OpenClaw bypasses
// DLP scanning to avoid false positives on agent instructions. User messages
// (role=user) are always scanned.
// OC-xj4w: Port-scoped trusted agent DLP bypass.
func (a *Adapter) TrustedAgentDLPEntries() []middleware.TrustedAgentDLPEntry {
	entries := make([]middleware.TrustedAgentDLPEntry, 0, 3)
	for _, spiffeID := range []string{OpenClawComposeSPIFFEID, OpenClawK8sBridgeSPIFFEID, OpenClawK8sSPIFFEID} {
		entries = append(entries, middleware.TrustedAgentDLPEntry{
			SPIFFEID:       spiffeID,
			DLPBypassScope: "system_prompt",
		})
	}
	return entries
}

// Compile-time checks.
var _ gateway.PortAdapter = (*Adapter)(nil)
var _ gateway.TrustedAgentDLPProvider = (*Adapter)(nil)
