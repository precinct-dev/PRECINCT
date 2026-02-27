package openclaw

import (
	"net/http"
	"os"
	"strings"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
	"github.com/RamXX/agentic_reference_architecture/POC/ports/openclaw/protocol"
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

// Compile-time check.
var _ gateway.PortAdapter = (*Adapter)(nil)
