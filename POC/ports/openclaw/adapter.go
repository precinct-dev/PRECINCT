package openclaw

import (
	"net/http"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
	"github.com/RamXX/agentic_reference_architecture/POC/ports/openclaw/protocol"
)

const openClawWSPath = "/openclaw/ws"

// Adapter implements gateway.PortAdapter for the OpenClaw third-party agent.
type Adapter struct {
	gw gateway.PortGatewayServices
}

// NewAdapter creates a new OpenClaw port adapter backed by the given gateway services.
func NewAdapter(gw gateway.PortGatewayServices) *Adapter {
	return &Adapter{gw: gw}
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
