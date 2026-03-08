package discord

import (
	"net/http"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
)

const (
	pathSend     = "/discord/send"
	pathWebhooks = "/discord/webhooks"
	pathCommands = "/discord/commands"
)

// Adapter implements gateway.PortAdapter for Discord channel mediation.
type Adapter struct {
	gw gateway.PortGatewayServices
}

// NewAdapter creates a new Discord port adapter backed by the given gateway services.
func NewAdapter(gw gateway.PortGatewayServices) *Adapter {
	return &Adapter{gw: gw}
}

// Name returns the port identifier.
func (a *Adapter) Name() string { return "discord" }

// TryServeHTTP dispatches to the appropriate handler if the path matches a Discord route.
// Returns true if the request was handled, false otherwise.
func (a *Adapter) TryServeHTTP(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case pathSend:
		a.handleSend(w, r)
		return true
	case pathWebhooks:
		a.handleWebhook(w, r)
		return true
	case pathCommands:
		a.handleCommand(w, r)
		return true
	}
	return false
}

// handleSend is a stub for outbound message sending.
// Will be implemented in story OC-o3xl.
func (a *Adapter) handleSend(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleWebhook is a stub for inbound webhook event processing.
// Will be implemented in story OC-q8yz.
func (a *Adapter) handleWebhook(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// handleCommand is a stub for bot slash-command processing.
// Will be implemented in story OC-q8yz.
func (a *Adapter) handleCommand(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// Compile-time check.
var _ gateway.PortAdapter = (*Adapter)(nil)
