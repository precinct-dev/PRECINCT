package email

import (
	"encoding/json"
	"net/http"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway"
)

const (
	pathSend     = "/email/send"
	pathWebhooks = "/email/webhooks"
	pathList     = "/email/list"
	pathRead     = "/email/read"
)

// Adapter implements gateway.PortAdapter for the email channel mediation port.
type Adapter struct {
	gw gateway.PortGatewayServices
}

// NewAdapter creates a new email port adapter backed by the given gateway services.
func NewAdapter(gw gateway.PortGatewayServices) *Adapter {
	return &Adapter{gw: gw}
}

// Name returns the port identifier.
func (a *Adapter) Name() string { return "email" }

// TryServeHTTP dispatches to the matching email handler if the path belongs
// to this port. Returns false for unrecognised paths.
func (a *Adapter) TryServeHTTP(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case pathSend:
		a.handleSend(w, r)
		return true
	case pathWebhooks:
		a.handleWebhook(w, r)
		return true
	case pathList:
		a.handleList(w, r)
		return true
	case pathRead:
		a.handleRead(w, r)
		return true
	}
	return false
}

// stubError writes a 501 Not Implemented JSON error body.
func stubError(w http.ResponseWriter, operation string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	resp := map[string]string{
		"error":     "not_implemented",
		"operation": operation,
		"message":   operation + " is not yet implemented",
	}
	json.NewEncoder(w).Encode(resp)
}

// All handlers are stubs returning 501 -- implemented in future stories.

func (a *Adapter) handleSend(w http.ResponseWriter, r *http.Request) {
	a.handleSendImpl(w, r)
}

func (a *Adapter) handleWebhook(w http.ResponseWriter, _ *http.Request) {
	stubError(w, "email_webhook")
}

func (a *Adapter) handleList(w http.ResponseWriter, _ *http.Request) {
	stubError(w, "email_list")
}

func (a *Adapter) handleRead(w http.ResponseWriter, r *http.Request) {
	a.handleReadImpl(w, r)
}

// RouteAuthorizations declares OPA route authorization rules for the Email port.
func (a *Adapter) RouteAuthorizations() []gateway.PortRouteAuth {
	return []gateway.PortRouteAuth{
		{Path: pathSend, Methods: []string{"POST"}, AuthModel: "tool_plane"},
		{Path: pathWebhooks, Methods: []string{"POST"}, AuthModel: "webhook_inbound"},
		{Path: pathList, Methods: []string{"GET"}, AuthModel: "tool_plane"},
		{Path: pathRead, Methods: []string{"GET"}, AuthModel: "tool_plane"},
	}
}

// Compile-time check.
var _ gateway.PortAdapter = (*Adapter)(nil)
