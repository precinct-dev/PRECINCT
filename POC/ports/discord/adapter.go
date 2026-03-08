package discord

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
	"github.com/RamXX/agentic_reference_architecture/POC/ports/discord/protocol"
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

// handleSend evaluates an outbound message-send request against the tool plane.
// Actual message dispatch is deferred to story OC-o3xl.
func (a *Adapter) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.gw.WriteGatewayError(w, r, http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest, "method not allowed",
			adapterName, gateway.ReasonContractInvalid,
			map[string]any{"route": pathSend, "expected_method": http.MethodPost})
		return
	}

	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest, "unable to read request body",
			adapterName, gateway.ReasonContractInvalid,
			map[string]any{"route": pathSend})
		return
	}

	var msg protocol.SendMessageRequest
	if err := json.Unmarshal(rawBody, &msg); err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrContractValidationFailed, "invalid JSON body",
			adapterName, gateway.ReasonContractInvalid,
			map[string]any{"route": pathSend, "error": err.Error()})
		return
	}
	if strings.TrimSpace(msg.ChannelID) == "" || strings.TrimSpace(msg.Content) == "" {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrContractValidationFailed, "channel_id and content are required",
			adapterName, gateway.ReasonContractInvalid,
			map[string]any{"route": pathSend})
		return
	}

	planeReq := a.buildToolPlaneRequest(r, "messaging_send", "discord:channel:"+msg.ChannelID, map[string]any{
		"channel_id": msg.ChannelID,
		"content":    msg.Content,
	})
	eval := a.gw.EvaluateToolRequest(planeReq)

	envelope := planeReq.Envelope
	traceID, decisionID := gateway.GetDecisionCorrelationIDs(r, envelope)
	a.gw.LogPlaneDecision(r, gateway.PlaneDecisionV2{
		Decision:   eval.Decision,
		ReasonCode: eval.Reason,
		Envelope:   envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   gateway.MergeMetadata(eval.Metadata, map[string]any{"discord_route": pathSend}),
	}, eval.HTTPStatus)

	if eval.Decision != gateway.DecisionAllow {
		writeDiscordError(w, eval.HTTPStatus, decisionID, traceID, eval.Reason, "messaging_send denied by policy")
		return
	}

	// Allowed but not yet implemented -- actual dispatch is story OC-o3xl.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        false,
		"operation": "messaging_send",
		"error":     "execution not yet implemented",
	})
}

// handleWebhook is implemented in webhook_receiver.go.

// handleCommand evaluates a bot slash-command request against the tool plane.
// Actual command execution is deferred to story OC-q8yz.
func (a *Adapter) handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.gw.WriteGatewayError(w, r, http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest, "method not allowed",
			adapterName, gateway.ReasonContractInvalid,
			map[string]any{"route": pathCommands, "expected_method": http.MethodPost})
		return
	}

	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest, "unable to read request body",
			adapterName, gateway.ReasonContractInvalid,
			map[string]any{"route": pathCommands})
		return
	}

	var cmd protocol.BotCommandRequest
	if err := json.Unmarshal(rawBody, &cmd); err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrContractValidationFailed, "invalid JSON body",
			adapterName, gateway.ReasonContractInvalid,
			map[string]any{"route": pathCommands, "error": err.Error()})
		return
	}
	if strings.TrimSpace(cmd.Command) == "" {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrContractValidationFailed, "command is required",
			adapterName, gateway.ReasonContractInvalid,
			map[string]any{"route": pathCommands})
		return
	}

	planeReq := a.buildToolPlaneRequest(r, "discord_command", "discord:command:"+cmd.Command, map[string]any{
		"command":  cmd.Command,
		"guild_id": cmd.GuildID,
		"options":  cmd.Options,
	})
	eval := a.gw.EvaluateToolRequest(planeReq)

	envelope := planeReq.Envelope
	traceID, decisionID := gateway.GetDecisionCorrelationIDs(r, envelope)
	a.gw.LogPlaneDecision(r, gateway.PlaneDecisionV2{
		Decision:   eval.Decision,
		ReasonCode: eval.Reason,
		Envelope:   envelope,
		TraceID:    traceID,
		DecisionID: decisionID,
		Metadata:   gateway.MergeMetadata(eval.Metadata, map[string]any{"discord_route": pathCommands}),
	}, eval.HTTPStatus)

	if eval.Decision != gateway.DecisionAllow {
		writeDiscordError(w, eval.HTTPStatus, decisionID, traceID, eval.Reason, "discord_command denied by policy")
		return
	}

	// Allowed but not yet implemented -- actual execution is story OC-q8yz.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        false,
		"operation": "discord_command",
		"error":     "execution not yet implemented",
	})
}

const adapterName = "discord_adapter"

// buildToolPlaneRequest constructs a PlaneRequestV2 for the tool plane.
func (a *Adapter) buildToolPlaneRequest(r *http.Request, action, resource string, attrs map[string]any) gateway.PlaneRequestV2 {
	envelope := gateway.RunEnvelope{
		RunID:         fmt.Sprintf("discord-%s-%d", action, time.Now().UnixNano()),
		SessionID:     "discord-session-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		Tenant:        gateway.DefaultString(strings.TrimSpace(r.Header.Get("X-Tenant")), "default"),
		ActorSPIFFEID: middleware.GetSPIFFEID(r.Context()),
		Plane:         gateway.PlaneTool,
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["adapter"] = "discord"
	attrs["protocol"] = "discord"
	return gateway.PlaneRequestV2{
		Envelope: envelope,
		Policy: gateway.PolicyInputV2{
			Envelope:   envelope,
			Action:     action,
			Resource:   resource,
			Attributes: attrs,
		},
	}
}

// writeDiscordError writes a structured JSON error response for the Discord adapter.
func writeDiscordError(w http.ResponseWriter, status int, decisionID, traceID string, reason gateway.ReasonCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Precinct-Decision-ID", decisionID)
	w.Header().Set("X-Precinct-Trace-ID", traceID)
	w.Header().Set("X-Precinct-Reason-Code", string(reason))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": false,
		"error": map[string]any{
			"type":        "policy_denied",
			"message":     message,
			"reason_code": reason,
			"decision_id": decisionID,
			"trace_id":    traceID,
		},
	})
}

// Compile-time check.
var _ gateway.PortAdapter = (*Adapter)(nil)
