package openclaw

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway"
	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
)

const (
	webhookBasePath     = "/openclaw/webhooks"
	whatsappWebhookPath = webhookBasePath + "/whatsapp"
	telegramWebhookPath = webhookBasePath + "/telegram"
	slackWebhookPath    = webhookBasePath + "/slack"
)

// inboundMessage holds the extracted content and sender from a webhook payload.
type inboundMessage struct {
	Content  string
	Sender   string
	Platform string
}

// handleWebhook dispatches inbound webhook requests for WhatsApp, Telegram, and Slack.
// It validates connector conformance BEFORE processing and uses internal loopback
// to POST through the gateway's full ingress middleware chain.
func (a *Adapter) handleWebhook(w http.ResponseWriter, r *http.Request) {
	// Determine platform from path.
	platform := platformFromPath(r.URL.Path)
	if platform == "" {
		a.gw.WriteGatewayError(w, r, http.StatusNotFound,
			middleware.ErrMCPInvalidRequest, "unknown webhook path",
			"webhook_receiver", gateway.ReasonContractInvalid, nil)
		return
	}

	// Only POST is accepted.
	if r.Method != http.MethodPost {
		a.gw.WriteGatewayError(w, r, http.StatusMethodNotAllowed,
			middleware.ErrMCPInvalidRequest, "method not allowed",
			"webhook_receiver", gateway.ReasonContractInvalid,
			map[string]any{"expected_method": http.MethodPost})
		return
	}

	// Parse JSON body.
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest, "invalid json payload",
			"webhook_receiver", gateway.ReasonContractInvalid, nil)
		return
	}

	// Determine connector ID: from payload or derive from platform.
	connectorID := extractConnectorID(payload, platform)
	connectorSig := computeWebhookConnectorSig(connectorID, platform)

	// Validate connector conformance BEFORE processing.
	allowed, reason := a.gw.ValidateConnector(connectorID, connectorSig)
	if !allowed {
		a.gw.WriteGatewayError(w, r, http.StatusForbidden,
			middleware.ErrMCPInvalidRequest, "connector conformance failed: "+reason,
			"webhook_receiver", gateway.ReasonContractInvalid,
			map[string]any{
				"connector_id":    connectorID,
				"connector_check": reason,
			})
		return
	}

	// Extract message content and sender from platform-specific payload.
	msg, err := extractInboundMessage(platform, payload)
	if err != nil {
		a.gw.WriteGatewayError(w, r, http.StatusBadRequest,
			middleware.ErrMCPInvalidRequest, "failed to extract message: "+err.Error(),
			"webhook_receiver", gateway.ReasonContractInvalid,
			map[string]any{"platform": platform})
		return
	}

	// Build ingress PlaneRequestV2 for internal loopback.
	now := time.Now().UTC()
	runID := fmt.Sprintf("webhook-%s-%d", platform, now.UnixNano())
	sessionID := fmt.Sprintf("webhook-session-%s-%d", platform, now.UnixNano())

	planeReq := gateway.PlaneRequestV2{
		Envelope: gateway.RunEnvelope{
			RunID:         runID,
			SessionID:     sessionID,
			Tenant:        "default",
			ActorSPIFFEID: "spiffe://poc.local/webhooks/" + platform,
			Plane:         gateway.PlaneIngress,
		},
		Policy: gateway.PolicyInputV2{
			Envelope: gateway.RunEnvelope{
				RunID:         runID,
				SessionID:     sessionID,
				Tenant:        "default",
				ActorSPIFFEID: "spiffe://poc.local/webhooks/" + platform,
				Plane:         gateway.PlaneIngress,
			},
			Action:   "webhook.inbound",
			Resource: platform + ".message",
			Attributes: map[string]any{
				"connector_id":        connectorID,
				"connector_signature": connectorSig,
				"source_principal":    "spiffe://poc.local/webhooks/" + platform,
				"platform":            platform,
				"sender":              msg.Sender,
				"content":             msg.Content,
			},
		},
	}

	// Internal loopback POST to the gateway's own ingress endpoint.
	loopbackResp, loopbackErr := a.postIngressLoopback(planeReq)
	if loopbackErr != nil {
		slog.Error("webhook loopback failed",
			"platform", platform,
			"error", loopbackErr.Error())
		a.gw.WriteGatewayError(w, r, http.StatusBadGateway,
			middleware.ErrMCPInvalidRequest, "internal loopback failed",
			"webhook_receiver", gateway.ReasonContractInvalid,
			map[string]any{"platform": platform})
		return
	}
	defer func() { _ = loopbackResp.Body.Close() }()

	// Forward the ingress response back to the webhook caller.
	respBody, _ := io.ReadAll(loopbackResp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(loopbackResp.StatusCode)
	_, _ = w.Write(respBody)
}

// postIngressLoopback POSTs a PlaneRequestV2 to the gateway's own /v1/ingress/submit.
func (a *Adapter) postIngressLoopback(req gateway.PlaneRequestV2) (*http.Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal ingress request: %w", err)
	}

	loopbackURL := a.internalGatewayURL + "/v1/ingress/submit"
	httpReq, err := http.NewRequest(http.MethodPost, loopbackURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build loopback request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Carry the webhook actor identity for the ingress middleware chain.
	httpReq.Header.Set("X-SPIFFE-ID", req.Envelope.ActorSPIFFEID)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("loopback POST: %w", err)
	}
	return resp, nil
}

// platformFromPath extracts the platform name from the webhook URL path.
// Returns empty string for unknown paths.
func platformFromPath(path string) string {
	switch path {
	case whatsappWebhookPath:
		return "whatsapp"
	case telegramWebhookPath:
		return "telegram"
	case slackWebhookPath:
		return "slack"
	default:
		return ""
	}
}

// extractConnectorID returns a connector ID from the payload or derives one from the platform.
func extractConnectorID(payload map[string]any, platform string) string {
	if id, ok := payload["connector_id"].(string); ok && strings.TrimSpace(id) != "" {
		return id
	}
	return "webhook-" + platform
}

// computeWebhookConnectorSig generates a deterministic signature for webhook connectors.
// This mirrors the canonical signature computation in the connector conformance authority.
func computeWebhookConnectorSig(connectorID, platform string) string {
	canon := map[string]any{
		"connector_id":   connectorID,
		"connector_type": "webhook",
		"platform":       platform,
	}
	data, _ := json.Marshal(canon)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// extractInboundMessage parses platform-specific payload formats into a unified inboundMessage.
func extractInboundMessage(platform string, payload map[string]any) (inboundMessage, error) {
	switch platform {
	case "whatsapp":
		return extractWhatsAppMessage(payload)
	case "telegram":
		return extractTelegramMessage(payload)
	case "slack":
		return extractSlackMessage(payload)
	default:
		return inboundMessage{}, fmt.Errorf("unsupported platform: %s", platform)
	}
}

// extractWhatsAppMessage parses: payload["entry"][0]["changes"][0]["value"]["messages"][0] -> text.body, from
func extractWhatsAppMessage(payload map[string]any) (inboundMessage, error) {
	entries, ok := payload["entry"].([]any)
	if !ok || len(entries) == 0 {
		return inboundMessage{}, fmt.Errorf("whatsapp: missing entry array")
	}
	entry, ok := entries[0].(map[string]any)
	if !ok {
		return inboundMessage{}, fmt.Errorf("whatsapp: entry[0] is not an object")
	}
	changes, ok := entry["changes"].([]any)
	if !ok || len(changes) == 0 {
		return inboundMessage{}, fmt.Errorf("whatsapp: missing changes array")
	}
	change, ok := changes[0].(map[string]any)
	if !ok {
		return inboundMessage{}, fmt.Errorf("whatsapp: changes[0] is not an object")
	}
	value, ok := change["value"].(map[string]any)
	if !ok {
		return inboundMessage{}, fmt.Errorf("whatsapp: missing value object")
	}
	messages, ok := value["messages"].([]any)
	if !ok || len(messages) == 0 {
		return inboundMessage{}, fmt.Errorf("whatsapp: missing messages array")
	}
	msg, ok := messages[0].(map[string]any)
	if !ok {
		return inboundMessage{}, fmt.Errorf("whatsapp: messages[0] is not an object")
	}

	sender, _ := msg["from"].(string)
	content := ""
	if textBlock, ok := msg["text"].(map[string]any); ok {
		content, _ = textBlock["body"].(string)
	}

	return inboundMessage{
		Content:  content,
		Sender:   sender,
		Platform: "whatsapp",
	}, nil
}

// extractTelegramMessage parses: payload["message"] -> text, from.username
func extractTelegramMessage(payload map[string]any) (inboundMessage, error) {
	message, ok := payload["message"].(map[string]any)
	if !ok {
		return inboundMessage{}, fmt.Errorf("telegram: missing message object")
	}
	content, _ := message["text"].(string)
	sender := ""
	if from, ok := message["from"].(map[string]any); ok {
		sender, _ = from["username"].(string)
	}
	return inboundMessage{
		Content:  content,
		Sender:   sender,
		Platform: "telegram",
	}, nil
}

// extractSlackMessage parses: payload["event"] -> text, user
func extractSlackMessage(payload map[string]any) (inboundMessage, error) {
	event, ok := payload["event"].(map[string]any)
	if !ok {
		return inboundMessage{}, fmt.Errorf("slack: missing event object")
	}
	content, _ := event["text"].(string)
	sender, _ := event["user"].(string)
	return inboundMessage{
		Content:  content,
		Sender:   sender,
		Platform: "slack",
	}, nil
}
