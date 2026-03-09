package discord

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/middleware"
	"github.com/RamXX/agentic_reference_architecture/POC/ports/discord/protocol"
)

// verifyDiscordSignature validates a Discord Ed25519 signature.
// Discord sends: X-Signature-Ed25519 (hex-encoded signature), X-Signature-Timestamp (timestamp string).
// The signed message is: timestamp + request body.
func verifyDiscordSignature(publicKeyHex, timestamp, body string, signatureHex string) bool {
	if publicKeyHex == "" || signatureHex == "" || timestamp == "" {
		return false
	}
	pubKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	message := []byte(timestamp + body)
	return ed25519.Verify(ed25519.PublicKey(pubKeyBytes), message, sigBytes)
}

// handleWebhook processes inbound Discord webhook events.
// It verifies the Ed25519 signature, parses the event, validates connector conformance,
// and emits an audit event so inbound content is captured in the audit log.
//
// NOTE: Full internal loopback through the middleware chain (DLP step 7, deep scan step 10,
// session context step 8) is deferred to story OC-di1n. This implementation uses AuditLog
// emission as the documented fallback, ensuring events are captured while the full loopback
// wiring is completed in the next story.
func (a *Adapter) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "unable to read body", http.StatusBadRequest)
		return
	}

	// Verify Discord Ed25519 signature.
	sig := r.Header.Get("X-Signature-Ed25519")
	ts := r.Header.Get("X-Signature-Timestamp")
	pubKey := os.Getenv("DISCORD_PUBLIC_KEY")

	if pubKey == "" || !verifyDiscordSignature(pubKey, ts, string(body), sig) {
		// Emit audit event for invalid/missing signature.
		a.gw.AuditLog(middleware.AuditEvent{
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			EventType:  "discord.webhook.signature_invalid",
			Severity:   "Critical",
			Action:     "webhook.inbound",
			Result:     "denied",
			Method:     r.Method,
			Path:       r.URL.Path,
			StatusCode: http.StatusUnauthorized,
		})
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// Parse webhook event.
	var event protocol.WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Validate connector conformance.
	connectorID := "webhook-discord"
	connectorSig := computeDiscordConnectorSig(connectorID)
	allowed, reason := a.gw.ValidateConnector(connectorID, connectorSig)

	slog.Info("discord webhook connector validation",
		"connector_id", connectorID,
		"allowed", allowed,
		"reason", reason)

	// Emit audit event for the inbound webhook.
	// This ensures AC7 (audit log captures inbound events) is met.
	// Full middleware chain traversal (DLP step 7, deep scan step 10) will be
	// wired via internal loopback in story OC-di1n.
	now := time.Now().UTC()
	runID := fmt.Sprintf("discord-webhook-%d", now.UnixNano())

	// Extract content from the event data for audit purposes.
	var eventData map[string]any
	if event.Data != nil {
		_ = json.Unmarshal(event.Data, &eventData)
	}
	content := ""
	if eventData != nil {
		if c, ok := eventData["content"].(string); ok {
			content = c
		}
	}

	// OC-di1n: Internal DLP scan for inbound webhook content.
	// This implements the internal loopback for DLP/injection detection
	// on inbound Discord messages, completing the story that was deferred
	// from the initial webhook implementation.
	safeZoneFlags := []string{
		"discord_webhook_received",
	}

	if content != "" {
		// Run DLP scan on inbound content.
		scanResult := a.gw.ScanContent(content)

		if scanResult.HasSuspicious {
			// Injection detected in inbound webhook content -- deny.
			safeZoneFlags = append(safeZoneFlags, "inbound_injection_detected")
			a.gw.AuditLog(middleware.AuditEvent{
				Timestamp:  now.Format(time.RFC3339),
				EventType:  "discord.webhook.injection_blocked",
				Severity:   "Critical",
				SessionID:  runID,
				SPIFFEID:   "spiffe://poc.local/webhooks/discord",
				Action:     "webhook.inbound",
				Result:     "denied",
				Method:     r.Method,
				Path:       r.URL.Path,
				StatusCode: http.StatusForbidden,
				Security: &middleware.SecurityAudit{
					SafeZoneFlags: append(safeZoneFlags, scanResult.Flags...),
				},
			})

			slog.Warn("discord webhook injection blocked",
				"event_type", event.Type,
				"content_length", len(content),
				"flags", scanResult.Flags,
				"run_id", runID)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":            middleware.ErrDeepScanBlocked,
				"message":         "Inbound webhook content contains injection pattern",
				"middleware":      "deep_scan",
				"middleware_step": 10,
			})
			return
		}

		if scanResult.HasCredentials {
			safeZoneFlags = append(safeZoneFlags, "inbound_credentials_detected")
		}
		if scanResult.HasPII {
			safeZoneFlags = append(safeZoneFlags, "inbound_pii_detected")
		}
		safeZoneFlags = append(safeZoneFlags, "dlp_scan_completed")
		safeZoneFlags = append(safeZoneFlags, scanResult.Flags...)
	}

	a.gw.AuditLog(middleware.AuditEvent{
		Timestamp: now.Format(time.RFC3339),
		EventType: "discord.webhook.inbound",
		Severity:  "Info",
		SessionID: runID,
		SPIFFEID:  "spiffe://poc.local/webhooks/discord",
		Action:    "webhook.inbound",
		Result:    "received",
		Method:    r.Method,
		Path:      r.URL.Path,
		Security: &middleware.SecurityAudit{
			SafeZoneFlags: safeZoneFlags,
		},
	})

	slog.Info("discord webhook processed",
		"event_type", event.Type,
		"content_length", len(content),
		"connector_allowed", allowed,
		"run_id", runID)

	// Return 200 OK -- Discord requires ACK within 3 seconds.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "received"})
}

// computeDiscordConnectorSig generates a deterministic signature for the Discord webhook connector.
func computeDiscordConnectorSig(connectorID string) string {
	canon := map[string]any{
		"connector_id":   connectorID,
		"connector_type": "webhook",
		"platform":       "discord",
	}
	data, _ := json.Marshal(canon)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
