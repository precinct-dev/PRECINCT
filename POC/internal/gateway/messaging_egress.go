package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// MessagingEgressResult holds the result of a messaging platform egress call.
type MessagingEgressResult struct {
	StatusCode int
	Body       []byte
	MessageID  string
	Platform   string
}

// executeMessagingEgress sends a payload to a messaging platform endpoint.
// It follows the same destination-validation pattern as executeModelEgress:
// env-var override -> production URL -> validation against allowlist.
func (g *Gateway) executeMessagingEgress(ctx context.Context, attrs map[string]string, payload []byte, authHeader string) (*MessagingEgressResult, error) {
	platform := strings.ToLower(strings.TrimSpace(attrs["platform"]))
	if platform == "" {
		return nil, fmt.Errorf("messaging platform is required")
	}

	target, err := g.resolveMessagingTarget(platform, attrs)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build messaging request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(authHeader) != "" {
		req.Header.Set("Authorization", authHeader)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("messaging egress HTTP call failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read messaging response: %w", err)
	}

	messageID := extractMessageID(platform, respBody)

	return &MessagingEgressResult{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		MessageID:  messageID,
		Platform:   platform,
	}, nil
}

// resolveMessagingTarget resolves the endpoint URL for a messaging platform.
// Priority: MESSAGING_PLATFORM_ENDPOINT_<PLATFORM> env var -> production URLs -> error.
// For Telegram production, the bot_token attribute is required to build /bot<token>/sendMessage.
func (g *Gateway) resolveMessagingTarget(platform string, attrs map[string]string) (*url.URL, error) {
	envKey := "MESSAGING_PLATFORM_ENDPOINT_" + strings.ToUpper(platform)
	endpoint := strings.TrimSpace(os.Getenv(envKey))

	if endpoint == "" {
		switch platform {
		case "whatsapp":
			endpoint = "https://graph.facebook.com/v17.0/messages"
		case "telegram":
			botToken := strings.TrimSpace(attrs["bot_token"])
			if botToken == "" {
				return nil, fmt.Errorf("telegram requires bot_token attribute for production endpoint")
			}
			endpoint = "https://api.telegram.org/bot" + botToken + "/sendMessage"
		case "slack":
			endpoint = "https://slack.com/api/chat.postMessage"
		default:
			return nil, fmt.Errorf("unsupported messaging platform: %s", platform)
		}
	}

	target, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid messaging endpoint: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(target.Hostname()))
	if host == "" {
		return nil, fmt.Errorf("messaging endpoint host is empty")
	}

	// Require HTTPS for production destinations; allow HTTP for local dev
	// (same logic as model egress).
	if target.Scheme != "https" && !isLocalHost(host) && !isSingleLabelHostname(host) {
		return nil, fmt.Errorf("messaging endpoint must use https outside local development")
	}

	return target, nil
}

// extractMessageID attempts to pull the message ID from a platform-specific
// JSON response body.
//   - WhatsApp: {"messages":[{"id":"wamid.xxx"}]}
//   - Telegram: {"ok":true,"result":{"message_id":42,...}}
//   - Slack:    {"ok":true,"ts":"1234567890.123456",...}
func extractMessageID(platform string, body []byte) string {
	switch platform {
	case "telegram":
		return extractTelegramMessageID(body)
	case "slack":
		return extractSlackMessageID(body)
	default:
		return extractWhatsAppMessageID(body)
	}
}

// extractWhatsAppMessageID parses WhatsApp response format.
func extractWhatsAppMessageID(body []byte) string {
	var parsed struct {
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}
	if len(parsed.Messages) > 0 {
		return strings.TrimSpace(parsed.Messages[0].ID)
	}
	return ""
}

// extractTelegramMessageID parses Telegram response format.
// Telegram returns message_id as a JSON number (float64 in Go's JSON decoder).
func extractTelegramMessageID(body []byte) string {
	var parsed struct {
		OK     bool `json:"ok"`
		Result struct {
			MessageID float64 `json:"message_id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}
	if !parsed.OK {
		return ""
	}
	if parsed.Result.MessageID == 0 {
		return ""
	}
	return fmt.Sprintf("%d", int64(parsed.Result.MessageID))
}

// extractSlackMessageID parses Slack response format.
// Slack uses the "ts" field as the message identifier.
func extractSlackMessageID(body []byte) string {
	var parsed struct {
		OK bool   `json:"ok"`
		TS string `json:"ts"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}
	if !parsed.OK {
		return ""
	}
	return strings.TrimSpace(parsed.TS)
}
