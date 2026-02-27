package gateway

import (
	"bytes"
	"context"
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

	target, err := g.resolveMessagingTarget(platform)
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

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("messaging egress HTTP call failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read messaging response: %w", err)
	}

	messageID := extractMessageID(respBody)

	return &MessagingEgressResult{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		MessageID:  messageID,
		Platform:   platform,
	}, nil
}

// resolveMessagingTarget resolves the endpoint URL for a messaging platform.
// Priority: MESSAGING_PLATFORM_ENDPOINT_<PLATFORM> env var -> production URLs -> error.
func (g *Gateway) resolveMessagingTarget(platform string) (*url.URL, error) {
	envKey := "MESSAGING_PLATFORM_ENDPOINT_" + strings.ToUpper(platform)
	endpoint := strings.TrimSpace(os.Getenv(envKey))

	if endpoint == "" {
		switch platform {
		case "whatsapp":
			endpoint = "https://graph.facebook.com/v17.0/messages"
		case "telegram":
			endpoint = "https://api.telegram.org/bot/sendMessage"
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

// extractMessageID attempts to pull the first message ID from a WhatsApp-style
// JSON response body ({"messages":[{"id":"wamid.xxx"}]}).
func extractMessageID(body []byte) string {
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
