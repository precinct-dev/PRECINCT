// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package protocol

import "encoding/json"

// SendMessageRequest represents an outbound Discord message.
type SendMessageRequest struct {
	ChannelID string  `json:"channel_id"`
	Content   string  `json:"content"`
	Embeds    []Embed `json:"embeds,omitempty"`
	ReplyTo   string  `json:"reply_to,omitempty"`
}

// Embed represents a Discord rich embed.
type Embed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url,omitempty"`
}

// WebhookEvent represents an inbound Discord webhook event.
type WebhookEvent struct {
	Type      string          `json:"type"`
	Signature string          `json:"signature"`
	Timestamp string          `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// BotCommandRequest represents a Discord bot slash-command invocation.
type BotCommandRequest struct {
	Command string                 `json:"command"`
	GuildID string                 `json:"guild_id"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// SendMessageResponse is the response from the send-message endpoint.
type SendMessageResponse struct {
	OK        bool   `json:"ok"`
	MessageID string `json:"message_id,omitempty"`
	Error     string `json:"error,omitempty"`
}
