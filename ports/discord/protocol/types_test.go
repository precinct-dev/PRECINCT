package protocol

import (
	"encoding/json"
	"testing"
)

// TestSendMessageRequest_JSONRoundtrip verifies marshal/unmarshal with all fields.
func TestSendMessageRequest_JSONRoundtrip(t *testing.T) {
	orig := SendMessageRequest{
		ChannelID: "123456789",
		Content:   "Hello, world!",
		Embeds: []Embed{
			{Title: "Test", Description: "A test embed", URL: "https://example.com"},
		},
		ReplyTo: "987654321",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Verify JSON keys match the expected tags.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}
	for _, key := range []string{"channel_id", "content", "embeds", "reply_to"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("Expected JSON key %q not found", key)
		}
	}

	var decoded SendMessageRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if decoded.ChannelID != orig.ChannelID {
		t.Errorf("ChannelID = %q, want %q", decoded.ChannelID, orig.ChannelID)
	}
	if decoded.Content != orig.Content {
		t.Errorf("Content = %q, want %q", decoded.Content, orig.Content)
	}
	if len(decoded.Embeds) != 1 {
		t.Fatalf("Embeds len = %d, want 1", len(decoded.Embeds))
	}
	if decoded.Embeds[0].Title != "Test" {
		t.Errorf("Embed title = %q, want %q", decoded.Embeds[0].Title, "Test")
	}
	if decoded.Embeds[0].URL != "https://example.com" {
		t.Errorf("Embed URL = %q, want %q", decoded.Embeds[0].URL, "https://example.com")
	}
	if decoded.ReplyTo != orig.ReplyTo {
		t.Errorf("ReplyTo = %q, want %q", decoded.ReplyTo, orig.ReplyTo)
	}
}

// TestWebhookEvent_JSONRoundtrip verifies marshal/unmarshal with raw JSON data.
func TestWebhookEvent_JSONRoundtrip(t *testing.T) {
	rawData := json.RawMessage(`{"guild_id":"111","content":"test message"}`)
	orig := WebhookEvent{
		Type:      "MESSAGE_CREATE",
		Signature: "ed25519:abc123",
		Timestamp: "2026-03-07T00:00:00Z",
		Data:      rawData,
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded WebhookEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if decoded.Type != orig.Type {
		t.Errorf("Type = %q, want %q", decoded.Type, orig.Type)
	}
	if decoded.Signature != orig.Signature {
		t.Errorf("Signature = %q, want %q", decoded.Signature, orig.Signature)
	}
	if decoded.Timestamp != orig.Timestamp {
		t.Errorf("Timestamp = %q, want %q", decoded.Timestamp, orig.Timestamp)
	}

	// Verify the raw JSON data round-trips correctly.
	var dataMap map[string]interface{}
	if err := json.Unmarshal(decoded.Data, &dataMap); err != nil {
		t.Fatalf("Failed to unmarshal Data: %v", err)
	}
	if dataMap["guild_id"] != "111" {
		t.Errorf("Data guild_id = %v, want %q", dataMap["guild_id"], "111")
	}
}

// TestBotCommandRequest_JSONRoundtrip verifies marshal/unmarshal with options map.
func TestBotCommandRequest_JSONRoundtrip(t *testing.T) {
	orig := BotCommandRequest{
		Command: "deploy",
		GuildID: "444555666",
		Options: map[string]interface{}{
			"env":     "staging",
			"dry_run": true,
			"count":   float64(3),
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Verify JSON keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}
	for _, key := range []string{"command", "guild_id", "options"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("Expected JSON key %q not found", key)
		}
	}

	var decoded BotCommandRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if decoded.Command != orig.Command {
		t.Errorf("Command = %q, want %q", decoded.Command, orig.Command)
	}
	if decoded.GuildID != orig.GuildID {
		t.Errorf("GuildID = %q, want %q", decoded.GuildID, orig.GuildID)
	}
	if decoded.Options["env"] != "staging" {
		t.Errorf("Options[env] = %v, want %q", decoded.Options["env"], "staging")
	}
	if decoded.Options["dry_run"] != true {
		t.Errorf("Options[dry_run] = %v, want true", decoded.Options["dry_run"])
	}
}
