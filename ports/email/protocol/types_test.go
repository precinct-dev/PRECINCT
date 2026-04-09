// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"encoding/json"
	"testing"
)

func TestSendEmailRequest_JSONRoundtrip(t *testing.T) {
	original := SendEmailRequest{
		To:             []string{"alice@example.com", "bob@example.com"},
		CC:             []string{"cc@example.com"},
		BCC:            []string{"bcc@example.com"},
		Subject:        "Test Subject",
		Body:           "Hello, world!",
		AttachmentRefs: []string{"ref-abc", "ref-def"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded SendEmailRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.To) != 2 || decoded.To[0] != "alice@example.com" {
		t.Fatalf("To mismatch: got %v", decoded.To)
	}
	if decoded.Subject != "Test Subject" {
		t.Fatalf("Subject mismatch: got %q", decoded.Subject)
	}
	if decoded.Body != "Hello, world!" {
		t.Fatalf("Body mismatch: got %q", decoded.Body)
	}
	if len(decoded.CC) != 1 || decoded.CC[0] != "cc@example.com" {
		t.Fatalf("CC mismatch: got %v", decoded.CC)
	}
	if len(decoded.BCC) != 1 || decoded.BCC[0] != "bcc@example.com" {
		t.Fatalf("BCC mismatch: got %v", decoded.BCC)
	}
	if len(decoded.AttachmentRefs) != 2 {
		t.Fatalf("AttachmentRefs mismatch: got %v", decoded.AttachmentRefs)
	}
}

func TestSendEmailRequest_Validate_RequiresTo(t *testing.T) {
	req := SendEmailRequest{
		Subject: "Test",
		Body:    "body",
	}
	if err := req.Validate(); err == nil {
		t.Fatal("Validate() should return error when To is empty")
	}
}

func TestSendEmailRequest_Validate_RequiresSubject(t *testing.T) {
	req := SendEmailRequest{
		To:   []string{"alice@example.com"},
		Body: "body",
	}
	if err := req.Validate(); err == nil {
		t.Fatal("Validate() should return error when Subject is empty")
	}
}

func TestSendEmailRequest_Validate_RequiresBody(t *testing.T) {
	req := SendEmailRequest{
		To:      []string{"alice@example.com"},
		Subject: "Test",
	}
	if err := req.Validate(); err == nil {
		t.Fatal("Validate() should return error when Body is empty")
	}
}

func TestSendEmailRequest_Validate_Valid(t *testing.T) {
	req := SendEmailRequest{
		To:      []string{"alice@example.com"},
		Subject: "Test",
		Body:    "body",
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate() returned unexpected error: %v", err)
	}
}

func TestEmailListRequest_JSONRoundtrip(t *testing.T) {
	original := EmailListRequest{
		Folder: "inbox",
		Limit:  50,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EmailListRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Folder != "inbox" {
		t.Fatalf("Folder mismatch: got %q", decoded.Folder)
	}
	if decoded.Limit != 50 {
		t.Fatalf("Limit mismatch: got %d", decoded.Limit)
	}
}

func TestEmailReadRequest_JSONRoundtrip(t *testing.T) {
	original := EmailReadRequest{
		MessageID: "msg-12345",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EmailReadRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.MessageID != "msg-12345" {
		t.Fatalf("MessageID mismatch: got %q", decoded.MessageID)
	}
}

func TestEmailWebhookEvent_JSONRoundtrip(t *testing.T) {
	original := EmailWebhookEvent{
		Type:      "delivery",
		Signature: "sig-abc",
		Timestamp: "2026-03-07T12:00:00Z",
		Data:      json.RawMessage(`{"status":"delivered"}`),
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EmailWebhookEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != "delivery" {
		t.Fatalf("Type mismatch: got %q", decoded.Type)
	}
	if decoded.Signature != "sig-abc" {
		t.Fatalf("Signature mismatch: got %q", decoded.Signature)
	}
	if decoded.Timestamp != "2026-03-07T12:00:00Z" {
		t.Fatalf("Timestamp mismatch: got %q", decoded.Timestamp)
	}
	if string(decoded.Data) != `{"status":"delivered"}` {
		t.Fatalf("Data mismatch: got %s", string(decoded.Data))
	}
}

func TestSendEmailResponse_JSONRoundtrip(t *testing.T) {
	original := SendEmailResponse{
		MessageID: "msg-001",
		Status:    "queued",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded SendEmailResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.MessageID != "msg-001" {
		t.Fatalf("MessageID mismatch: got %q", decoded.MessageID)
	}
	if decoded.Status != "queued" {
		t.Fatalf("Status mismatch: got %q", decoded.Status)
	}
}

func TestEmailSummary_JSONRoundtrip(t *testing.T) {
	original := EmailSummary{
		MessageID:  "msg-002",
		Subject:    "Hello",
		From:       "alice@example.com",
		ReceivedAt: "2026-03-07T12:00:00Z",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EmailSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.MessageID != "msg-002" {
		t.Fatalf("MessageID mismatch: got %q", decoded.MessageID)
	}
	if decoded.Subject != "Hello" {
		t.Fatalf("Subject mismatch: got %q", decoded.Subject)
	}
	if decoded.From != "alice@example.com" {
		t.Fatalf("From mismatch: got %q", decoded.From)
	}
	if decoded.ReceivedAt != "2026-03-07T12:00:00Z" {
		t.Fatalf("ReceivedAt mismatch: got %q", decoded.ReceivedAt)
	}
}

func TestEmailContent_JSONRoundtrip(t *testing.T) {
	original := EmailContent{
		MessageID:  "msg-003",
		Subject:    "Re: Hello",
		From:       "bob@example.com",
		Body:       "Thanks for your message.",
		ReceivedAt: "2026-03-07T13:00:00Z",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EmailContent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.MessageID != "msg-003" {
		t.Fatalf("MessageID mismatch: got %q", decoded.MessageID)
	}
	if decoded.Subject != "Re: Hello" {
		t.Fatalf("Subject mismatch: got %q", decoded.Subject)
	}
	if decoded.From != "bob@example.com" {
		t.Fatalf("From mismatch: got %q", decoded.From)
	}
	if decoded.Body != "Thanks for your message." {
		t.Fatalf("Body mismatch: got %q", decoded.Body)
	}
	if decoded.ReceivedAt != "2026-03-07T13:00:00Z" {
		t.Fatalf("ReceivedAt mismatch: got %q", decoded.ReceivedAt)
	}
}

func TestEmailListResponse_JSONRoundtrip(t *testing.T) {
	original := EmailListResponse{
		Emails: []EmailSummary{
			{MessageID: "msg-001", Subject: "First", From: "a@b.com", ReceivedAt: "2026-03-07T10:00:00Z"},
			{MessageID: "msg-002", Subject: "Second", From: "c@d.com", ReceivedAt: "2026-03-07T11:00:00Z"},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EmailListResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Emails) != 2 {
		t.Fatalf("Emails length = %d, want 2", len(decoded.Emails))
	}
	if decoded.Emails[0].MessageID != "msg-001" {
		t.Fatalf("first email MessageID = %q, want %q", decoded.Emails[0].MessageID, "msg-001")
	}
}
