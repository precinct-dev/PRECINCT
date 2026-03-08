package protocol

import (
	"encoding/json"
	"errors"
)

// SendEmailRequest is the request body for POST /email/send.
type SendEmailRequest struct {
	To             []string `json:"to"`
	CC             []string `json:"cc,omitempty"`
	BCC            []string `json:"bcc,omitempty"`
	Subject        string   `json:"subject"`
	Body           string   `json:"body"`
	AttachmentRefs []string `json:"attachment_refs,omitempty"`
}

// Validate checks that the required fields are present.
func (r *SendEmailRequest) Validate() error {
	if len(r.To) == 0 {
		return errors.New("to is required")
	}
	if r.Subject == "" {
		return errors.New("subject is required")
	}
	if r.Body == "" {
		return errors.New("body is required")
	}
	return nil
}

// EmailWebhookEvent is the inbound webhook payload from an email provider.
type EmailWebhookEvent struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Signature string          `json:"signature"`
	Timestamp string          `json:"timestamp"`
}

// EmailListRequest is the request body for POST /email/list.
type EmailListRequest struct {
	Folder string `json:"folder,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// EmailReadRequest is the request body for POST /email/read.
type EmailReadRequest struct {
	MessageID string `json:"message_id"`
}

// SendEmailResponse is the response body for POST /email/send.
type SendEmailResponse struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
}

// EmailSummary is a single entry in the email list response.
type EmailSummary struct {
	MessageID  string `json:"message_id"`
	Subject    string `json:"subject"`
	From       string `json:"from"`
	ReceivedAt string `json:"received_at"`
}

// EmailListResponse is the response body for POST /email/list.
type EmailListResponse struct {
	Emails []EmailSummary `json:"emails"`
}

// EmailContent is the response body for POST /email/read.
type EmailContent struct {
	MessageID  string `json:"message_id"`
	Subject    string `json:"subject"`
	From       string `json:"from"`
	Body       string `json:"body"`
	ReceivedAt string `json:"received_at"`
}
