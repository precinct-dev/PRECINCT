package email

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/precinct-dev/precinct/ports/email/protocol"
)

// mockGatewayServices captures calls to gateway methods for assertion.
type mockGatewayServices struct {
	// EvaluateToolRequest captures
	lastPlaneReq   gateway.PlaneRequestV2
	evalResult     gateway.ToolPlaneEvalResult
	evalCallCount  int

	// ExecuteMessagingEgress captures
	lastEgressAttrs   map[string]string
	lastEgressPayload []byte
	egressResult      *gateway.MessagingEgressResult
	egressErr         error
	egressCallCount   int

	// RedeemSPIKESecret captures
	lastSPIKEToken    string
	spikeResult       string
	spikeErr          error
	spikeCallCount    int
}

func (m *mockGatewayServices) BuildModelPlaneRequest(_ *http.Request, _ map[string]any) gateway.PlaneRequestV2 {
	return gateway.PlaneRequestV2{}
}
func (m *mockGatewayServices) EvaluateModelPlaneDecision(_ *http.Request, _ gateway.PlaneRequestV2) (gateway.Decision, gateway.ReasonCode, int, map[string]any) {
	return gateway.DecisionAllow, "", 200, nil
}
func (m *mockGatewayServices) ExecuteModelEgress(_ context.Context, _ map[string]any, _ map[string]any, _ string) (*gateway.ModelEgressResult, error) {
	return nil, nil
}
func (m *mockGatewayServices) ShouldApplyPolicyIntentProjection() bool { return false }

func (m *mockGatewayServices) EvaluateToolRequest(req gateway.PlaneRequestV2) gateway.ToolPlaneEvalResult {
	m.lastPlaneReq = req
	m.evalCallCount++
	return m.evalResult
}

func (m *mockGatewayServices) ExecuteMessagingEgress(_ context.Context, attrs map[string]string, payload []byte, _ string) (*gateway.MessagingEgressResult, error) {
	m.lastEgressAttrs = attrs
	m.lastEgressPayload = payload
	m.egressCallCount++
	return m.egressResult, m.egressErr
}

func (m *mockGatewayServices) RedeemSPIKESecret(_ context.Context, tokenStr string) (string, error) {
	m.lastSPIKEToken = tokenStr
	m.spikeCallCount++
	return m.spikeResult, m.spikeErr
}

func (m *mockGatewayServices) LogPlaneDecision(_ *http.Request, _ gateway.PlaneDecisionV2, _ int) {}
func (m *mockGatewayServices) AuditLog(_ middleware.AuditEvent)                                    {}
func (m *mockGatewayServices) WriteGatewayError(w http.ResponseWriter, _ *http.Request, httpCode int, errorCode string, message string, _ string, _ gateway.ReasonCode, _ map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   errorCode,
		"message": message,
	})
}
func (m *mockGatewayServices) ValidateAndConsumeApproval(_ string, _ middleware.ApprovalScope) (*middleware.ApprovalCapabilityClaims, error) {
	return nil, nil
}
func (m *mockGatewayServices) HasApprovalService() bool                       { return false }
func (m *mockGatewayServices) ValidateConnector(_, _ string) (bool, string)   { return true, "" }
func (m *mockGatewayServices) ScanContent(_ string) middleware.ScanResult    { return middleware.ScanResult{} }

// newAllowMock returns a mock that allows all tool requests and returns a
// successful egress result.
func newAllowMock() *mockGatewayServices {
	return &mockGatewayServices{
		evalResult: gateway.ToolPlaneEvalResult{
			Decision:   gateway.DecisionAllow,
			Reason:     gateway.ReasonToolAllow,
			HTTPStatus: http.StatusOK,
		},
		egressResult: &gateway.MessagingEgressResult{
			StatusCode: http.StatusOK,
			MessageID:  "mock-msg-id",
			Platform:   "email",
		},
	}
}

func sendEmailRequest(to []string, subject, body string) []byte {
	req := protocol.SendEmailRequest{
		To:      to,
		Subject: subject,
		Body:    body,
	}
	b, _ := json.Marshal(req)
	return b
}

func sendEmailRequestFull(to, cc, bcc []string, subject, body string, attachmentRefs []string) []byte {
	req := protocol.SendEmailRequest{
		To:             to,
		CC:             cc,
		BCC:            bcc,
		Subject:        subject,
		Body:           body,
		AttachmentRefs: attachmentRefs,
	}
	b, _ := json.Marshal(req)
	return b
}

// TestHandleSend_DLPBlocking verifies that the full email content (subject + body)
// is passed to EvaluateToolRequest so DLP middleware can scan it. When the
// policy denies (e.g., AWS key detected), the handler returns the denial.
func TestHandleSend_DLPBlocking(t *testing.T) {
	mock := &mockGatewayServices{
		evalResult: gateway.ToolPlaneEvalResult{
			Decision:   gateway.DecisionDeny,
			Reason:     gateway.ReasonContextDLPDenied,
			HTTPStatus: http.StatusForbidden,
		},
	}
	adapter := NewAdapter(mock)

	body := sendEmailRequest(
		[]string{"alice@example.com"},
		"Credential Leak",
		"Here is the key: AKIAIOSFODNN7EXAMPLE",
	)
	req := httptest.NewRequest(http.MethodPost, pathSend, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://test/agent")
	rr := httptest.NewRecorder()
	adapter.handleSendImpl(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	if mock.evalCallCount != 1 {
		t.Fatalf("EvaluateToolRequest call count = %d, want 1", mock.evalCallCount)
	}

	// Verify the payload contains the credential for DLP scanning.
	policyAttrs := mock.lastPlaneReq.Policy.Attributes
	if policyAttrs == nil {
		t.Fatal("policy attributes are nil")
	}
	if policyAttrs["tool_name"] != "messaging_send" {
		t.Fatalf("tool_name = %v, want messaging_send", policyAttrs["tool_name"])
	}
}

// TestHandleSend_MassEmail verifies that sending to more than massEmailThreshold
// recipients triggers step-up approval required (OC-di1n).
func TestHandleSend_MassEmail(t *testing.T) {
	mock := newAllowMock()
	adapter := NewAdapter(mock)

	// Generate 15 recipients (> 10 threshold).
	to := make([]string, 15)
	for i := range to {
		to[i] = "user" + strings.Repeat("x", 1) + "@example.com"
	}

	body := sendEmailRequest(to, "Mass Email Test", "Hello everyone")
	req := httptest.NewRequest(http.MethodPost, pathSend, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://test/agent")
	rr := httptest.NewRecorder()
	adapter.handleSendImpl(rr, req)

	// OC-di1n: mass email should require step-up approval.
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body: %s)", rr.Code, http.StatusForbidden, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	code, _ := resp["code"].(string)
	if code != middleware.ErrStepUpApprovalRequired {
		t.Fatalf("code = %q, want %q", code, middleware.ErrStepUpApprovalRequired)
	}
}

// TestHandleSend_NotMassEmail verifies that sending to 10 or fewer recipients
// sets mass_email to "false".
func TestHandleSend_NotMassEmail(t *testing.T) {
	mock := newAllowMock()
	adapter := NewAdapter(mock)

	body := sendEmailRequest([]string{"a@b.com"}, "Single", "Body")
	req := httptest.NewRequest(http.MethodPost, pathSend, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://test/agent")
	rr := httptest.NewRecorder()
	adapter.handleSendImpl(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if mock.lastPlaneReq.Policy.Attributes["mass_email"] != "false" {
		t.Fatalf("mass_email = %v, want false", mock.lastPlaneReq.Policy.Attributes["mass_email"])
	}
}

// TestHandleSend_SPIKETokenRedemption verifies that attachment_refs containing
// SPIKE tokens trigger RedeemSPIKESecret calls.
func TestHandleSend_SPIKETokenRedemption(t *testing.T) {
	mock := newAllowMock()
	mock.spikeResult = "resolved-secret-value"
	adapter := NewAdapter(mock)

	body := sendEmailRequestFull(
		[]string{"user@example.com"}, nil, nil,
		"With attachment", "See attached",
		[]string{"$SPIKE{ref:abc123}"},
	)
	req := httptest.NewRequest(http.MethodPost, pathSend, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://test/agent")
	rr := httptest.NewRecorder()
	adapter.handleSendImpl(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}
	if mock.spikeCallCount != 1 {
		t.Fatalf("RedeemSPIKESecret call count = %d, want 1", mock.spikeCallCount)
	}
	if mock.lastSPIKEToken != "$SPIKE{ref:abc123}" {
		t.Fatalf("SPIKE token = %q, want $SPIKE{ref:abc123}", mock.lastSPIKEToken)
	}
}

// TestHandleSend_RecipientDomainExtraction verifies that recipient domains
// are extracted and set in attributes for OPA policy evaluation.
func TestHandleSend_RecipientDomainExtraction(t *testing.T) {
	mock := newAllowMock()
	adapter := NewAdapter(mock)

	body := sendEmailRequestFull(
		[]string{"alice@example.com"},
		[]string{"bob@corp.com"},
		[]string{"carol@example.com"}, // duplicate domain with To
		"Domain Test", "Body text", nil,
	)
	req := httptest.NewRequest(http.MethodPost, pathSend, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://test/agent")
	rr := httptest.NewRecorder()
	adapter.handleSendImpl(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	domains, ok := mock.lastPlaneReq.Policy.Attributes["recipient_domains"].(string)
	if !ok {
		t.Fatal("recipient_domains attribute not set or not a string")
	}
	if !strings.Contains(domains, "example.com") {
		t.Fatalf("recipient_domains %q does not contain example.com", domains)
	}
	if !strings.Contains(domains, "corp.com") {
		t.Fatalf("recipient_domains %q does not contain corp.com", domains)
	}
	// Verify deduplication: example.com should appear only once.
	count := strings.Count(domains, "example.com")
	if count != 1 {
		t.Fatalf("example.com appears %d times in %q, want 1", count, domains)
	}
}

// TestHandleSend_ValidationRejects verifies that missing required fields
// result in 400 Bad Request.
func TestHandleSend_ValidationRejects(t *testing.T) {
	mock := newAllowMock()
	adapter := NewAdapter(mock)

	tests := []struct {
		name string
		body []byte
	}{
		{"missing_to", sendEmailRequest(nil, "Subject", "Body")},
		{"empty_to", sendEmailRequest([]string{}, "Subject", "Body")},
		{"missing_subject", sendEmailRequest([]string{"a@b.com"}, "", "Body")},
		{"missing_body", sendEmailRequest([]string{"a@b.com"}, "Subject", "")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, pathSend, bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			adapter.handleSendImpl(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body: %s)", rr.Code, http.StatusBadRequest, rr.Body.String())
			}
		})
	}
}

// TestHandleSend_MethodNotAllowed verifies GET to /email/send returns 405.
func TestHandleSend_MethodNotAllowed(t *testing.T) {
	mock := newAllowMock()
	adapter := NewAdapter(mock)

	req := httptest.NewRequest(http.MethodGet, pathSend, nil)
	rr := httptest.NewRecorder()
	adapter.handleSendImpl(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

// TestHandleSend_SuccessResponse verifies that a successful send returns
// a SendEmailResponse with a message_id and status="queued".
func TestHandleSend_SuccessResponse(t *testing.T) {
	mock := newAllowMock()
	adapter := NewAdapter(mock)

	body := sendEmailRequest([]string{"user@test.com"}, "Hello", "World")
	req := httptest.NewRequest(http.MethodPost, pathSend, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://test/agent")
	rr := httptest.NewRecorder()
	adapter.handleSendImpl(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp protocol.SendEmailResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "queued" {
		t.Fatalf("status = %q, want %q", resp.Status, "queued")
	}
	if resp.MessageID == "" {
		t.Fatal("message_id is empty")
	}
}

// TestHandleSend_PlaneRequestToolName verifies that the PlaneRequestV2
// uses tool name "messaging_send" for consistency with the tool taxonomy.
func TestHandleSend_PlaneRequestToolName(t *testing.T) {
	mock := newAllowMock()
	adapter := NewAdapter(mock)

	body := sendEmailRequest([]string{"user@test.com"}, "Subject", "Body")
	req := httptest.NewRequest(http.MethodPost, pathSend, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://test/agent")
	rr := httptest.NewRecorder()
	adapter.handleSendImpl(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if mock.lastPlaneReq.Policy.Resource != "messaging_send" {
		t.Fatalf("resource = %q, want messaging_send", mock.lastPlaneReq.Policy.Resource)
	}
	if mock.lastPlaneReq.Policy.Attributes["tool_name"] != "messaging_send" {
		t.Fatalf("tool_name = %v, want messaging_send", mock.lastPlaneReq.Policy.Attributes["tool_name"])
	}
	if mock.lastPlaneReq.Envelope.Plane != gateway.PlaneTool {
		t.Fatalf("plane = %q, want %q", mock.lastPlaneReq.Envelope.Plane, gateway.PlaneTool)
	}
}

// TestExtractDomains verifies the domain extraction helper.
func TestExtractDomains(t *testing.T) {
	tests := []struct {
		name string
		to   []string
		cc   []string
		bcc  []string
		want []string
	}{
		{
			name: "basic",
			to:   []string{"alice@example.com", "bob@corp.com"},
			want: []string{"example.com", "corp.com"},
		},
		{
			name: "dedup",
			to:   []string{"a@example.com"},
			cc:   []string{"b@example.com"},
			want: []string{"example.com"},
		},
		{
			name: "angle_bracket",
			to:   []string{"Alice <alice@example.com>"},
			want: []string{"example.com"},
		},
		{
			name: "empty",
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractDomains(tc.to, tc.cc, tc.bcc)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i, d := range tc.want {
				if got[i] != d {
					t.Fatalf("got[%d] = %q, want %q", i, got[i], d)
				}
			}
		})
	}
}

// TestTruncate verifies the truncate helper.
func TestTruncate(t *testing.T) {
	if got := truncate("hello world", 5); got != "hello" {
		t.Fatalf("truncate = %q, want hello", got)
	}
	if got := truncate("hi", 10); got != "hi" {
		t.Fatalf("truncate = %q, want hi", got)
	}
}

// TestHandleSend_SubjectBodyConcatenation verifies that subject and body
// are concatenated in the payload for DLP scanning.
func TestHandleSend_SubjectBodyConcatenation(t *testing.T) {
	mock := newAllowMock()
	adapter := NewAdapter(mock)

	body := sendEmailRequest([]string{"user@test.com"}, "Test Subject", "Test Body Content")
	req := httptest.NewRequest(http.MethodPost, pathSend, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://test/agent")
	rr := httptest.NewRecorder()
	adapter.handleSendImpl(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify the egress payload contains subject + newline + body.
	expected := "Test Subject\nTest Body Content"
	if string(mock.lastEgressPayload) != expected {
		t.Fatalf("egress payload = %q, want %q", string(mock.lastEgressPayload), expected)
	}
}

// TestHandleSend_HasAttachments verifies the has_attachments attribute.
func TestHandleSend_HasAttachments(t *testing.T) {
	mock := newAllowMock()
	adapter := NewAdapter(mock)

	// With attachments.
	body := sendEmailRequestFull(
		[]string{"user@test.com"}, nil, nil,
		"Subject", "Body",
		[]string{"file-ref-1"},
	)
	req := httptest.NewRequest(http.MethodPost, pathSend, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://test/agent")
	rr := httptest.NewRecorder()
	adapter.handleSendImpl(rr, req)

	if mock.lastPlaneReq.Policy.Attributes["has_attachments"] != "true" {
		t.Fatalf("has_attachments = %v, want true", mock.lastPlaneReq.Policy.Attributes["has_attachments"])
	}

	// Without attachments.
	body = sendEmailRequest([]string{"user@test.com"}, "Subject", "Body")
	req = httptest.NewRequest(http.MethodPost, pathSend, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", "spiffe://test/agent")
	rr = httptest.NewRecorder()
	adapter.handleSendImpl(rr, req)

	if mock.lastPlaneReq.Policy.Attributes["has_attachments"] != "false" {
		t.Fatalf("has_attachments = %v, want false", mock.lastPlaneReq.Policy.Attributes["has_attachments"])
	}
}
