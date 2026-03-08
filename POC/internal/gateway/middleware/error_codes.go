// Error code catalog for the unified gateway error envelope.
// RFA-tj9.1: Machine-readable codes for every denial path. Each code
// maps to a specific middleware and HTTP status code.
package middleware

// Error code constants. Naming convention: <middleware>_<reason>.
// The associated HTTP status codes are documented but not encoded here
// because the same code can appear in different status contexts (e.g.
// a 403 in normal flow vs a 503 when the service backing the check is down).
const (
	// SPIFFE Auth (step 3) -- 401 Unauthorized
	ErrAuthMissingIdentity = "auth_missing_identity"
	ErrAuthInvalidIdentity = "auth_invalid_identity"

	// OPA Policy (step 6) -- 403 Forbidden
	ErrAuthzPolicyDenied    = "authz_policy_denied"
	ErrAuthzNoMatchingGrant = "authz_no_matching_grant"
	ErrAuthzToolNotFound    = "authz_tool_not_found"

	// Tool Registry (step 5) -- 403 Forbidden
	ErrRegistryHashMismatch = "registry_hash_mismatch"
	ErrRegistryToolUnknown  = "registry_tool_unknown"

	// DLP (step 7) -- 403 Forbidden
	ErrDLPCredentialsDetected   = "dlp_credentials_detected"
	ErrDLPInjectionBlocked      = "dlp_injection_blocked" // RFA-sd7: injection blocked by policy
	ErrDLPPIIBlocked            = "dlp_pii_blocked"       // RFA-sd7: PII blocked by policy
	ErrDLPUnavailableFailClosed = "dlp_unavailable_fail_closed"

	// Step-Up Gating (step 9) -- 403 Forbidden
	ErrStepUpDenied                = "stepup_denied"
	ErrStepUpApprovalRequired      = "stepup_approval_required"
	ErrStepUpGuardBlocked          = "stepup_guard_blocked"
	ErrStepUpDestinationBlocked    = "stepup_destination_blocked"
	ErrStepUpUnavailableFailClosed = "stepup_unavailable_fail_closed"
	ErrIrreversibleActionDenied    = "irreversible_action_denied" // OC-h4m7: step 9, HTTP 403

	// Deep Scan (step 10) -- 403 / 503
	ErrDeepScanBlocked               = "deepscan_blocked"
	ErrDeepScanUnavailableFailClosed = "deepscan_unavailable_fail_closed"

	// Rate Limiting (step 11) -- 429 Too Many Requests
	ErrRateLimitExceeded = "ratelimit_exceeded"

	// Circuit Breaker (step 12) -- 503 Service Unavailable
	ErrCircuitOpen = "circuit_open"

	// Request Size (step 1) -- 413 Request Entity Too Large
	ErrRequestTooLarge = "request_too_large"

	// Session Context (step 8) -- 403 Forbidden
	ErrExfiltrationDetected = "exfiltration_detected"

	// Response Firewall (step 14) -- 503 / 500
	ErrResponseHandleStoreUnavailable = "response_handle_store_unavailable"
	ErrResponseHandleizationFailed    = "response_handleization_failed"

	// UI Capability Gating -- 403 Forbidden
	ErrUICapabilityDenied = "ui_capability_denied"
	ErrUIResourceBlocked  = "ui_resource_blocked"

	// MCP Transport (proxy handler) -- 502/503
	ErrMCPTransportFailed = "mcp_transport_failed" // transport-level failure (connection, timeout)
	ErrMCPRequestFailed   = "mcp_request_failed"   // MCP server returned JSON-RPC error
	ErrMCPInvalidResponse = "mcp_invalid_response" // malformed response from MCP server

	// MCP Request Validation -- 400 Bad Request
	ErrMCPInvalidRequest = "mcp_invalid_request"

	// Extension Slots -- 403 / 503
	ErrExtensionBlocked               = "extension_blocked"
	ErrExtensionUnavailableFailClosed = "extension_unavailable_fail_closed"

	// Phase 3 contract validation (plane entry points) -- 400 Bad Request
	ErrContractValidationFailed = "contract_validation_failed"
)
