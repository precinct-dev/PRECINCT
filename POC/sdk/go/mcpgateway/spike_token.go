package mcpgateway

import (
	"fmt"
	"strings"
)

// DefaultSPIKEExpSeconds is the default token expiration when no positive
// value is provided (matches the Python SDK default of 3600).
const DefaultSPIKEExpSeconds = 3600

// BuildSPIKETokenRef constructs a Bearer SPIKE token reference string for
// gateway model and tool egress. The returned value is suitable for use as
// an Authorization header value.
//
// The format matches the Python SDK's build_spike_token_ref exactly:
//
//	Bearer $SPIKE{ref:<spikeRef>,exp:<expSeconds>}
//
// If spikeRef is empty (or whitespace-only), an empty string is returned.
// If expSeconds is <= 0, it defaults to 3600.
func BuildSPIKETokenRef(spikeRef string, expSeconds int) string {
	ref := strings.TrimSpace(spikeRef)
	if ref == "" {
		return ref // guard: empty/whitespace-only input produces no token
	}
	if expSeconds <= 0 {
		expSeconds = DefaultSPIKEExpSeconds
	}
	return fmt.Sprintf("Bearer $SPIKE{ref:%s,exp:%d}", ref, expSeconds)
}

// BuildSPIKETokenRefWithScope is like BuildSPIKETokenRef but appends an
// optional scope qualifier to the token reference:
//
//	Bearer $SPIKE{ref:<spikeRef>,exp:<expSeconds>,scope:<scope>}
//
// If scope is empty (or whitespace-only), the result is identical to
// BuildSPIKETokenRef (no scope segment is appended).
func BuildSPIKETokenRefWithScope(spikeRef string, expSeconds int, scope string) string {
	ref := strings.TrimSpace(spikeRef)
	if ref == "" {
		return ref // guard: empty/whitespace-only input produces no token
	}
	if expSeconds <= 0 {
		expSeconds = DefaultSPIKEExpSeconds
	}
	s := strings.TrimSpace(scope)
	if s == "" {
		return fmt.Sprintf("Bearer $SPIKE{ref:%s,exp:%d}", ref, expSeconds)
	}
	return fmt.Sprintf("Bearer $SPIKE{ref:%s,exp:%d,scope:%s}", ref, expSeconds, s)
}
