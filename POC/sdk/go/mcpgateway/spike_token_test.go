package mcpgateway

import "testing"

func TestBuildSPIKETokenRef(t *testing.T) {
	tests := []struct {
		name       string
		spikeRef   string
		expSeconds int
		want       string
	}{
		{
			name:       "standard reference with default expiration",
			spikeRef:   "deadbeef",
			expSeconds: 3600,
			want:       "Bearer $SPIKE{ref:deadbeef,exp:3600}",
		},
		{
			name:       "custom reference with custom expiration",
			spikeRef:   "my-secret-ref",
			expSeconds: 7200,
			want:       "Bearer $SPIKE{ref:my-secret-ref,exp:7200}",
		},
		{
			name:       "empty spikeRef returns empty string",
			spikeRef:   "",
			expSeconds: 3600,
			want:       "",
		},
		{
			name:       "whitespace-only spikeRef returns empty string",
			spikeRef:   "   ",
			expSeconds: 3600,
			want:       "",
		},
		{
			name:       "zero expSeconds defaults to 3600",
			spikeRef:   "ref",
			expSeconds: 0,
			want:       "Bearer $SPIKE{ref:ref,exp:3600}",
		},
		{
			name:       "negative expSeconds defaults to 3600",
			spikeRef:   "ref",
			expSeconds: -1,
			want:       "Bearer $SPIKE{ref:ref,exp:3600}",
		},
		{
			name:       "leading and trailing whitespace is trimmed",
			spikeRef:   "  spaced  ",
			expSeconds: 3600,
			want:       "Bearer $SPIKE{ref:spaced,exp:3600}",
		},
		{
			name:       "large negative expSeconds defaults to 3600",
			spikeRef:   "abc",
			expSeconds: -999,
			want:       "Bearer $SPIKE{ref:abc,exp:3600}",
		},
		{
			name:       "expSeconds of 1 is valid",
			spikeRef:   "short-lived",
			expSeconds: 1,
			want:       "Bearer $SPIKE{ref:short-lived,exp:1}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildSPIKETokenRef(tt.spikeRef, tt.expSeconds)
			if got != tt.want {
				t.Errorf("BuildSPIKETokenRef(%q, %d) = %q, want %q",
					tt.spikeRef, tt.expSeconds, got, tt.want)
			}
		})
	}
}

func TestBuildSPIKETokenRefWithScope(t *testing.T) {
	tests := []struct {
		name       string
		spikeRef   string
		expSeconds int
		scope      string
		want       string
	}{
		{
			name:       "with model scope",
			spikeRef:   "deadbeef",
			expSeconds: 3600,
			scope:      "model",
			want:       "Bearer $SPIKE{ref:deadbeef,exp:3600,scope:model}",
		},
		{
			name:       "with tool scope",
			spikeRef:   "deadbeef",
			expSeconds: 7200,
			scope:      "tool",
			want:       "Bearer $SPIKE{ref:deadbeef,exp:7200,scope:tool}",
		},
		{
			name:       "empty scope falls back to no-scope format",
			spikeRef:   "deadbeef",
			expSeconds: 3600,
			scope:      "",
			want:       "Bearer $SPIKE{ref:deadbeef,exp:3600}",
		},
		{
			name:       "whitespace-only scope falls back to no-scope format",
			spikeRef:   "deadbeef",
			expSeconds: 3600,
			scope:      "   ",
			want:       "Bearer $SPIKE{ref:deadbeef,exp:3600}",
		},
		{
			name:       "empty spikeRef with scope returns empty string",
			spikeRef:   "",
			expSeconds: 3600,
			scope:      "model",
			want:       "",
		},
		{
			name:       "zero expSeconds with scope defaults to 3600",
			spikeRef:   "ref",
			expSeconds: 0,
			scope:      "model",
			want:       "Bearer $SPIKE{ref:ref,exp:3600,scope:model}",
		},
		{
			name:       "trimmed spikeRef with scope",
			spikeRef:   "  spaced  ",
			expSeconds: 3600,
			scope:      "model",
			want:       "Bearer $SPIKE{ref:spaced,exp:3600,scope:model}",
		},
		{
			name:       "scope with whitespace is trimmed",
			spikeRef:   "ref",
			expSeconds: 3600,
			scope:      "  model  ",
			want:       "Bearer $SPIKE{ref:ref,exp:3600,scope:model}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildSPIKETokenRefWithScope(tt.spikeRef, tt.expSeconds, tt.scope)
			if got != tt.want {
				t.Errorf("BuildSPIKETokenRefWithScope(%q, %d, %q) = %q, want %q",
					tt.spikeRef, tt.expSeconds, tt.scope, got, tt.want)
			}
		})
	}
}

// TestBuildSPIKETokenRef_MatchesPythonSDK verifies that the Go implementation
// produces output identical to the Python SDK's build_spike_token_ref function
// defined in POC/sdk/python/mcp_gateway_sdk/runtime.py.
func TestBuildSPIKETokenRef_MatchesPythonSDK(t *testing.T) {
	// Python: build_spike_token_ref("deadbeef", exp_seconds=3600)
	// -> "Bearer $SPIKE{ref:deadbeef,exp:3600}"
	got := BuildSPIKETokenRef("deadbeef", 3600)
	want := "Bearer $SPIKE{ref:deadbeef,exp:3600}"
	if got != want {
		t.Errorf("Python SDK parity failed:\n  got:  %q\n  want: %q", got, want)
	}

	// Python: build_spike_token_ref("", exp_seconds=3600) -> ""
	got = BuildSPIKETokenRef("", 3600)
	if got != "" {
		t.Errorf("empty ref should return empty string, got %q", got)
	}

	// Python: build_spike_token_ref("  spaced  ", exp_seconds=3600)
	// -> "Bearer $SPIKE{ref:spaced,exp:3600}"
	got = BuildSPIKETokenRef("  spaced  ", 3600)
	want = "Bearer $SPIKE{ref:spaced,exp:3600}"
	if got != want {
		t.Errorf("trimmed ref parity failed:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestDefaultSPIKEExpSeconds verifies the exported constant value.
func TestDefaultSPIKEExpSeconds(t *testing.T) {
	if DefaultSPIKEExpSeconds != 3600 {
		t.Errorf("DefaultSPIKEExpSeconds = %d, want 3600", DefaultSPIKEExpSeconds)
	}
}
