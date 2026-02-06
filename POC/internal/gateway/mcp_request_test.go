package gateway

import (
	"testing"
)

// =============================================================================
// MCPRequestInfo Unit Tests - RFA-j2d.6
// =============================================================================

func TestMCPRequestInfo_IsToolsList(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		expected bool
	}{
		{"tools/list method", "tools/list", true},
		{"tools/call method", "tools/call", false},
		{"resources/read method", "resources/read", false},
		{"empty method", "", false},
		{"similar method", "tools/list/extra", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := NewMCPRequestInfo(tt.method, nil)
			if got := req.IsToolsList(); got != tt.expected {
				t.Errorf("IsToolsList() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMCPRequestInfo_IsResourceRead(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		expected bool
	}{
		{"resources/read method", "resources/read", true},
		{"tools/list method", "tools/list", false},
		{"tools/call method", "tools/call", false},
		{"empty method", "", false},
		{"resources/list method", "resources/list", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := NewMCPRequestInfo(tt.method, nil)
			if got := req.IsResourceRead(); got != tt.expected {
				t.Errorf("IsResourceRead() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMCPRequestInfo_IsUIResource(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]interface{}
		expected bool
	}{
		{
			"ui:// URI",
			map[string]interface{}{"uri": "ui://server/page.html"},
			true,
		},
		{
			"http:// URI",
			map[string]interface{}{"uri": "http://server/page.html"},
			false,
		},
		{
			"file:// URI",
			map[string]interface{}{"uri": "file:///path/to/resource"},
			false,
		},
		{
			"no URI in params",
			map[string]interface{}{"name": "test"},
			false,
		},
		{
			"nil params",
			nil,
			false,
		},
		{
			"empty params",
			map[string]interface{}{},
			false,
		},
		{
			"non-string URI",
			map[string]interface{}{"uri": 123},
			false,
		},
		{
			"ui:// with nested path",
			map[string]interface{}{"uri": "ui://dashboard-server/analytics/v2.html"},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := NewMCPRequestInfo("resources/read", tt.params)
			if got := req.IsUIResource(); got != tt.expected {
				t.Errorf("IsUIResource() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMCPRequestInfo_ResourceURI(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]interface{}
		expected string
	}{
		{
			"present URI",
			map[string]interface{}{"uri": "ui://server/page.html"},
			"ui://server/page.html",
		},
		{
			"no URI key",
			map[string]interface{}{"name": "test"},
			"",
		},
		{
			"nil params",
			nil,
			"",
		},
		{
			"non-string URI",
			map[string]interface{}{"uri": 42},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := NewMCPRequestInfo("resources/read", tt.params)
			if got := req.ResourceURI(); got != tt.expected {
				t.Errorf("ResourceURI() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestMCPRequestInfo_CombinedRouting verifies the routing logic that
// processUpstreamResponse uses to dispatch requests.
func TestMCPRequestInfo_CombinedRouting(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		params       map[string]interface{}
		expectRoute  string // "tools_list", "ui_resource_read", "standard"
	}{
		{
			"tools/list routes to tools_list",
			"tools/list",
			map[string]interface{}{},
			"tools_list",
		},
		{
			"resources/read with ui:// routes to ui_resource_read",
			"resources/read",
			map[string]interface{}{"uri": "ui://server/page.html"},
			"ui_resource_read",
		},
		{
			"resources/read with http:// routes to standard",
			"resources/read",
			map[string]interface{}{"uri": "http://server/data"},
			"standard",
		},
		{
			"tools/call routes to standard",
			"tools/call",
			map[string]interface{}{"name": "file_read"},
			"standard",
		},
		{
			"empty method routes to standard",
			"",
			nil,
			"standard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := NewMCPRequestInfo(tt.method, tt.params)

			var route string
			switch {
			case req.IsResourceRead() && req.IsUIResource():
				route = "ui_resource_read"
			case req.IsToolsList():
				route = "tools_list"
			default:
				route = "standard"
			}

			if route != tt.expectRoute {
				t.Errorf("Route = %q, want %q", route, tt.expectRoute)
			}
		})
	}
}
