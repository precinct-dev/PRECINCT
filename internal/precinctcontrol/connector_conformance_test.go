package precinctcontrol

import "testing"

func TestIsConnectorMutationPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "register", path: "/v1/connectors/register", want: true},
		{name: "validate", path: "/v1/connectors/validate", want: true},
		{name: "approve", path: "/v1/connectors/approve", want: true},
		{name: "activate", path: "/v1/connectors/activate", want: true},
		{name: "revoke", path: "/v1/connectors/revoke", want: true},
		{name: "status", path: "/v1/connectors/status", want: false},
		{name: "report", path: "/v1/connectors/report", want: false},
		{name: "unknown", path: "/v1/connectors/unknown", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsConnectorMutationPath(tt.path); got != tt.want {
				t.Fatalf("IsConnectorMutationPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
