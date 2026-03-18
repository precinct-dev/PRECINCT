package gateway

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// OAuthProtectedResourceMetadata represents the RFC 9470 Protected Resource Metadata
// document. External MCP clients fetch this to discover which Authorization Server(s)
// to contact, what audience/resource indicator to request, and which scopes are
// relevant.
type OAuthProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
	MCPEndpoint          string   `json:"mcp_endpoint"`
}

// oauthProtectedResourceHandler returns an http.Handler that serves
// GET /.well-known/oauth-protected-resource.
//
// The response is derived entirely from the loaded OAuthJWTConfig -- no values are
// hardcoded. When the gateway was started without OAuth configuration the handler
// returns 404, which is a truthful signal: the resource does not require OAuth.
func oauthProtectedResourceHandler(oauthCfg *middleware.OAuthJWTConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if oauthCfg == nil {
			http.NotFound(w, r)
			return
		}

		meta := OAuthProtectedResourceMetadata{
			Resource:             strings.TrimSpace(oauthCfg.Audience),
			AuthorizationServers: []string{strings.TrimSpace(oauthCfg.Issuer)},
			MCPEndpoint:          "/",
		}
		if len(oauthCfg.RequiredScopes) > 0 {
			meta.ScopesSupported = oauthCfg.RequiredScopes
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if err := json.NewEncoder(w).Encode(meta); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	})
}
