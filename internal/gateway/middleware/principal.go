// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/url"
	"strings"
)

// PrincipalRole represents the resolved authority level and capabilities for a
// SPIFFE identity. The 6-level hierarchy (0=system through 5=anonymous) maps
// SPIFFE ID path prefixes to authority tiers, addressing the owner vs non-owner
// instruction confusion documented in 'Agents of Chaos' (arXiv:2602.20021v1).
type PrincipalRole struct {
	Level        int      `json:"level"`        // 0=system, 1=owner, 2=delegated, 3=peer_agent, 4=external, 5=anonymous
	Role         string   `json:"role"`         // "system", "owner", "delegated_admin", "agent", "external_user", "anonymous"
	Capabilities []string `json:"capabilities"` // e.g. ["admin","read","write","execute","delegate"]
	TrustDomain  string   `json:"trust_domain"` // the SPIFFE trust domain extracted from the ID
	AuthMethod   string   `json:"auth_method"`  // "mtls_svid", "token", "header_declared"
}

// principalMapping defines the path prefix to role mapping for SPIFFE ID resolution.
type principalMapping struct {
	pathPrefix   string
	level        int
	role         string
	capabilities []string
}

// principalMappings is the ordered set of path prefix to role mappings.
// Order matters: first match wins (though prefixes are non-overlapping).
var principalMappings = []principalMapping{
	{"system/", 0, "system", []string{"admin", "read", "write", "execute", "delegate"}},
	{"gateways/", 0, "system", []string{"admin", "read", "write", "execute", "delegate"}}, // OC-3ch6: gateway identities are system-level
	{"owner/", 1, "owner", []string{"admin", "read", "write", "execute", "delegate"}},
	{"delegated/", 2, "delegated_admin", []string{"read", "write", "execute", "delegate"}},
	{"agents/", 3, "agent", []string{"read", "write", "execute"}},
	{"external/", 4, "external_user", []string{"read"}},
}

var kubernetesSystemServiceAccounts = map[string]map[string]struct{}{
	"gateway": {
		"precinct-gateway": {},
		"precinct-control": {},
	},
}

// ResolvePrincipalRole resolves a SPIFFE ID to a PrincipalRole based on the
// path prefix hierarchy. The trustDomain parameter is the expected trust domain;
// if the SPIFFE ID belongs to a different domain, anonymous is returned.
// The authMethod is passed through as-is from the caller.
func ResolvePrincipalRole(spiffeID string, trustDomain string, authMethod string) PrincipalRole {
	if spiffeID == "" {
		return PrincipalRole{
			Level:        5,
			Role:         "anonymous",
			Capabilities: []string{},
			TrustDomain:  "",
			AuthMethod:   authMethod,
		}
	}

	// Parse the SPIFFE ID to extract the trust domain and path.
	u, err := url.Parse(spiffeID)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" {
		return PrincipalRole{
			Level:        5,
			Role:         "anonymous",
			Capabilities: []string{},
			TrustDomain:  "",
			AuthMethod:   authMethod,
		}
	}

	extractedDomain := u.Host

	// Verify trust domain matches.
	if extractedDomain != trustDomain {
		return PrincipalRole{
			Level:        5,
			Role:         "anonymous",
			Capabilities: []string{},
			TrustDomain:  extractedDomain,
			AuthMethod:   authMethod,
		}
	}

	// Extract the path (strip leading slash).
	path := strings.TrimPrefix(u.Path, "/")

	// Match against known path prefixes.
	for _, m := range principalMappings {
		if strings.HasPrefix(path, m.pathPrefix) {
			// Copy capabilities to avoid sharing the backing array.
			caps := make([]string, len(m.capabilities))
			copy(caps, m.capabilities)
			return PrincipalRole{
				Level:        m.level,
				Role:         m.role,
				Capabilities: caps,
				TrustDomain:  extractedDomain,
				AuthMethod:   authMethod,
			}
		}
	}

	if role, ok := resolveKubernetesPrincipal(path, extractedDomain, authMethod); ok {
		return role
	}

	// No matching prefix: anonymous.
	return PrincipalRole{
		Level:        5,
		Role:         "anonymous",
		Capabilities: []string{},
		TrustDomain:  extractedDomain,
		AuthMethod:   authMethod,
	}
}

func resolveKubernetesPrincipal(path string, trustDomain string, authMethod string) (PrincipalRole, bool) {
	parts := strings.Split(path, "/")
	if len(parts) != 4 || parts[0] != "ns" || parts[2] != "sa" {
		return PrincipalRole{}, false
	}

	namespace := strings.TrimSpace(parts[1])
	serviceAccount := strings.TrimSpace(parts[3])
	if namespace == "" || serviceAccount == "" {
		return PrincipalRole{}, false
	}

	role := "agent"
	level := 3
	capabilities := []string{"read", "write", "execute"}
	if isKubernetesSystemServiceAccount(namespace, serviceAccount) {
		role = "system"
		level = 0
		capabilities = []string{"admin", "read", "write", "execute", "delegate"}
	}

	caps := make([]string, len(capabilities))
	copy(caps, capabilities)

	return PrincipalRole{
		Level:        level,
		Role:         role,
		Capabilities: caps,
		TrustDomain:  trustDomain,
		AuthMethod:   authMethod,
	}, true
}

func isKubernetesSystemServiceAccount(namespace string, serviceAccount string) bool {
	serviceAccounts, ok := kubernetesSystemServiceAccounts[namespace]
	if !ok {
		return false
	}

	_, ok = serviceAccounts[serviceAccount]
	return ok
}
