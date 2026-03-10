package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

const (
	spiffePeerAuthorizationModeAny       = "trust_domain_any"
	spiffePeerAuthorizationModeAllowlist = "explicit_allowlist"
)

type spiffePeerAuthorizerResult struct {
	authorizer tlsconfig.Authorizer
	allowedIDs []string
	mode       string
}

func buildSPIFFEPeerAuthorizer(rawAllowedIDs []string, peerName string) (spiffePeerAuthorizerResult, error) {
	allowedIDs := normalizeSPIFFEIDAllowlist(rawAllowedIDs)
	if len(allowedIDs) == 0 {
		return spiffePeerAuthorizerResult{
			authorizer: tlsconfig.AuthorizeAny(),
			mode:       spiffePeerAuthorizationModeAny,
		}, nil
	}

	parsedIDs := make([]spiffeid.ID, 0, len(allowedIDs))
	for _, rawID := range allowedIDs {
		id, err := spiffeid.FromString(rawID)
		if err != nil {
			return spiffePeerAuthorizerResult{}, fmt.Errorf("%s expected SPIFFE ID %q is invalid: %w", peerName, rawID, err)
		}
		parsedIDs = append(parsedIDs, id)
	}

	return spiffePeerAuthorizerResult{
		authorizer: tlsconfig.AuthorizeOneOf(parsedIDs...),
		allowedIDs: allowedIDs,
		mode:       spiffePeerAuthorizationModeAllowlist,
	}, nil
}

func installPinnedPeerIdentityVerifier(cfg *tls.Config, allowedIDs []string, peerName string) {
	if cfg == nil {
		return
	}

	normalized := normalizeSPIFFEIDAllowlist(allowedIDs)
	if len(normalized) == 0 {
		return
	}

	allowedSet := make(map[string]struct{}, len(normalized))
	for _, id := range normalized {
		allowedSet[id] = struct{}{}
	}

	previousVerify := cfg.VerifyConnection
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if previousVerify != nil {
			if err := previousVerify(state); err != nil {
				return err
			}
		}
		return verifyPinnedPeerSPIFFEIdentity(state.PeerCertificates, allowedSet, peerName)
	}
}

func verifyPinnedPeerSPIFFEIdentity(peerCertificates []*x509.Certificate, allowedIDs map[string]struct{}, peerName string) error {
	if len(peerCertificates) == 0 {
		return fmt.Errorf("%s peer identity verification failed: no peer certificate presented", peerName)
	}

	observedIDs := extractSPIFFEIDs(peerCertificates[0])
	if len(observedIDs) == 0 {
		return fmt.Errorf("%s peer identity verification failed: peer certificate is missing a valid SPIFFE URI SAN", peerName)
	}

	for _, observed := range observedIDs {
		if _, ok := allowedIDs[observed]; ok {
			return nil
		}
	}

	allowed := mapKeys(allowedIDs)
	sort.Strings(allowed)
	sort.Strings(observedIDs)

	return fmt.Errorf(
		"%s peer identity verification failed: unexpected SPIFFE ID(s) %s (allowed: %s)",
		peerName,
		strings.Join(observedIDs, ", "),
		strings.Join(allowed, ", "),
	)
}

func extractSPIFFEIDs(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	ids := make([]string, 0, len(cert.URIs))
	seen := make(map[string]struct{}, len(cert.URIs))
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		id, err := spiffeid.FromURI(uri)
		if err != nil {
			continue
		}
		raw := id.String()
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		ids = append(ids, raw)
	}
	return ids
}

func normalizeSPIFFEIDAllowlist(values []string) []string {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		id := strings.TrimSpace(value)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
	}
	return normalized
}

func mapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func isStrictEnforcementProfileName(profile string) bool {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case enforcementProfileProdStandard, enforcementProfileProdRegulatedHIPAA:
		return true
	default:
		return false
	}
}

func shouldApplyDefaultSPIFFEPeerAllowlists(spiffeMode, enforcementProfile string) bool {
	if strings.EqualFold(strings.TrimSpace(spiffeMode), "prod") {
		return true
	}
	return isStrictEnforcementProfileName(enforcementProfile)
}

func defaultUpstreamAuthzAllowedSPIFFEIDs(trustDomain string) []string {
	td := strings.TrimSpace(trustDomain)
	if td == "" {
		td = "poc.local"
	}

	return []string{
		fmt.Sprintf("spiffe://%s/ns/tools/sa/mcp-tool", td),
		fmt.Sprintf("spiffe://%s/tools/docker-mcp-server/dev", td),
	}
}

func defaultKeyDBAuthzAllowedSPIFFEIDs(trustDomain string) []string {
	td := strings.TrimSpace(trustDomain)
	if td == "" {
		td = "poc.local"
	}

	return []string{
		fmt.Sprintf("spiffe://%s/keydb", td),
		fmt.Sprintf("spiffe://%s/ns/data/sa/keydb", td),
	}
}
