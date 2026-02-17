package middleware

import "sort"

// FrameworkRefs captures stable, app-agnostic framework enrichment fields.
// signal_keys is the shared resolver output consumed by taxonomy stories
// (e.g., MITRE ATLAS / OWASP Agentic Top 10 mappings).
type FrameworkRefs struct {
	SignalKeys        []string `json:"signal_keys,omitempty"`
	MITREAtlas        []string `json:"mitre_atlas,omitempty"`
	OWASPAgenticTop10 []string `json:"owasp_agentic_top10,omitempty"`
}

func resolveFrameworkRefs(flags []string, toolHashVerified bool, statusCode int) *FrameworkRefs {
	keys := make(map[string]struct{})
	add := func(k string) {
		if k == "" {
			return
		}
		keys[k] = struct{}{}
	}

	for _, flag := range flags {
		switch flag {
		case "blocked_content":
			add("content.blocked")
		case "potential_injection":
			add("prompt.injection_detected")
		case "deepscan_blocked", "deep_scan_blocked":
			add("prompt.injection_blocked")
		case "stepup_guard_blocked":
			add("policy.step_up_blocked")
		case "potential_jailbreak", "jailbreak_detected":
			add("prompt.jailbreak_detected")
		case "potential_pii":
			add("data.pii_detected")
		case "rate_limit_exceeded":
			add("availability.rate_limited")
		case "tool_hash_mismatch", "tool_hash_unverified":
			add("tool.hash_unverified")
		}
	}

	if !toolHashVerified {
		add("tool.hash_unverified")
	}
	if statusCode == 403 {
		add("policy.authorization_denied")
	}
	if statusCode == 429 {
		add("availability.rate_limited")
	}

	if len(keys) == 0 {
		return nil
	}

	sortedKeys := make([]string, 0, len(keys))
	for k := range keys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	return &FrameworkRefs{
		SignalKeys:        sortedKeys,
		MITREAtlas:        mapTaxonomyIDs(sortedKeys, mitreAtlasBySignalKey),
		OWASPAgenticTop10: mapTaxonomyIDs(sortedKeys, owaspAgenticBySignalKey),
	}
}
