// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import "sort"

var requiredFrameworkSignalKeys = []string{
	"availability.rate_limited",
	"content.blocked",
	"data.pii_detected",
	"policy.authorization_denied",
	"policy.step_up_blocked",
	"prompt.injection_blocked",
	"prompt.injection_detected",
	"prompt.jailbreak_detected",
	"tool.hash_unverified",
}

var mitreAtlasBySignalKey = map[string][]string{
	"availability.rate_limited":   {"AML.T0029"},
	"content.blocked":             {"AML.T0024", "AML.T0098"},
	"data.pii_detected":           {"AML.T0024"},
	"policy.authorization_denied": {"AML.T0102"},
	"policy.step_up_blocked":      {"AML.T0102"},
	"prompt.injection_blocked":    {"AML.T0051"},
	"prompt.injection_detected":   {"AML.T0051"},
	"prompt.jailbreak_detected":   {"AML.T0054"},
	"tool.hash_unverified":        {"AML.T0010"},
}

var owaspAgenticBySignalKey = map[string][]string{
	"availability.rate_limited":   {"ASI04"},
	"content.blocked":             {"ASI05"},
	"data.pii_detected":           {"ASI05"},
	"policy.authorization_denied": {"ASI03"},
	"policy.step_up_blocked":      {"ASI03"},
	"prompt.injection_blocked":    {"ASI01"},
	"prompt.injection_detected":   {"ASI01"},
	"prompt.jailbreak_detected":   {"ASI01"},
	"tool.hash_unverified":        {"ASI02"},
}

func mapTaxonomyIDs(signalKeys []string, catalog map[string][]string) []string {
	ids := make(map[string]struct{})
	for _, signalKey := range signalKeys {
		for _, id := range catalog[signalKey] {
			if id == "" {
				continue
			}
			ids[id] = struct{}{}
		}
	}

	if len(ids) == 0 {
		return nil
	}

	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	return sorted
}

func missingTaxonomyCoverage(catalog map[string][]string) []string {
	missing := make([]string, 0)
	for _, signalKey := range requiredFrameworkSignalKeys {
		if len(catalog[signalKey]) == 0 {
			missing = append(missing, signalKey)
		}
	}
	sort.Strings(missing)
	return missing
}
