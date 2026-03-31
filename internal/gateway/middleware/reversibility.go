// Reversibility Classifier - OC-ytph
// Analyzes tool actions and parameters to produce a scored reversibility assessment.
// Used by step-up gating to make informed decisions about irreversible actions.
//
// Four-tier taxonomy:
//
//	Score 0: fully reversible (read-only, no side effects)
//	Score 1: mostly reversible (can be undone with effort)
//	Score 2: partially reversible (requires backup to undo)
//	Score 3: irreversible (permanent data/state loss)
package middleware

import "strings"

// ActionReversibility represents the reversibility assessment of a tool action.
type ActionReversibility struct {
	Score          int    `json:"score"`           // 0=fully reversible, 1=mostly, 2=partially, 3=irreversible
	Category       string `json:"category"`        // "reversible", "costly_reversible", "partially_reversible", "irreversible"
	Explanation    string `json:"explanation"`     // human-readable explanation
	RequiresBackup bool   `json:"requires_backup"` // should pre-action snapshot be taken?
}

// reversibilityTier groups the classification metadata for a single tier.
type reversibilityTier struct {
	score       int
	category    string
	explanation string
	keywords    []string
}

// tiers is ordered from most severe to least severe so that the first match
// in a linear scan yields the correct classification when multiple keywords
// could theoretically overlap across tiers.
var tiers = []reversibilityTier{
	{
		score:       3,
		category:    "irreversible",
		explanation: "Action cannot be undone. Data/state will be permanently lost.",
		keywords: []string{
			"delete", "rm", "remove", "drop", "reset", "wipe",
			"shutdown", "terminate", "revoke", "purge", "destroy", "truncate",
		},
	},
	{
		score:       2,
		category:    "partially_reversible",
		explanation: "Action can be reversed if a backup was taken before execution.",
		keywords: []string{
			"modify", "update", "overwrite", "chmod", "chown",
			"rename", "replace", "patch",
		},
	},
	{
		score:       1,
		category:    "costly_reversible",
		explanation: "Action can be reversed with effort. Some side effects may persist.",
		keywords: []string{
			"create", "send", "post", "publish", "write", "insert", "upload",
		},
	},
	{
		score:       0,
		category:    "reversible",
		explanation: "Action is read-only and has no side effects.",
		keywords: []string{
			"read", "list", "search", "get", "health", "status",
			"ping", "head", "describe", "show", "count", "exists",
		},
	},
}

// defaultResult is returned when no keyword matches and no ToolDefinition
// override applies.
var defaultResult = ActionReversibility{
	Score:          1,
	Category:       "costly_reversible",
	Explanation:    "Action can be reversed with effort. Some side effects may persist.",
	RequiresBackup: false,
}

// matchTier checks whether text (already lowercased) contains any keyword from
// any tier. Returns the tier index and true on match, or -1 and false.
func matchTier(text string) (int, bool) {
	for i, tier := range tiers {
		for _, kw := range tier.keywords {
			if strings.Contains(text, kw) {
				return i, true
			}
		}
	}
	return -1, false
}

// ClassifyReversibility analyzes a tool action and its parameters to produce a
// scored reversibility assessment.
//
// Matching logic:
//  1. Check action string (case-insensitive contains-match) against tier keywords.
//  2. Check params for "command" or "action" keys; if they contain tier keywords,
//     take the more severe (higher score) of the two matches.
//  3. If ToolDefinition is non-nil and RiskLevel == "critical", enforce minimum Score=2.
//  4. Default to Score=1 (costly_reversible) when no pattern matches.
//
// RequiresBackup is true when Score >= 2.
func ClassifyReversibility(tool string, action string, params map[string]interface{}, toolDef *ToolDefinition) ActionReversibility {
	actionLower := strings.ToLower(action)

	// Step 1: classify from action string
	bestTierIdx := -1
	if idx, ok := matchTier(actionLower); ok {
		bestTierIdx = idx
	}

	// Step 2: classify from params "command" or "action" keys
	for _, key := range []string{"command", "action"} {
		if val, ok := params[key]; ok {
			if s, ok := val.(string); ok {
				paramLower := strings.ToLower(s)
				if idx, ok := matchTier(paramLower); ok {
					// Take the more severe (lower tier index = higher score)
					if bestTierIdx == -1 || idx < bestTierIdx {
						bestTierIdx = idx
					}
				}
			}
		}
	}

	// Build result from best match or default
	var result ActionReversibility
	if bestTierIdx >= 0 {
		t := tiers[bestTierIdx]
		result = ActionReversibility{
			Score:       t.score,
			Category:    t.category,
			Explanation: t.explanation,
		}
	} else {
		result = defaultResult
	}

	// Step 3: ToolDefinition RiskLevel="critical" enforces minimum Score=2
	if toolDef != nil && strings.EqualFold(toolDef.RiskLevel, "critical") {
		if result.Score < 2 {
			result.Score = 2
			result.Category = "partially_reversible"
			result.Explanation = "Action can be reversed if a backup was taken before execution."
		}
	}

	// RequiresBackup = Score >= 2
	result.RequiresBackup = result.Score >= 2

	return result
}
