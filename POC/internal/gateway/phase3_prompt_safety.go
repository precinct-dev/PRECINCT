package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var (
	promptSafetyEmailPattern = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	promptSafetySSNPattern   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	promptSafetyPhonePattern = regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`)
)

func evaluatePromptSafety(attrs map[string]any) (Decision, ReasonCode, int, map[string]any, bool) {
	profile := strings.ToLower(getStringAttr(attrs, "compliance_profile", "standard"))
	modelScope := strings.ToLower(getStringAttr(attrs, "model_scope", "external"))
	if profile != "hipaa" && profile != "regulated" {
		return "", "", 0, nil, false
	}
	if modelScope != "external" {
		return "", "", 0, nil, false
	}

	classification := strings.ToLower(getStringAttr(attrs, "prompt_classification", ""))
	hasRegulatedPrompt := getBoolAttr(attrs, "prompt_has_phi", false) ||
		getBoolAttr(attrs, "prompt_has_pii", false) ||
		classification == "phi" ||
		classification == "pii" ||
		classification == "high_risk"
	if !hasRegulatedPrompt {
		return "", "", 0, nil, false
	}

	action := strings.ToLower(getStringAttr(attrs, "prompt_action", "deny"))
	prompt := getStringAttr(attrs, "prompt", "")
	baseMetadata := map[string]any{
		"compliance_profile":     profile,
		"model_scope":            modelScope,
		"prompt_classification":  classification,
		"prompt_original_digest": digestString(prompt),
	}

	switch action {
	case "redact":
		transformed := deterministicRedactPrompt(prompt)
		baseMetadata["prompt_transform"] = "redact"
		baseMetadata["prompt_transformed_digest"] = digestString(transformed)
		return DecisionAllow, ReasonPromptSafetyRedacted, 200, baseMetadata, true
	case "tokenize":
		transformed := deterministicTokenizePrompt(prompt)
		baseMetadata["prompt_transform"] = "tokenize"
		baseMetadata["prompt_transformed_digest"] = digestString(transformed)
		return DecisionAllow, ReasonPromptSafetyTokenized, 200, baseMetadata, true
	case "override":
		approvalMarker := strings.TrimSpace(getStringAttr(attrs, "approval_marker", ""))
		if approvalMarker == "" {
			baseMetadata["fail_closed"] = true
			return DecisionDeny, ReasonPromptSafetyOverrideReq, 403, baseMetadata, true
		}
		baseMetadata["prompt_transform"] = "override"
		baseMetadata["approval_marker"] = approvalMarker
		return DecisionAllow, ReasonPromptSafetyOverride, 200, baseMetadata, true
	default:
		baseMetadata["fail_closed"] = true
		return DecisionDeny, ReasonPromptSafetyRawDenied, 403, baseMetadata, true
	}
}

func deterministicRedactPrompt(in string) string {
	out := in
	out = promptSafetyEmailPattern.ReplaceAllString(out, "[REDACTED_EMAIL]")
	out = promptSafetySSNPattern.ReplaceAllString(out, "[REDACTED_SSN]")
	out = promptSafetyPhonePattern.ReplaceAllString(out, "[REDACTED_PHONE]")
	return out
}

func deterministicTokenizePrompt(in string) string {
	out := in
	out = replaceWithToken(out, promptSafetyEmailPattern, "EMAIL")
	out = replaceWithToken(out, promptSafetySSNPattern, "SSN")
	out = replaceWithToken(out, promptSafetyPhonePattern, "PHONE")
	return out
}

func replaceWithToken(in string, re *regexp.Regexp, label string) string {
	return re.ReplaceAllStringFunc(in, func(match string) string {
		return "[TOKEN_" + label + "_" + shortDigest(match) + "]"
	})
}

func shortDigest(in string) string {
	full := digestString(in)
	if len(full) <= 12 {
		return full
	}
	return full[:12]
}

func digestString(in string) string {
	sum := sha256.Sum256([]byte(in))
	return hex.EncodeToString(sum[:])
}
