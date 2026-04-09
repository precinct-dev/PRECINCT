// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// MatchesQuery evaluates the simplified jq-like evidence query used by
// tools/compliance/control_taxonomy.yaml.
//
// Supported patterns:
// - '.field != null'
// - '.field != ""'
// - '.field == "value"'
// - '.field == number'
// - '.field | startswith("prefix")'
// - '.field | contains("substring")'
// - compound 'and' expressions (split on ' and ')
func MatchesQuery(entry map[string]any, query string) bool {
	query = strings.TrimSpace(query)
	if query == "" {
		return false
	}

	parts := strings.Split(query, " and ")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !evalSingle(entry, part) {
			return false
		}
	}
	return true
}

func evalSingle(entry map[string]any, expr string) bool {
	expr = strings.TrimSpace(expr)

	if strings.Contains(expr, "| startswith(") {
		field, rest, ok := strings.Cut(expr, " | startswith(")
		if !ok {
			return false
		}
		field = strings.TrimSpace(strings.TrimPrefix(field, "."))
		value := strings.TrimSuffix(strings.TrimSpace(rest), ")")
		value = strings.Trim(value, `"'`)
		resolved, ok := resolvePath(entry, field)
		if !ok {
			return false
		}
		return strings.HasPrefix(anyToString(resolved), value)
	}

	if strings.Contains(expr, "| contains(") {
		field, rest, ok := strings.Cut(expr, " | contains(")
		if !ok {
			return false
		}
		field = strings.TrimSpace(strings.TrimPrefix(field, "."))
		value := strings.TrimSuffix(strings.TrimSpace(rest), ")")
		value = strings.Trim(value, `"'`)
		resolved, ok := resolvePath(entry, field)
		if !ok {
			return false
		}
		return strings.Contains(anyToString(resolved), value)
	}

	if strings.Contains(expr, "!= null") {
		field := strings.TrimSpace(strings.TrimPrefix(strings.ReplaceAll(expr, "!= null", ""), "."))
		resolved, ok := resolvePath(entry, field)
		return ok && resolved != nil
	}

	if strings.Contains(expr, `!= ""`) {
		field := strings.TrimSpace(strings.TrimPrefix(strings.ReplaceAll(expr, `!= ""`, ""), "."))
		resolved, ok := resolvePath(entry, field)
		if !ok {
			return false
		}
		// Treat nil as empty.
		return resolved != nil && anyToString(resolved) != ""
	}

	if strings.Contains(expr, `== "`) {
		field, rest, ok := strings.Cut(expr, ` == "`)
		if !ok {
			return false
		}
		field = strings.TrimSpace(strings.TrimPrefix(field, "."))
		value := strings.TrimSuffix(rest, `"`)
		resolved, ok := resolvePath(entry, field)
		if !ok {
			return false
		}
		return anyToString(resolved) == value
	}

	if strings.Contains(expr, " == ") {
		field, value, ok := strings.Cut(expr, " == ")
		if !ok {
			return false
		}
		field = strings.TrimSpace(strings.TrimPrefix(field, "."))
		value = strings.TrimSpace(value)
		resolved, ok := resolvePath(entry, field)
		if !ok {
			return false
		}
		// Numeric equality when value parses as int and resolved is numeric-like.
		if n, err := strconv.Atoi(value); err == nil {
			switch t := resolved.(type) {
			case int:
				return t == n
			case int64:
				return t == int64(n)
			case float64:
				return int(t) == n
			case json.Number:
				i, err := t.Int64()
				return err == nil && i == int64(n)
			default:
				// Fall back to string compare.
				return anyToString(resolved) == fmt.Sprintf("%d", n)
			}
		}
		return anyToString(resolved) == value
	}

	return false
}

func resolvePath(entry map[string]any, dotPath string) (any, bool) {
	parts := strings.Split(dotPath, ".")
	var cur any = entry
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, exists := m[p]
		if !exists {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

func anyToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		// Keep nested structures readable for contains().
		b, err := json.Marshal(t)
		if err == nil {
			return string(b)
		}
		return fmt.Sprintf("%v", t)
	}
}
