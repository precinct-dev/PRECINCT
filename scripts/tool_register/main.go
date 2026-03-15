// Story RFA-fu1 - Tool onboarding CLI
// Registers new tools into the security gateway by:
// 1. Computing SHA-256 hash of canonical(description + schema)
// 2. Generating tool-registry.yaml entry
// 3. Generating tool_grants.yaml entry with placeholder SPIFFE pattern
// 4. Running poisoning detection on description
// 5. Printing formatted YAML output for copy-paste
//
// Usage:
//
//	go run scripts/tool_register.go \
//	  --name my_tool \
//	  --description "Tool description" \
//	  --schema '{"type":"object","properties":{"query":{"type":"string"}}}' \
//	  --risk-level medium \
//	  --allowed-destinations "api.example.com,*.example.com" \
//	  --requires-step-up=false
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// poisoningPatterns mirrors the patterns from internal/gateway/middleware/tool_registry.go (RFA-qq0.19)
// and config/opa/mcp_policy.rego. Both the Go middleware and OPA policy use these same patterns.
var poisoningPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"<IMPORTANT> tag", regexp.MustCompile(`(?i)<IMPORTANT>.*?</IMPORTANT>`)},
	{"<SYSTEM> tag", regexp.MustCompile(`(?i)<SYSTEM>.*?</SYSTEM>`)},
	{"HTML comment", regexp.MustCompile(`(?i)<!--.*?-->`)},
	{"before using...first instruction", regexp.MustCompile(`(?i)before\s+using\s+this\s+tool.*?first`)},
	{"ignore instructions command", regexp.MustCompile(`(?i)ignore\s+(previous|all|prior)\s+instructions`)},
	{"you must command", regexp.MustCompile(`(?i)you\s+must\s+(always|first|never)`)},
	{"send to external destination", regexp.MustCompile(`(?i)send.*?(email|http|webhook|upload).*?to`)},
}

// validRiskLevels defines the allowed risk classifications.
var validRiskLevels = map[string]bool{
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

// ComputeHash computes SHA-256 hash of tool description + input schema.
// This MUST match the algorithm in internal/gateway/middleware/tool_registry.go:ComputeHash
// and scripts/compute_tool_hashes.go:ComputeHash exactly.
//
// Algorithm: SHA256(description + json.Marshal(inputSchema))
// json.Marshal sorts map keys alphabetically, producing canonical JSON.
func ComputeHash(description string, inputSchema map[string]interface{}) string {
	schemaJSON, err := json.Marshal(inputSchema)
	if err != nil {
		schemaJSON = []byte("{}")
	}

	content := description + string(schemaJSON)
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// CheckPoisoning checks the description for known poisoning patterns.
// Returns a list of matched pattern names. Empty list means clean.
func CheckPoisoning(description string) []string {
	var matches []string
	for _, p := range poisoningPatterns {
		if p.Pattern.MatchString(description) {
			matches = append(matches, p.Name)
		}
	}
	return matches
}

// GenerateRegistryEntry produces a tool-registry.yaml entry as formatted text.
func GenerateRegistryEntry(name, description, hash, riskLevel string, requiresStepUp bool, schema map[string]interface{}, allowedDestinations []string) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "  # %s - registered %s\n", name, time.Now().Format("2006-01-02"))
	fmt.Fprintf(&sb, "  - name: %q\n", name)
	fmt.Fprintf(&sb, "    description: %q\n", description)
	fmt.Fprintf(&sb, "    hash: %q  # SHA-256 (RFA-fu1)\n", hash)

	// Write input_schema as nested YAML
	sb.WriteString("    input_schema:\n")
	writeSchemaYAML(&sb, schema, 6)

	// Allowed destinations
	if len(allowedDestinations) > 0 {
		sb.WriteString("    allowed_destinations:\n")
		for _, dest := range allowedDestinations {
			fmt.Fprintf(&sb, "      - %q\n", dest)
		}
	}

	fmt.Fprintf(&sb, "    risk_level: %q\n", riskLevel)
	fmt.Fprintf(&sb, "    requires_step_up: %t\n", requiresStepUp)

	return sb.String()
}

// writeSchemaYAML writes a map as YAML with indentation. This handles the nested
// structure of JSON Schema objects (type, required, properties, etc.).
func writeSchemaYAML(sb *strings.Builder, m map[string]interface{}, indent int) {
	prefix := strings.Repeat(" ", indent)
	for _, entry := range sortedMapEntries(m) {
		switch v := entry.Value.(type) {
		case map[string]interface{}:
			_, _ = fmt.Fprintf(sb, "%s%s:\n", prefix, entry.Key)
			writeSchemaYAML(sb, v, indent+2)
		case []interface{}:
			_, _ = fmt.Fprintf(sb, "%s%s:\n", prefix, entry.Key)
			for _, item := range v {
				_, _ = fmt.Fprintf(sb, "%s  - %v\n", prefix, formatYAMLValue(item))
			}
		default:
			_, _ = fmt.Fprintf(sb, "%s%s: %v\n", prefix, entry.Key, formatYAMLValue(v))
		}
	}
}

// sortedMapEntries returns map entries in a stable, sorted order.
// This produces deterministic YAML output.
func sortedMapEntries(m map[string]interface{}) []mapEntry {
	// Define a preferred key order for JSON Schema fields
	order := []string{"type", "required", "description", "properties", "default", "enum", "minimum", "maximum"}
	seen := make(map[string]bool)
	var result []mapEntry

	// Add keys in preferred order first
	for _, key := range order {
		if val, ok := m[key]; ok {
			result = append(result, mapEntry{key, val})
			seen[key] = true
		}
	}

	// Add remaining keys alphabetically
	var remaining []string
	for key := range m {
		if !seen[key] {
			remaining = append(remaining, key)
		}
	}
	// Simple sort for remaining keys
	for i := 0; i < len(remaining); i++ {
		for j := i + 1; j < len(remaining); j++ {
			if remaining[i] > remaining[j] {
				remaining[i], remaining[j] = remaining[j], remaining[i]
			}
		}
	}
	for _, key := range remaining {
		result = append(result, mapEntry{key, m[key]})
	}

	return result
}

type mapEntry struct {
	Key   string
	Value interface{}
}

// formatYAMLValue formats a value for YAML output.
func formatYAMLValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return fmt.Sprintf("%q", val)
	case float64:
		// JSON numbers are float64; render as int if no fractional part
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case bool:
		return fmt.Sprintf("%t", val)
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%v", val)
	}
}

// GenerateGrantsEntry produces a tool_grants.yaml entry template.
func GenerateGrantsEntry(name, description string) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "  # Grant template for %s - registered %s\n", name, time.Now().Format("2006-01-02"))
	sb.WriteString("  # ACTION REQUIRED: Replace placeholder SPIFFE pattern with actual agent identity\n")
	sb.WriteString("  - spiffe_pattern: \"spiffe://poc.local/agents/mcp-client/*/dev\"\n")
	fmt.Fprintf(&sb, "    description: \"Grant for %s - %s\"\n", name, description)
	sb.WriteString("    allowed_tools:\n")
	fmt.Fprintf(&sb, "      - %s\n", name)
	sb.WriteString("    max_data_classification: internal\n")
	sb.WriteString("    requires_approval_for: []\n")

	return sb.String()
}

func main() {
	// Parse flags
	name := flag.String("name", "", "Tool name (required)")
	description := flag.String("description", "", "Tool description (required, will be hashed)")
	schema := flag.String("schema", "", "Tool input schema as JSON (required, will be hashed)")
	riskLevel := flag.String("risk-level", "medium", "Risk classification: low, medium, high, critical")
	allowedDest := flag.String("allowed-destinations", "", "Comma-separated allowed destinations (default: none)")
	requiresStepUp := flag.Bool("requires-step-up", false, "Whether tool requires step-up authentication")

	flag.Parse()

	// Validate required parameters
	exitCode := 0
	if *name == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --name is required")
		exitCode = 1
	}
	if *description == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --description is required")
		exitCode = 1
	}
	if *schema == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --schema is required")
		exitCode = 1
	}
	if exitCode != 0 {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage: go run scripts/tool_register.go --name NAME --description DESC --schema JSON")
		os.Exit(exitCode)
	}

	// Validate risk level
	if !validRiskLevels[*riskLevel] {
		fmt.Fprintf(os.Stderr, "ERROR: invalid risk level %q (must be: low, medium, high, critical)\n", *riskLevel)
		os.Exit(1)
	}

	// Parse schema JSON into map for canonical hashing
	var inputSchema map[string]interface{}
	if err := json.Unmarshal([]byte(*schema), &inputSchema); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: invalid JSON schema: %v\n", err)
		os.Exit(1)
	}

	// Parse allowed destinations
	var destinations []string
	if *allowedDest != "" {
		for _, d := range strings.Split(*allowedDest, ",") {
			trimmed := strings.TrimSpace(d)
			if trimmed != "" {
				destinations = append(destinations, trimmed)
			}
		}
	}

	// === Step 1: Poisoning Detection ===
	fmt.Println("=== Tool Security Lint ===")
	poisonMatches := CheckPoisoning(*description)
	if len(poisonMatches) > 0 {
		fmt.Println("WARNING: Poisoning patterns detected in tool description!")
		for _, match := range poisonMatches {
			fmt.Printf("  [CRITICAL] Pattern: %s\n", match)
		}
		fmt.Println("")
		fmt.Println("This tool description contains patterns commonly used in tool poisoning attacks.")
		fmt.Println("The tool will be BLOCKED by the security gateway if registered with this description.")
		fmt.Println("Review the description carefully before proceeding.")
		fmt.Println("")
	} else {
		fmt.Println("OK: No poisoning patterns detected in tool description.")
		fmt.Println("")
	}

	// === Step 2: Compute Hash ===
	hash := ComputeHash(*description, inputSchema)
	fmt.Println("=== Hash Computation ===")
	fmt.Printf("Algorithm: SHA-256(description + canonical_json(input_schema))\n")
	fmt.Printf("Hash: %s\n", hash)
	fmt.Println("")

	// === Step 3: Generate tool-registry.yaml entry ===
	registryEntry := GenerateRegistryEntry(*name, *description, hash, *riskLevel, *requiresStepUp, inputSchema, destinations)
	fmt.Println("=== tool-registry.yaml entry ===")
	fmt.Println("# Add the following to config/tool-registry.yaml under 'tools:'")
	fmt.Println("")
	fmt.Print(registryEntry)
	fmt.Println("")

	// === Step 4: Generate tool_grants.yaml entry ===
	grantsEntry := GenerateGrantsEntry(*name, *description)
	fmt.Println("=== tool_grants.yaml entry ===")
	fmt.Println("# Add the following to config/opa/tool_grants.yaml under 'tool_grants:'")
	fmt.Println("")
	fmt.Print(grantsEntry)
	fmt.Println("")

	// === Summary ===
	fmt.Println("=== Registration Summary ===")
	fmt.Printf("Tool:           %s\n", *name)
	fmt.Printf("Risk Level:     %s\n", *riskLevel)
	fmt.Printf("Step-up Auth:   %t\n", *requiresStepUp)
	fmt.Printf("Hash:           %s\n", hash)
	if len(destinations) > 0 {
		fmt.Printf("Destinations:   %s\n", strings.Join(destinations, ", "))
	} else {
		fmt.Printf("Destinations:   none (internal only)\n")
	}
	if len(poisonMatches) > 0 {
		fmt.Printf("Security Lint:  FAILED (%d poisoning pattern(s) detected)\n", len(poisonMatches))
	} else {
		fmt.Printf("Security Lint:  PASSED\n")
	}

	// Exit with non-zero status if poisoning detected (so CI can catch it)
	if len(poisonMatches) > 0 {
		os.Exit(2)
	}
}
