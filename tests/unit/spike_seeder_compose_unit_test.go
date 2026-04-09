// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package unit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// composeFile is a minimal struct to parse the spike-secret-seeder service
// from docker-compose.yml without importing the full Docker Compose schema.
type composeFile struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	EnvFile     interface{}            `yaml:"env_file"`
	Environment []string               `yaml:"environment"`
	Command     interface{}            `yaml:"command"`
	Entrypoint  interface{}            `yaml:"entrypoint"`
	Volumes     []string               `yaml:"volumes"`
	Networks    []string               `yaml:"networks"`
	Labels      []string               `yaml:"labels"`
	Restart     string                 `yaml:"restart"`
	DependsOn   map[string]interface{} `yaml:"depends_on"`
}

func loadCompose(t *testing.T) composeFile {
	t.Helper()
	composePath := filepath.Join(pocRoot(t), "deploy", "compose", "docker-compose.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("failed to read docker-compose.yml: %v", err)
	}

	var cf composeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		t.Fatalf("failed to parse docker-compose.yml: %v", err)
	}
	return cf
}

func seederService(t *testing.T) composeService {
	t.Helper()
	cf := loadCompose(t)
	svc, ok := cf.Services["spike-secret-seeder"]
	if !ok {
		t.Fatal("spike-secret-seeder service not found in docker-compose.yml")
	}
	return svc
}

func seederCommand(t *testing.T) string {
	t.Helper()
	svc := seederService(t)
	// Command is a list with a single multiline string element
	switch cmd := svc.Command.(type) {
	case []interface{}:
		if len(cmd) == 0 {
			t.Fatal("spike-secret-seeder command is empty list")
		}
		return cmd[0].(string)
	case string:
		return cmd
	default:
		t.Fatalf("unexpected command type: %T", cmd)
		return ""
	}
}

// ---------------------------------------------------------------------------
// AC2: GROQ_API_KEY passed via secret mount (not bare env var or env_file)
// The .env file is mounted as /run/secrets/env and sourced at runtime inside
// the shell script. This prevents docker compose config from revealing key
// values (AC8), while still making the key available to the seeder command.
// ---------------------------------------------------------------------------

func TestSeeder_EnvSecretMount(t *testing.T) {
	svc := seederService(t)

	// Verify .env is mounted as a read-only secret file
	found := false
	for _, vol := range svc.Volumes {
		if strings.Contains(vol, ".env:/run/secrets/env:ro") {
			found = true
			break
		}
	}
	if !found {
		t.Error("spike-secret-seeder must mount .env as /run/secrets/env:ro volume")
	}
}

func TestSeeder_EnvSourcedInCommand(t *testing.T) {
	cmd := seederCommand(t)

	// The command must source /run/secrets/env at startup to load GROQ_API_KEY
	if !strings.Contains(cmd, ". /run/secrets/env") {
		t.Error("command does not source /run/secrets/env (required to load GROQ_API_KEY)")
	}
}

func TestSeeder_NoEnvFile_Directive(t *testing.T) {
	// env_file would leak key values in docker compose config output (AC8 violation).
	// The .env must be mounted as a volume instead.
	svc := seederService(t)
	if svc.EnvFile != nil {
		t.Error("spike-secret-seeder must NOT use env_file (leaks secrets via docker compose config); use volume mount instead")
	}
}

func TestSeeder_NoBareEnvVar(t *testing.T) {
	// AC2: GROQ_API_KEY must NOT appear in the environment list (bare env var substitution).
	svc := seederService(t)
	for _, env := range svc.Environment {
		if strings.HasPrefix(env, "GROQ_API_KEY") {
			t.Errorf("GROQ_API_KEY found in environment list (bare substitution); must use secret mount only: %s", env)
		}
	}
}

// ---------------------------------------------------------------------------
// AC1: spike-secret-seeder seeds 'groq-api-key' when GROQ_API_KEY is set
// ---------------------------------------------------------------------------

func TestSeeder_Command_ContainsGroqKeySeeding(t *testing.T) {
	cmd := seederCommand(t)
	if !strings.Contains(cmd, "spike secret put groq-api-key") {
		t.Error("command does not contain 'spike secret put groq-api-key'")
	}
}

func TestSeeder_Command_GroqSeedingUsesEnvVar(t *testing.T) {
	cmd := seederCommand(t)
	// The value= argument must reference the GROQ_API_KEY variable, not a literal
	if !strings.Contains(cmd, "value=$$GROQ_API_KEY") {
		t.Error("groq-api-key seeding does not reference $$GROQ_API_KEY env var")
	}
}

// ---------------------------------------------------------------------------
// AC3: When GROQ_API_KEY empty/unset, seeder logs warning and exits 0
// ---------------------------------------------------------------------------

func TestSeeder_Command_EmptyKeyWarning(t *testing.T) {
	cmd := seederCommand(t)
	expected := "spike-seeder: GROQ_API_KEY not set, skipping guard model key seeding (step-up guard will degrade to fail-open)"
	if !strings.Contains(cmd, expected) {
		t.Errorf("command missing empty-key warning message.\nwant substring: %s", expected)
	}
}

func TestSeeder_Command_GroqSeedingGuardedByNonEmpty(t *testing.T) {
	cmd := seederCommand(t)
	// The seeding must be guarded by a non-empty check on GROQ_API_KEY
	if !strings.Contains(cmd, `GROQ_API_KEY:-}`) {
		t.Error("groq-api-key seeding is not guarded by non-empty check (missing ${GROQ_API_KEY:-} pattern)")
	}
}

// ---------------------------------------------------------------------------
// AC4: Existing 'deadbeef' seeding and 'gateway-read' policy unchanged
// ---------------------------------------------------------------------------

func TestSeeder_Command_DeadbeefSeedingIntact(t *testing.T) {
	cmd := seederCommand(t)

	checks := []string{
		"spike secret put deadbeef value=test-secret-value-12345",
		"spike-seeder: seeding ref=deadbeef",
		"spike secret list",
	}

	for _, check := range checks {
		if !strings.Contains(cmd, check) {
			t.Errorf("deadbeef seeding missing expected substring: %s", check)
		}
	}
}

func TestSeeder_Command_GatewayReadPolicyIntact(t *testing.T) {
	cmd := seederCommand(t)

	checks := []string{
		"spike policy create --name=gateway-read",
		"--path-pattern='.*'",
		"--spiffeid-pattern='^spiffe://poc.local/gateways/.*'",
		"--permissions=read",
		"spike-seeder: creating gateway-read ACL policy",
	}

	for _, check := range checks {
		if !strings.Contains(cmd, check) {
			t.Errorf("gateway-read policy creation missing expected substring: %s", check)
		}
	}
}

func TestSeeder_Command_OrderingCorrect(t *testing.T) {
	cmd := seederCommand(t)

	// Verify ordering: deadbeef seeding -> groq seeding -> policy creation
	deadbeefIdx := strings.Index(cmd, "spike secret put deadbeef")
	groqIdx := strings.Index(cmd, "spike secret put groq-api-key")
	policyIdx := strings.Index(cmd, "spike policy create --name=gateway-read")

	if deadbeefIdx < 0 || groqIdx < 0 || policyIdx < 0 {
		t.Fatal("one or more required sections not found in command")
	}

	if deadbeefIdx >= groqIdx {
		t.Error("deadbeef seeding must come before groq-api-key seeding")
	}

	if groqIdx >= policyIdx {
		t.Error("groq-api-key seeding must come before gateway-read policy creation")
	}
}

// ---------------------------------------------------------------------------
// AC5: Retry pattern matches existing (max 15 attempts, 2s sleep)
// ---------------------------------------------------------------------------

func TestSeeder_Command_GroqRetryPattern(t *testing.T) {
	cmd := seederCommand(t)

	// The groq seeding must reuse the same max_attempts variable (15) and sleep 2
	// Verify the groq block uses the retry pattern.
	// Note: YAML parsing converts $$ to $ (Docker Compose escaping convention).
	groqSection := extractGroqSection(t, cmd)

	if !strings.Contains(groqSection, "$max_attempts") {
		t.Error("groq seeding does not use $max_attempts for retry limit")
	}

	if !strings.Contains(groqSection, "sleep 2") {
		t.Error("groq seeding does not sleep 2s between retries")
	}
}

func extractGroqSection(t *testing.T, cmd string) string {
	t.Helper()
	// Start from the RFA-cjc comment or the GROQ_API_KEY guard (whichever appears first)
	start := strings.Index(cmd, "seeding groq-api-key")
	if start < 0 {
		// Fall back to the spike secret put line itself
		start = strings.Index(cmd, "spike secret put groq-api-key")
	}
	if start < 0 {
		t.Fatal("groq-api-key seeding not found")
	}
	// Walk backward to the nearest if/while/echo line to capture the retry loop context
	lineStart := strings.LastIndex(cmd[:start], "\n")
	if lineStart < 0 {
		lineStart = 0
	}

	// Find the end of the groq section (the start of policy creation)
	end := strings.Index(cmd[lineStart:], "spike-seeder: creating gateway-read ACL policy")
	if end < 0 {
		t.Fatal("policy creation marker not found after groq seeding")
	}
	return cmd[lineStart : lineStart+end]
}

// ---------------------------------------------------------------------------
// AC6: Seeder does NOT log the key value
// ---------------------------------------------------------------------------

func TestSeeder_Command_NoKeyValueLogging(t *testing.T) {
	cmd := seederCommand(t)

	// The groq seeding section must not echo the output of spike secret put
	// as a standalone statement (unlike deadbeef which echoes PUT_OUT for debugging).
	// The `echo "$GROQ_OUT" | grep` pattern is acceptable because it pipes to
	// grep (not stdout). After YAML parsing, $$ becomes $ (Docker Compose escaping).
	groqSection := extractGroqSection(t, cmd)

	// Split into lines and check for standalone echo of GROQ_OUT (not piped to grep)
	for _, line := range strings.Split(groqSection, "\n") {
		trimmed := strings.TrimSpace(line)
		// Standalone echo of GROQ_OUT (no pipe) would leak the key
		if (strings.Contains(trimmed, `echo "$GROQ_OUT"`) || strings.Contains(trimmed, `echo $GROQ_OUT`)) &&
			!strings.Contains(trimmed, "|") {
			t.Errorf("groq seeding logs GROQ_OUT to stdout (no pipe): %s", trimmed)
		}
	}

	// Verify no standalone echo of the raw key variable value (shell expansion).
	// Echoing the literal string "GROQ_API_KEY" in a warning message is safe
	// (it's the variable name, not the value). We check for $GROQ_API_KEY or
	// ${GROQ_API_KEY} in echo statements (which would expand to the actual key).
	for _, line := range strings.Split(groqSection, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "echo") &&
			(strings.Contains(trimmed, "$GROQ_API_KEY") || strings.Contains(trimmed, "${GROQ_API_KEY}")) &&
			!strings.Contains(trimmed, "|") {
			t.Errorf("groq seeding echoes the GROQ_API_KEY value via shell expansion: %s", trimmed)
		}
	}
}

func TestSeeder_Command_GroqSuccessLogSafe(t *testing.T) {
	cmd := seederCommand(t)

	// Success message should only log the path name, not the value
	if !strings.Contains(cmd, "spike-seeder: groq-api-key seeded successfully") {
		t.Error("missing safe success log message for groq-api-key")
	}
}

// ---------------------------------------------------------------------------
// AC8: docker compose config must not contain raw key value
// The .env is mounted as a volume (not env_file), so docker compose config
// never interpolates or displays the key. We verify structurally that no
// hardcoded keys or env_file directives are present.
// ---------------------------------------------------------------------------

func TestSeeder_Command_NoHardcodedAPIKey(t *testing.T) {
	cmd := seederCommand(t)

	// The command must not contain any hardcoded API key patterns
	if strings.Contains(cmd, "gsk_") {
		t.Error("command contains a hardcoded Groq API key (gsk_ prefix)")
	}
}

func TestSeeder_ComposeConfig_NoKeyLeakage(t *testing.T) {
	// Structural verification: the compose file must not contain GROQ_API_KEY
	// in any environment section of the seeder (which would be visible in
	// docker compose config output).
	composePath := filepath.Join(pocRoot(t), "deploy", "compose", "docker-compose.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("failed to read docker-compose.yml: %v", err)
	}

	raw := string(data)
	// Find the spike-secret-seeder section
	seederStart := strings.Index(raw, "spike-secret-seeder:")
	if seederStart < 0 {
		t.Fatal("spike-secret-seeder service not found in raw YAML")
	}

	// Find the next service (look for a line starting with two spaces followed by a service name)
	seederSection := raw[seederStart:]
	// Find the next service definition at same indent level
	lines := strings.Split(seederSection, "\n")
	var seederBlock strings.Builder
	seederBlock.WriteString(lines[0])
	seederBlock.WriteString("\n")
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		// Next top-level service starts with exactly 2 spaces + non-space (not more indentation)
		if len(line) > 2 && line[0] == ' ' && line[1] == ' ' && line[2] != ' ' && line[2] != '#' {
			break
		}
		seederBlock.WriteString(line)
		seederBlock.WriteString("\n")
	}

	block := seederBlock.String()

	// env_file must not appear (it leaks values in docker compose config)
	if strings.Contains(block, "env_file:") {
		t.Error("spike-secret-seeder uses env_file which leaks secrets via docker compose config")
	}

	// No bare GROQ_API_KEY= in environment section
	if strings.Contains(block, "GROQ_API_KEY=") {
		// Check it's not just a variable reference in the command script
		envIdx := strings.Index(block, "environment:")
		cmdIdx := strings.Index(block, "command:")
		groqIdx := strings.Index(block, "GROQ_API_KEY=")
		if envIdx >= 0 && groqIdx > envIdx && (cmdIdx < 0 || groqIdx < cmdIdx) {
			t.Error("GROQ_API_KEY appears in the environment section (would be visible in docker compose config)")
		}
	}
}

// ---------------------------------------------------------------------------
// Structural: container exits 0 regardless of seeding outcome
// ---------------------------------------------------------------------------

func TestSeeder_Command_SetEU(t *testing.T) {
	cmd := seederCommand(t)
	if !strings.HasPrefix(strings.TrimSpace(cmd), "set -eu") {
		t.Error("command must start with 'set -eu'")
	}
}

func TestSeeder_Command_GroqFailureDoesNotAbort(t *testing.T) {
	cmd := seederCommand(t)

	// The groq spike secret put must use || true to prevent set -e from aborting
	groqSection := extractGroqSection(t, cmd)
	if !strings.Contains(groqSection, "|| true)") {
		t.Error("groq seeding spike command does not use '|| true' -- will abort on failure under set -e")
	}
}

func TestSeeder_Command_EndsDone(t *testing.T) {
	cmd := seederCommand(t)
	trimmed := strings.TrimSpace(cmd)
	if !strings.HasSuffix(trimmed, "echo 'spike-seeder: done'") {
		t.Error("command must end with 'spike-seeder: done' echo")
	}
}

// ---------------------------------------------------------------------------
// Structural integrity: service config
// ---------------------------------------------------------------------------

func TestSeeder_Networks(t *testing.T) {
	svc := seederService(t)
	found := false
	for _, n := range svc.Networks {
		if n == "secrets-plane" {
			found = true
			break
		}
	}
	if !found {
		t.Error("spike-secret-seeder must be on secrets-plane network")
	}
}

func TestSeeder_DependsOn(t *testing.T) {
	svc := seederService(t)
	for _, dep := range []string{"spike-nexus", "spike-bootstrap"} {
		if _, ok := svc.DependsOn[dep]; !ok {
			t.Errorf("spike-secret-seeder missing depends_on: %s", dep)
		}
	}
}
