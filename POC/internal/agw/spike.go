package agw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
)

var spikeSecretRefPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

type SPIKESecretRef struct {
	Ref     string `json:"ref"`
	Created string `json:"created"`
	Type    string `json:"type"`
}

type SPIKESecretListOutput struct {
	Secrets []SPIKESecretRef `json:"secrets"`
}

type SPIKESecretPutResult struct {
	Status string `json:"status"`
	Ref    string `json:"ref"`
}

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout string, stderr string, err error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

type SPIKECLI struct {
	runner CommandRunner
}

func NewSPIKECLI() *SPIKECLI {
	return &SPIKECLI{runner: execCommandRunner{}}
}

func NewSPIKECLIWithRunner(runner CommandRunner) *SPIKECLI {
	if runner == nil {
		runner = execCommandRunner{}
	}
	return &SPIKECLI{runner: runner}
}

func (s *SPIKECLI) ListSecretRefs(ctx context.Context) ([]SPIKESecretRef, error) {
	stdout, stderr, err := s.run(ctx, spikeListPrimaryArgs())
	if err != nil && shouldFallbackToModernSPIKECLI(err, stderr) {
		stdout, stderr, err = s.run(ctx, spikeListFallbackArgs())
	}
	if err != nil {
		return nil, fmt.Errorf("list SPIKE secret refs: %w", redactSecretValueInError(stderr, err))
	}
	refs, parseErr := ParseSPIKESecretList(strings.TrimSpace(stdout + "\n" + stderr))
	if parseErr != nil {
		return nil, parseErr
	}
	return refs, nil
}

func (s *SPIKECLI) PutSecret(ctx context.Context, ref, value string) (SPIKESecretPutResult, error) {
	ref = strings.TrimSpace(ref)
	value = strings.TrimSpace(value)
	if ref == "" {
		return SPIKESecretPutResult{}, errors.New("ref is required")
	}
	if value == "" {
		return SPIKESecretPutResult{}, errors.New("value is required")
	}

	_, stderr, err := s.run(ctx, spikePutPrimaryArgs(ref, value))
	if err != nil && shouldFallbackToModernSPIKECLI(err, stderr) {
		_, stderr, err = s.run(ctx, spikePutFallbackArgs(ref, value))
	}
	if err != nil {
		return SPIKESecretPutResult{}, fmt.Errorf("put SPIKE secret ref %q: %w", ref, redactSecretValueInError(stderr, err))
	}

	return SPIKESecretPutResult{
		Status: "stored",
		Ref:    ref,
	}, nil
}

func ParseSPIKESecretList(raw string) ([]SPIKESecretRef, error) {
	lines := strings.Split(raw, "\n")
	seen := make(map[string]struct{})
	refs := make([]SPIKESecretRef, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "- ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ref := strings.TrimSpace(fields[0])
		ref = strings.Trim(ref, `"'`)
		if ref == "" || !spikeSecretRefPattern.MatchString(ref) {
			continue
		}
		if _, exists := seen[ref]; exists {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, SPIKESecretRef{
			Ref:     ref,
			Created: "-",
			Type:    "string",
		})
	}

	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Ref < refs[j].Ref
	})
	return refs, nil
}

func RenderSecretListTable(refs []SPIKESecretRef) (string, error) {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "REF\tCREATED\tTYPE")
	for _, ref := range refs {
		created := ref.Created
		if strings.TrimSpace(created) == "" {
			created = "-"
		}
		typ := ref.Type
		if strings.TrimSpace(typ) == "" {
			typ = "string"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", ref.Ref, created, typ)
	}
	if err := w.Flush(); err != nil {
		return "", err
	}
	return b.String(), nil
}

func RenderSecretListJSON(refs []SPIKESecretRef) ([]byte, error) {
	return json.MarshalIndent(SPIKESecretListOutput{Secrets: refs}, "", "  ")
}

func RenderSecretPutTable(result SPIKESecretPutResult) (string, error) {
	var b strings.Builder
	_, _ = fmt.Fprintln(&b, "Secret stored successfully")
	_, _ = fmt.Fprintf(&b, "REF: %s\n", result.Ref)
	return b.String(), nil
}

func RenderSecretPutJSON(result SPIKESecretPutResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

func (s *SPIKECLI) run(ctx context.Context, args []string) (string, string, error) {
	if len(args) == 0 {
		return "", "", errors.New("command args cannot be empty")
	}
	return s.runner.Run(ctx, args[0], args[1:]...)
}

func spikeListPrimaryArgs() []string {
	// Story-required command path:
	// docker compose exec spike-nexus spike pilot list
	return []string{"docker", "compose", "exec", "-T", "spike-nexus", "spike", "pilot", "list"}
}

func spikeListFallbackArgs() []string {
	// The currently running stack exposes the CLI through the spike-pilot image.
	return []string{"docker", "compose", "run", "--rm", "--no-deps", "--entrypoint", "/usr/local/bin/spike", "spike-secret-seeder", "secret", "list"}
}

func spikePutPrimaryArgs(ref, value string) []string {
	// Story-required command path:
	// docker compose exec spike-nexus spike pilot put --ref <ref> --value <value>
	return []string{"docker", "compose", "exec", "-T", "spike-nexus", "spike", "pilot", "put", "--ref", ref, "--value", value}
}

func spikePutFallbackArgs(ref, value string) []string {
	return []string{"docker", "compose", "run", "--rm", "--no-deps", "--entrypoint", "/usr/local/bin/spike", "spike-secret-seeder", "secret", "put", ref, "value=" + value}
}

func shouldFallbackToModernSPIKECLI(err error, stderr string) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(stderr + " " + err.Error()))
	return strings.Contains(msg, "exec: \"spike\"") ||
		strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "not found in $path") ||
		strings.Contains(msg, "unknown command \"pilot\"") ||
		strings.Contains(msg, "exit status 127")
}

func redactSecretValueInError(stderr string, err error) error {
	redacted := redactSecretValue(stderr)
	if redacted == "" {
		return err
	}
	return fmt.Errorf("%w (stderr=%s)", err, redacted)
}

func redactSecretValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	valueKV := regexp.MustCompile(`(?i)value\s*=\s*[^[:space:]]+`)
	s = valueKV.ReplaceAllString(s, "value=<redacted>")
	valueJSON := regexp.MustCompile(`(?i)"value"\s*:\s*"[^"]*"`)
	s = valueJSON.ReplaceAllString(s, `"value":"<redacted>"`)
	return s
}
