package precinctcli

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeCommandResult struct {
	stdout string
	stderr string
	err    error
}

type fakeCommandRunner struct {
	results []fakeCommandResult
	calls   [][]string
}

func (f *fakeCommandRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	if len(f.results) == 0 {
		return "", "", errors.New("unexpected command")
	}
	result := f.results[0]
	f.results = f.results[1:]
	return result.stdout, result.stderr, result.err
}

func TestParseSPIKESecretList(t *testing.T) {
	raw := `
- deadbeef
- f6e5d4c3b2a1
deadbeef
value: should-not-parse
`

	refs, err := ParseSPIKESecretList(raw)
	if err != nil {
		t.Fatalf("ParseSPIKESecretList() error = %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %+v", refs)
	}
	if refs[0].Ref != "deadbeef" {
		t.Fatalf("expected first ref deadbeef, got %+v", refs)
	}
	if refs[1].Ref != "f6e5d4c3b2a1" {
		t.Fatalf("expected second ref f6e5d4c3b2a1, got %+v", refs)
	}
}

func TestSPIKECLI_ListSecretRefs_Fallback(t *testing.T) {
	runner := &fakeCommandRunner{
		results: []fakeCommandResult{
			{
				stderr: `OCI runtime exec failed: exec: "spike": executable file not found in $PATH`,
				err:    errors.New("exit status 127"),
			},
			{
				stderr: "time=... warning...\n- deadbeef\n- a1b2c3d4\n",
			},
		},
	}
	cli := NewSPIKECLIWithRunner(runner)

	refs, err := cli.ListSecretRefs(context.Background())
	if err != nil {
		t.Fatalf("ListSecretRefs() error = %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %+v", refs)
	}
	if refs[0].Ref != "a1b2c3d4" || refs[1].Ref != "deadbeef" {
		t.Fatalf("unexpected refs ordering/content: %+v", refs)
	}

	if len(runner.calls) != 2 {
		t.Fatalf("expected 2 command calls, got %+v", runner.calls)
	}
	wantFirst := append([]string{"docker"}, composeArgs("exec", "-T", "spike-nexus", "spike", "pilot", "list")...)
	if !reflect.DeepEqual(runner.calls[0], wantFirst) {
		t.Fatalf("unexpected first command call: got=%v want=%v", runner.calls[0], wantFirst)
	}
	wantSecond := append([]string{"docker"}, composeArgs("run", "--rm", "--no-deps", "--entrypoint", "/usr/local/bin/spike", "spike-secret-seeder", "secret", "list")...)
	if !reflect.DeepEqual(runner.calls[1], wantSecond) {
		t.Fatalf("unexpected second command call: got=%v want=%v", runner.calls[1], wantSecond)
	}
}

func TestSPIKECLI_PutSecret_Fallback(t *testing.T) {
	runner := &fakeCommandRunner{
		results: []fakeCommandResult{
			{
				stderr: `unknown command "pilot" for "spike"`,
				err:    errors.New("exit status 1"),
			},
			{
				stdout: "OK\n",
			},
		},
	}
	cli := NewSPIKECLIWithRunner(runner)

	result, err := cli.PutSecret(context.Background(), "deadbeef", "super-secret")
	if err != nil {
		t.Fatalf("PutSecret() error = %v", err)
	}
	if result.Status != "stored" || result.Ref != "deadbeef" {
		t.Fatalf("unexpected put result: %+v", result)
	}

	if len(runner.calls) != 2 {
		t.Fatalf("expected 2 command calls, got %+v", runner.calls)
	}
	wantFirst := append([]string{"docker"}, composeArgs("exec", "-T", "spike-nexus", "spike", "pilot", "put", "--ref", "deadbeef", "--value", "super-secret")...)
	if !reflect.DeepEqual(runner.calls[0], wantFirst) {
		t.Fatalf("unexpected first put command: got=%v want=%v", runner.calls[0], wantFirst)
	}
	wantSecond := append([]string{"docker"}, composeArgs("run", "--rm", "--no-deps", "--entrypoint", "/usr/local/bin/spike", "spike-secret-seeder", "secret", "put", "deadbeef", "value=super-secret")...)
	if !reflect.DeepEqual(runner.calls[1], wantSecond) {
		t.Fatalf("unexpected fallback put command: got=%v want=%v", runner.calls[1], wantSecond)
	}
}

func TestRedactSecretValue(t *testing.T) {
	raw := `failed call value=super-secret and payload {"value":"super-secret"}`
	redacted := redactSecretValue(raw)
	if redacted == "" {
		t.Fatalf("expected non-empty redacted output")
	}
	if redacted == raw {
		t.Fatalf("expected output to change, got %q", redacted)
	}
	if strings.Contains(raw, "super-secret") && strings.Contains(redacted, "super-secret") {
		t.Fatalf("expected secret value to be redacted: %q", redacted)
	}
}
