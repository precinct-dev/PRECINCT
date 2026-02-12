package compliance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSignEvidencePackage_SkipsWhenCosignMissing(t *testing.T) {
	origLookPath := cosignLookPath
	t.Cleanup(func() { cosignLookPath = origLookPath })

	cosignLookPath = func(file string) (string, error) {
		return "", errors.New("not found")
	}

	evidenceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(evidenceDir, "evidence.json"), []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write evidence file: %v", err)
	}

	got, err := SignEvidencePackage(SignParams{EvidenceDir: evidenceDir})
	if err != nil {
		t.Fatalf("SignEvidencePackage: %v", err)
	}
	if !got.Skipped {
		t.Fatalf("expected skipped=true, got %+v", got)
	}
}

func TestSignEvidencePackage_SignsBlobAndWritesSignature(t *testing.T) {
	origRun := runExternalCommand
	origLookPath := cosignLookPath
	t.Cleanup(func() {
		runExternalCommand = origRun
		cosignLookPath = origLookPath
	})

	cosignLookPath = func(file string) (string, error) {
		return "/usr/bin/cosign", nil
	}

	runExternalCommand = func(ctx context.Context, cwd, name string, args ...string) (string, string, error) {
		if name != "cosign" {
			t.Fatalf("expected cosign command, got %s", name)
		}
		if len(args) < 5 || args[0] != "sign-blob" {
			t.Fatalf("unexpected args: %+v", args)
		}
		sigPath := ""
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "--output-signature" {
				sigPath = args[i+1]
				break
			}
		}
		if sigPath == "" {
			t.Fatalf("missing --output-signature in args: %+v", args)
		}
		if err := os.WriteFile(sigPath, []byte("signature"), 0o644); err != nil {
			t.Fatalf("write fake signature: %v", err)
		}
		return "", "", nil
	}

	keyFile := filepath.Join(t.TempDir(), "cosign.key")
	if err := os.WriteFile(keyFile, []byte("dummy-key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	evidenceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(evidenceDir, "evidence.json"), []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write evidence file: %v", err)
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))

	got, err := SignEvidencePackage(SignParams{
		EvidenceDir: evidenceDir,
		CosignKey:   keyFile,
		WorkDir:     projectRoot,
	})
	if err != nil {
		t.Fatalf("SignEvidencePackage: %v", err)
	}
	if got.Skipped {
		t.Fatalf("expected signed result, got %+v", got)
	}
	if _, err := os.Stat(got.ArchivePath); err != nil {
		t.Fatalf("expected archive file at %s: %v", got.ArchivePath, err)
	}
	if _, err := os.Stat(got.SignaturePath); err != nil {
		t.Fatalf("expected signature file at %s: %v", got.SignaturePath, err)
	}
}
