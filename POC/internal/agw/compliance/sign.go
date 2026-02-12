package compliance

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var cosignLookPath = exec.LookPath

type SignParams struct {
	EvidenceDir string
	CosignKey   string
	WorkDir     string
}

type SignResult struct {
	Skipped       bool   `json:"skipped"`
	SkipReason    string `json:"skip_reason,omitempty"`
	ArchivePath   string `json:"archive_path,omitempty"`
	BundlePath    string `json:"bundle_path,omitempty"`
	SignaturePath string `json:"signature_path,omitempty"`
}

func SignEvidencePackage(p SignParams) (SignResult, error) {
	evidenceDir := strings.TrimSpace(p.EvidenceDir)
	if evidenceDir == "" {
		return SignResult{}, fmt.Errorf("evidence dir is required")
	}
	if st, err := os.Stat(evidenceDir); err != nil || !st.IsDir() {
		return SignResult{}, fmt.Errorf("evidence dir does not exist: %s", evidenceDir)
	}

	if _, err := cosignLookPath("cosign"); err != nil {
		return SignResult{
			Skipped:    true,
			SkipReason: "cosign not installed; skipping signing",
		}, nil
	}

	wd := strings.TrimSpace(p.WorkDir)
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return SignResult{}, err
		}
	}

	projectRoot, err := FindProjectRoot(wd)
	if err != nil {
		return SignResult{}, err
	}

	keyPath := strings.TrimSpace(p.CosignKey)
	if keyPath == "" {
		keyPath = filepath.Join(projectRoot, ".cosign", "cosign.key")
	}
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(projectRoot, keyPath)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return SignResult{}, fmt.Errorf("cosign key not found: %s", keyPath)
	}

	archivePath := filepath.Join(evidenceDir, "evidence-package.tar.gz")
	if err := createTarGzFromDir(evidenceDir, archivePath); err != nil {
		return SignResult{}, err
	}
	sigPath := archivePath + ".sig"
	bundlePath := archivePath + ".bundle"

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, stderr, err := runExternalCommand(
		ctx,
		projectRoot,
		"cosign",
		"sign-blob",
		"--yes",
		"--key", keyPath,
		"--output-signature", sigPath,
		"--bundle", bundlePath,
		"--new-bundle-format=false",
		"--use-signing-config=false",
		archivePath,
	)
	if err != nil {
		return SignResult{}, fmt.Errorf("cosign sign-blob failed: %w (stderr=%s)", err, strings.TrimSpace(stderr))
	}
	if _, err := os.Stat(sigPath); err != nil {
		return SignResult{}, fmt.Errorf("expected signature not found at %s", sigPath)
	}

	return SignResult{
		ArchivePath:   archivePath,
		BundlePath:    bundlePath,
		SignaturePath: sigPath,
	}, nil
}

func createTarGzFromDir(srcDir, dstPath string) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	gw := gzip.NewWriter(out)
	defer func() {
		_ = gw.Close()
	}()

	tw := tar.NewWriter(gw)
	defer func() {
		_ = tw.Close()
	}()

	base := filepath.Dir(srcDir)
	dstAbs, _ := filepath.Abs(dstPath)
	return filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == srcDir {
			return nil
		}
		pathAbs, _ := filepath.Abs(path)
		if pathAbs == dstAbs {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if d.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() {
			_ = f.Close()
		}()
		if _, err := io.Copy(tw, f); err != nil {
			return err
		}
		return nil
	})
}
