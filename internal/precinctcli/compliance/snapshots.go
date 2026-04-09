// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type SnapshotItem struct {
	SourcePath string `json:"source_path"`
	DestPath   string `json:"dest_path"`
	SHA256     string `json:"sha256,omitempty"`
	SizeBytes  int64  `json:"size_bytes,omitempty"`
}

func CopyFile(src, dst string) (SnapshotItem, error) {
	in, err := os.Open(src)
	if err != nil {
		return SnapshotItem{}, err
	}
	defer func() {
		_ = in.Close()
	}()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return SnapshotItem{}, err
	}

	out, err := os.Create(dst)
	if err != nil {
		return SnapshotItem{}, err
	}
	defer func() {
		_ = out.Close()
	}()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), in)
	if err != nil {
		return SnapshotItem{}, err
	}

	return SnapshotItem{
		SourcePath: src,
		DestPath:   dst,
		SHA256:     hex.EncodeToString(h.Sum(nil)),
		SizeBytes:  n,
	}, nil
}

func CopyDirRecursive(srcDir, dstDir string) ([]SnapshotItem, error) {
	var items []SnapshotItem
	err := filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(dstDir, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		it, err := CopyFile(path, dst)
		if err != nil {
			return fmt.Errorf("copy %s: %w", path, err)
		}
		items = append(items, it)
		return nil
	})
	return items, err
}
