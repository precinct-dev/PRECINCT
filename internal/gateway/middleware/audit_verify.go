// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// ChainVerificationResult contains the result of chain verification
type ChainVerificationResult struct {
	Valid          bool
	TotalEvents    int
	TamperedEvents []int // indices of tampered events
	ErrorMessage   string
}

// VerifyAuditChain verifies the integrity of the audit chain from a JSONL file
func VerifyAuditChain(jsonlPath string) (*ChainVerificationResult, error) {
	file, err := os.Open(jsonlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	result := &ChainVerificationResult{
		Valid:          true,
		TotalEvents:    0,
		TamperedEvents: make([]int, 0),
	}

	// Genesis hash (SHA-256 of empty string)
	genesisHash := sha256.Sum256([]byte(""))
	expectedPrevHash := hex.EncodeToString(genesisHash[:])

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		lineNum++
		result.TotalEvents++

		// Parse event
		var event AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			result.Valid = false
			result.ErrorMessage = fmt.Sprintf("line %d: invalid JSON: %v", lineNum, err)
			result.TamperedEvents = append(result.TamperedEvents, lineNum-1)
			continue
		}

		// Verify prev_hash matches expected
		if event.PrevHash != expectedPrevHash {
			result.Valid = false
			result.TamperedEvents = append(result.TamperedEvents, lineNum-1)
			if result.ErrorMessage == "" {
				result.ErrorMessage = fmt.Sprintf("chain break at event %d: expected prev_hash %s, got %s",
					lineNum, expectedPrevHash, event.PrevHash)
			}
		}

		// Compute hash of this event for next iteration
		currentHash := sha256.Sum256(line)
		expectedPrevHash = hex.EncodeToString(currentHash[:])
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if result.TotalEvents == 0 {
		return nil, fmt.Errorf("no events found in file")
	}

	return result, nil
}

// VerifyEventIntegrity verifies a single event's integrity fields
func VerifyEventIntegrity(event AuditEvent, bundlePath, registryPath string) error {
	// Verify bundle digest
	bundleDigest, err := computeFileDigest(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to compute bundle digest: %w", err)
	}
	if event.BundleDigest != bundleDigest {
		return fmt.Errorf("bundle digest mismatch: expected %s, got %s", bundleDigest, event.BundleDigest)
	}

	// Verify registry digest
	registryDigest, err := computeFileDigest(registryPath)
	if err != nil {
		return fmt.Errorf("failed to compute registry digest: %w", err)
	}
	if event.RegistryDigest != registryDigest {
		return fmt.Errorf("registry digest mismatch: expected %s, got %s", registryDigest, event.RegistryDigest)
	}

	return nil
}
