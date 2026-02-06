// cmd/gdpr-delete implements the GDPR/CCPA right-to-deletion command for
// session and rate limit data stored in KeyDB.
//
// Usage:
//
//	go run ./cmd/gdpr-delete <SPIFFE_ID>
//	KEYDB_URL=redis://keydb:6379 go run ./cmd/gdpr-delete spiffe://poc.local/agents/example
//
// Environment variables:
//
//	KEYDB_URL  KeyDB/Redis connection URL (default: redis://localhost:6379)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "" {
		fmt.Fprintf(os.Stderr, "Usage: gdpr-delete <SPIFFE_ID>\n")
		fmt.Fprintf(os.Stderr, "  Removes ALL session and rate limit data for the given SPIFFE ID.\n")
		fmt.Fprintf(os.Stderr, "\nEnvironment:\n")
		fmt.Fprintf(os.Stderr, "  KEYDB_URL  KeyDB/Redis URL (default: redis://localhost:6379)\n")
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  make gdpr-delete SPIFFE_ID=spiffe://poc.local/agents/example\n")
		os.Exit(1)
	}

	spiffeID := os.Args[1]

	keyDBURL := os.Getenv("KEYDB_URL")
	if keyDBURL == "" {
		keyDBURL = "redis://localhost:6379"
	}

	// Create KeyDB client (pool min=1, max=5 -- this is a short-lived CLI tool)
	client := middleware.NewKeyDBClient(keyDBURL, 1, 5)
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("Warning: failed to close KeyDB connection: %v", err)
		}
	}()

	// Verify connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Fatalf("Cannot connect to KeyDB at %s: %v", keyDBURL, err)
	}

	// Execute deletion
	log.Printf("GDPR Right-to-Deletion: SPIFFE_ID=%s", spiffeID)
	log.Printf("KeyDB: %s", keyDBURL)

	result, err := middleware.GDPRDeleteAllData(ctx, client, spiffeID)
	if err != nil {
		log.Fatalf("Deletion failed: %v", err)
	}

	// Output result as JSON for compliance evidence
	resultJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal result: %v", err)
	}

	fmt.Println(string(resultJSON))

	if result.SessionsFound == 0 && result.KeysDeleted == 0 {
		log.Printf("No data found for SPIFFE ID %s (no-op)", spiffeID)
	} else {
		log.Printf("Deletion complete: %d sessions, %d keys removed", result.SessionsFound, result.KeysDeleted)
	}
}
