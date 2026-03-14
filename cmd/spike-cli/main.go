package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/precinct-dev/precinct/internal/spike"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "init":
		if err := runInit(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "put":
		if err := runPut(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "issue":
		if err := runIssue(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("spike-cli version %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`spike-cli - SPIKE Nexus secret management CLI

Usage:
  spike-cli <command> [options]

Commands:
  init                  Bootstrap SPIKE Nexus with root policy for local dev
  put <ref> <value>     Seed a secret with SPIFFE allowlist and scope
  issue <ref>           Issue a token for testing
  version               Show version
  help                  Show this help message

Examples:
  spike-cli init
  spike-cli put my-api-key sk-abc123 --spiffe spiffe://example.org/agent/test --scope tools.http.api.openai.com
  spike-cli issue my-api-key --exp 300 --scope tools.http.api.openai.com

For more information, see: docs/spike-cli.md`)
}

func runInit() error {
	client := spike.NewClient(spike.DefaultConfig())

	fmt.Println("Initializing SPIKE Nexus for local development...")

	if err := client.Init(); err != nil {
		return fmt.Errorf("initialization failed: %w", err)
	}

	fmt.Println("SUCCESS: SPIKE Nexus initialized")
	fmt.Println("  - Root policy created")
	fmt.Println("  - Local development mode enabled")
	fmt.Println("")
	fmt.Println("Next steps:")
	fmt.Println("  1. Use 'spike-cli put' to seed secrets")
	fmt.Println("  2. Use 'spike-cli issue' to generate test tokens")

	return nil
}

func runPut(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: spike-cli put <ref> <value> [--spiffe <spiffe-id>] [--scope <scope>]")
	}

	ref := args[0]
	value := args[1]

	// Parse optional flags
	spiffeID := ""
	scope := ""

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--spiffe":
			if i+1 < len(args) {
				spiffeID = args[i+1]
				i++
			}
		case "--scope":
			if i+1 < len(args) {
				scope = args[i+1]
				i++
			}
		}
	}

	client := spike.NewClient(spike.DefaultConfig())

	fmt.Printf("Seeding secret: ref=%s\n", ref)

	secret := &spike.Secret{
		Ref:       ref,
		Value:     value,
		SpiffeID:  spiffeID,
		Scope:     scope,
		ExpiresAt: 0, // No expiry for seeded secrets (tokens have expiry)
	}

	if err := client.Put(secret); err != nil {
		return fmt.Errorf("failed to seed secret: %w", err)
	}

	fmt.Println("SUCCESS: Secret seeded")
	fmt.Printf("  Ref: %s\n", ref)
	if spiffeID != "" {
		fmt.Printf("  SPIFFE ID: %s\n", spiffeID)
	}
	if scope != "" {
		fmt.Printf("  Scope: %s\n", scope)
	}
	fmt.Println("")
	fmt.Println("Use 'spike-cli issue' to generate a token for this secret")

	return nil
}

func runIssue(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: spike-cli issue <ref> [--exp <seconds>] [--scope <scope>]")
	}

	ref := args[0]

	// Parse optional flags
	exp := int64(300) // Default 5 minutes
	scope := ""

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--exp":
			if i+1 < len(args) {
				parsedExp, err := strconv.ParseInt(args[i+1], 10, 64)
				if err != nil {
					return fmt.Errorf("invalid --exp value %q: %w", args[i+1], err)
				}
				exp = parsedExp
				i++
			}
		case "--scope":
			if i+1 < len(args) {
				scope = args[i+1]
				i++
			}
		}
	}

	client := spike.NewClient(spike.DefaultConfig())

	fmt.Printf("Issuing token: ref=%s\n", ref)

	token, err := client.Issue(ref, exp, scope)
	if err != nil {
		return fmt.Errorf("failed to issue token: %w", err)
	}

	fmt.Println("SUCCESS: Token issued")
	fmt.Println("")
	fmt.Println("Token:")
	fmt.Printf("  %s\n", token)
	fmt.Println("")
	fmt.Println("Use this token in your agent requests to the gateway.")
	fmt.Println("The gateway will substitute it with the actual secret.")

	return nil
}
