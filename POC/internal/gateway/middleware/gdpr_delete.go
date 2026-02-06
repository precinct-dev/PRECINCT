package middleware

import (
	"context"
	"fmt"
	"log"

	"github.com/redis/go-redis/v9"
)

// GDPRDeleteResult captures the outcome of a right-to-deletion operation
// for compliance evidence (GDPR Art. 17, CCPA 1798.105).
type GDPRDeleteResult struct {
	SPIFFEID        string   `json:"spiffe_id"`
	SessionsFound   int      `json:"sessions_found"`
	KeysDeleted     int      `json:"keys_deleted"`
	SessionIDs      []string `json:"session_ids,omitempty"`
	RateLimitPurged bool     `json:"rate_limit_purged"`
}

// GDPRDeleteAllData removes ALL session and rate limit data associated with
// a given SPIFFE ID from KeyDB. This implements the right-to-deletion
// required by GDPR Article 17 and CCPA Section 1798.105.
//
// Keys deleted:
//   - session:{spiffe_id}:{session_id}          (session metadata)
//   - session:{spiffe_id}:{session_id}:actions   (tool action list)
//   - ratelimit:{spiffe_id}:tokens               (rate limit token count)
//   - ratelimit:{spiffe_id}:last_fill            (rate limit last refill)
//   - gdpr:sessions:{spiffe_id}                  (GDPR tracking set)
//
// If the SPIFFE ID has no data, this is a no-op (returns zero counts, no error).
func GDPRDeleteAllData(ctx context.Context, client *redis.Client, spiffeID string) (*GDPRDeleteResult, error) {
	result := &GDPRDeleteResult{
		SPIFFEID:   spiffeID,
		SessionIDs: make([]string, 0),
	}

	// 1. Read the gdpr:sessions:{spiffe_id} SET to find all session IDs
	gdprKey := keyDBGDPRKey(spiffeID)
	sessionIDs, err := client.SMembers(ctx, gdprKey).Result()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("gdpr read sessions set: %w", err)
	}

	result.SessionsFound = len(sessionIDs)
	result.SessionIDs = sessionIDs

	// 2. Collect all keys to delete
	keysToDelete := make([]string, 0, len(sessionIDs)*2+3)

	// Session keys and action lists
	for _, sessionID := range sessionIDs {
		keysToDelete = append(keysToDelete,
			keyDBSessionKey(spiffeID, sessionID),
			keyDBActionsKey(spiffeID, sessionID),
		)
	}

	// Rate limit keys
	keysToDelete = append(keysToDelete,
		rateLimitTokensKey(spiffeID),
		rateLimitLastFillKey(spiffeID),
	)

	// The GDPR tracking set itself
	keysToDelete = append(keysToDelete, gdprKey)

	// 3. Delete all keys in a single pipeline for atomicity
	if len(keysToDelete) > 0 {
		pipe := client.Pipeline()
		for _, key := range keysToDelete {
			pipe.Del(ctx, key)
		}
		cmds, err := pipe.Exec(ctx)
		if err != nil {
			return nil, fmt.Errorf("gdpr delete pipeline: %w", err)
		}

		// Count how many keys were actually deleted (existed before deletion)
		for _, cmd := range cmds {
			if delCmd, ok := cmd.(*redis.IntCmd); ok {
				result.KeysDeleted += int(delCmd.Val())
			}
		}
	}

	// Mark rate limit as purged (even if keys did not exist)
	result.RateLimitPurged = true

	// 4. Log the deletion event for compliance evidence
	log.Printf("GDPR_DELETION: spiffe_id=%s sessions_found=%d keys_deleted=%d session_ids=%v",
		spiffeID, result.SessionsFound, result.KeysDeleted, result.SessionIDs)

	return result, nil
}
