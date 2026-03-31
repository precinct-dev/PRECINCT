package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	approvalRequestKeyPrefix = "approval:request:"
	approvalNonceKeyPrefix   = "approval:nonce:"
	approvalRecordMinTTL     = 5 * time.Minute
	approvalRecordTailTTL    = 1 * time.Hour
)

type approvalDistributedStore interface {
	PutRequest(ctx context.Context, record ApprovalRequestRecord) error
	GetRequest(ctx context.Context, requestID string) (ApprovalRequestRecord, bool, error)
	MarkNonceConsumed(ctx context.Context, nonce string, expiresAt time.Time) (bool, error)
}

type keyDBApprovalDistributedStore struct {
	client *redis.Client
}

func (s *ApprovalCapabilityService) EnableDistributedState(client *redis.Client) {
	if client == nil {
		s.distributed = nil
		return
	}
	s.distributed = &keyDBApprovalDistributedStore{client: client}
}

func (k *keyDBApprovalDistributedStore) PutRequest(ctx context.Context, record ApprovalRequestRecord) error {
	if k == nil || k.client == nil {
		return fmt.Errorf("approval distributed store is unavailable")
	}
	key := approvalRequestKey(strings.TrimSpace(record.RequestID))
	if key == "" {
		return fmt.Errorf("approval request_id is required")
	}

	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal approval request: %w", err)
	}
	ttl := approvalRecordTTL(record.ExpiresAt)
	if err := k.client.Set(ctx, key, raw, ttl).Err(); err != nil {
		return fmt.Errorf("keydb set approval request: %w", err)
	}
	return nil
}

func (k *keyDBApprovalDistributedStore) GetRequest(ctx context.Context, requestID string) (ApprovalRequestRecord, bool, error) {
	if k == nil || k.client == nil {
		return ApprovalRequestRecord{}, false, fmt.Errorf("approval distributed store is unavailable")
	}
	key := approvalRequestKey(strings.TrimSpace(requestID))
	if key == "" {
		return ApprovalRequestRecord{}, false, nil
	}
	raw, err := k.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return ApprovalRequestRecord{}, false, nil
	}
	if err != nil {
		return ApprovalRequestRecord{}, false, fmt.Errorf("keydb get approval request: %w", err)
	}

	var record ApprovalRequestRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return ApprovalRequestRecord{}, false, fmt.Errorf("unmarshal approval request: %w", err)
	}
	return record, true, nil
}

func (k *keyDBApprovalDistributedStore) MarkNonceConsumed(ctx context.Context, nonce string, expiresAt time.Time) (bool, error) {
	if k == nil || k.client == nil {
		return false, fmt.Errorf("approval distributed store is unavailable")
	}
	n := strings.TrimSpace(nonce)
	if n == "" {
		return false, ErrApprovalTokenInvalid
	}
	key := approvalNonceKeyPrefix + n
	ttl := time.Until(expiresAt.Add(approvalRecordTailTTL))
	if ttl < time.Minute {
		ttl = time.Minute
	}
	set, err := k.client.SetArgs(ctx, key, "1", redis.SetArgs{
		Mode: "NX",
		TTL:  ttl,
	}).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("keydb setnx approval nonce: %w", err)
	}
	return set == "OK", nil
}

func approvalRequestKey(requestID string) string {
	if requestID == "" {
		return ""
	}
	return approvalRequestKeyPrefix + requestID
}

func approvalRecordTTL(expiresAt time.Time) time.Duration {
	if expiresAt.IsZero() {
		return approvalRecordTailTTL
	}
	ttl := time.Until(expiresAt.Add(approvalRecordTailTTL))
	if ttl < approvalRecordMinTTL {
		return approvalRecordMinTTL
	}
	return ttl
}
