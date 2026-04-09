// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

const (
	breakGlassRequestKeyPrefix = "breakglass:request:"
	breakGlassIndexKey         = "breakglass:requests"
)

type breakGlassDistributedStore interface {
	Put(ctx context.Context, record breakGlassRecord) error
	Get(ctx context.Context, requestID string) (breakGlassRecord, bool, error)
	List(ctx context.Context) ([]breakGlassRecord, error)
}

type keyDBBreakGlassStore struct {
	client *redis.Client
}

func newKeyDBBreakGlassStore(client *redis.Client) *keyDBBreakGlassStore {
	if client == nil {
		return nil
	}
	return &keyDBBreakGlassStore{client: client}
}

func (k *keyDBBreakGlassStore) Put(ctx context.Context, record breakGlassRecord) error {
	if k == nil || k.client == nil {
		return fmt.Errorf("breakglass distributed store unavailable")
	}
	requestID := strings.TrimSpace(record.RequestID)
	if requestID == "" {
		return fmt.Errorf("breakglass request_id is required")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal breakglass record: %w", err)
	}
	key := breakGlassRequestKeyPrefix + requestID
	pipe := k.client.TxPipeline()
	pipe.Set(ctx, key, raw, 0)
	pipe.SAdd(ctx, breakGlassIndexKey, requestID)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("keydb persist breakglass record: %w", err)
	}
	return nil
}

func (k *keyDBBreakGlassStore) Get(ctx context.Context, requestID string) (breakGlassRecord, bool, error) {
	if k == nil || k.client == nil {
		return breakGlassRecord{}, false, fmt.Errorf("breakglass distributed store unavailable")
	}
	id := strings.TrimSpace(requestID)
	if id == "" {
		return breakGlassRecord{}, false, nil
	}
	raw, err := k.client.Get(ctx, breakGlassRequestKeyPrefix+id).Bytes()
	if err == redis.Nil {
		return breakGlassRecord{}, false, nil
	}
	if err != nil {
		return breakGlassRecord{}, false, fmt.Errorf("keydb get breakglass record: %w", err)
	}
	var record breakGlassRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return breakGlassRecord{}, false, fmt.Errorf("unmarshal breakglass record: %w", err)
	}
	return record, true, nil
}

func (k *keyDBBreakGlassStore) List(ctx context.Context) ([]breakGlassRecord, error) {
	if k == nil || k.client == nil {
		return nil, fmt.Errorf("breakglass distributed store unavailable")
	}
	ids, err := k.client.SMembers(ctx, breakGlassIndexKey).Result()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("keydb list breakglass ids: %w", err)
	}
	out := make([]breakGlassRecord, 0, len(ids))
	for _, id := range ids {
		record, ok, getErr := k.Get(ctx, id)
		if getErr != nil {
			return nil, getErr
		}
		if !ok {
			continue
		}
		out = append(out, cloneBreakGlassRecord(record))
	}
	return out, nil
}
