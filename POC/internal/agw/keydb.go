package agw

import (
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

func NewKeyDBClient(keydbURL string) (*redis.Client, error) {
	keydbURL = strings.TrimSpace(keydbURL)
	if keydbURL == "" {
		return nil, fmt.Errorf("keydb url is empty")
	}
	opt, err := redis.ParseURL(keydbURL)
	if err != nil {
		return nil, fmt.Errorf("parse keydb url: %w", err)
	}
	return redis.NewClient(opt), nil
}

