package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tiiuae/oryxid/internal/config"
)

type Client struct {
	client *redis.Client
	ctx    context.Context
}

// NewClient creates a new Redis client
func NewClient(cfg *config.Config) (*Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		PoolSize:     cfg.Redis.PoolSize,
		MinIdleConns: cfg.Redis.MinIdleConns,
	})

	ctx := context.Background()

	// Test connection
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Client{
		client: client,
		ctx:    ctx,
	}, nil
}

// Close closes the Redis connection
func (c *Client) Close() error {
	return c.client.Close()
}

// Session Management

// SetSession stores a session in Redis
func (c *Client) SetSession(sessionID string, data interface{}, expiration time.Duration) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	return c.client.Set(c.ctx, fmt.Sprintf("session:%s", sessionID), jsonData, expiration).Err()
}

// GetSession retrieves a session from Redis
func (c *Client) GetSession(sessionID string, data interface{}) error {
	result, err := c.client.Get(c.ctx, fmt.Sprintf("session:%s", sessionID)).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("session not found")
		}
		return err
	}

	return json.Unmarshal([]byte(result), data)
}

// DeleteSession removes a session from Redis
func (c *Client) DeleteSession(sessionID string) error {
	return c.client.Del(c.ctx, fmt.Sprintf("session:%s", sessionID)).Err()
}

// RefreshSession updates session expiration
func (c *Client) RefreshSession(sessionID string, expiration time.Duration) error {
	return c.client.Expire(c.ctx, fmt.Sprintf("session:%s", sessionID), expiration).Err()
}

// Token Blacklisting

// BlacklistToken adds a token to the blacklist
func (c *Client) BlacklistToken(tokenHash string, expiration time.Duration) error {
	return c.client.Set(c.ctx, fmt.Sprintf("blacklist:%s", tokenHash), true, expiration).Err()
}

// IsTokenBlacklisted checks if a token is blacklisted
func (c *Client) IsTokenBlacklisted(tokenHash string) bool {
	exists, _ := c.client.Exists(c.ctx, fmt.Sprintf("blacklist:%s", tokenHash)).Result()
	return exists > 0
}

// Rate Limiting

// IncrementRateLimit increments the rate limit counter for a key
func (c *Client) IncrementRateLimit(key string, window time.Duration) (int64, error) {
	pipe := c.client.Pipeline()
	incr := pipe.Incr(c.ctx, fmt.Sprintf("ratelimit:%s", key))
	pipe.Expire(c.ctx, fmt.Sprintf("ratelimit:%s", key), window)

	_, err := pipe.Exec(c.ctx)
	if err != nil {
		return 0, err
	}

	return incr.Val(), nil
}

// GetRateLimit gets the current rate limit count for a key
func (c *Client) GetRateLimit(key string) (int64, error) {
	result, err := c.client.Get(c.ctx, fmt.Sprintf("ratelimit:%s", key)).Int64()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, err
	}
	return result, nil
}

// ResetRateLimit resets the rate limit for a key
func (c *Client) ResetRateLimit(key string) error {
	return c.client.Del(c.ctx, fmt.Sprintf("ratelimit:%s", key)).Err()
}

// Caching

// SetCache stores a value in cache
func (c *Client) SetCache(key string, value interface{}, expiration time.Duration) error {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %w", err)
	}

	return c.client.Set(c.ctx, fmt.Sprintf("cache:%s", key), jsonData, expiration).Err()
}

// GetCache retrieves a value from cache
func (c *Client) GetCache(key string, value interface{}) error {
	result, err := c.client.Get(c.ctx, fmt.Sprintf("cache:%s", key)).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("cache miss")
		}
		return err
	}

	return json.Unmarshal([]byte(result), value)
}

// DeleteCache removes a value from cache
func (c *Client) DeleteCache(key string) error {
	return c.client.Del(c.ctx, fmt.Sprintf("cache:%s", key)).Err()
}

// InvalidateCache removes multiple cache entries by pattern
func (c *Client) InvalidateCache(pattern string) error {
	keys, err := c.client.Keys(c.ctx, fmt.Sprintf("cache:%s*", pattern)).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return c.client.Del(c.ctx, keys...).Err()
	}

	return nil
}

// Distributed Locking

// AcquireLock attempts to acquire a distributed lock
func (c *Client) AcquireLock(key string, value string, expiration time.Duration) (bool, error) {
	result := c.client.SetNX(c.ctx, fmt.Sprintf("lock:%s", key), value, expiration)
	return result.Val(), result.Err()
}

// ReleaseLock releases a distributed lock
func (c *Client) ReleaseLock(key string, value string) error {
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`

	result := c.client.Eval(c.ctx, script, []string{fmt.Sprintf("lock:%s", key)}, value)
	return result.Err()
}

// ExtendLock extends the expiration of a lock
func (c *Client) ExtendLock(key string, value string, expiration time.Duration) (bool, error) {
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("expire", KEYS[1], ARGV[2])
		else
			return 0
		end
	`

	result := c.client.Eval(c.ctx, script, []string{fmt.Sprintf("lock:%s", key)}, value, int(expiration.Seconds()))
	val, err := result.Int()
	return val == 1, err
}

// Statistics and Monitoring

// IncrementCounter increments a counter
func (c *Client) IncrementCounter(key string) error {
	return c.client.Incr(c.ctx, fmt.Sprintf("counter:%s", key)).Err()
}

// GetCounter gets a counter value
func (c *Client) GetCounter(key string) (int64, error) {
	result, err := c.client.Get(c.ctx, fmt.Sprintf("counter:%s", key)).Int64()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, err
	}
	return result, nil
}

// Pub/Sub

// Publish publishes a message to a channel
func (c *Client) Publish(channel string, message interface{}) error {
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	return c.client.Publish(c.ctx, channel, jsonData).Err()
}

// Subscribe subscribes to a channel
func (c *Client) Subscribe(channel string) *redis.PubSub {
	return c.client.Subscribe(c.ctx, channel)
}
