package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tiiuae/oryxid/internal/redis"
	"golang.org/x/time/rate"
)

// RateLimiter interface for different rate limiting strategies
type RateLimiter interface {
	Allow(key string) bool
}

// InMemoryRateLimiter uses in-memory rate limiting
type InMemoryRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.Mutex
	rps      int
	burst    int
}

// NewInMemoryRateLimiter creates a new in-memory rate limiter
func NewInMemoryRateLimiter(rps, burst int) *InMemoryRateLimiter {
	return &InMemoryRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rps,
		burst:    burst,
	}
}

// Allow checks if the request is allowed
func (r *InMemoryRateLimiter) Allow(key string) bool {
	r.mu.Lock()
	limiter, exists := r.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(r.rps), r.burst)
		r.limiters[key] = limiter
	}
	r.mu.Unlock()
	return limiter.Allow()
}

// RedisRateLimiter uses Redis for distributed rate limiting
type RedisRateLimiter struct {
	client *redis.Client
	rps    int
	window time.Duration
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
func NewRedisRateLimiter(client *redis.Client, rps int) *RedisRateLimiter {
	return &RedisRateLimiter{
		client: client,
		rps:    rps,
		window: time.Second,
	}
}

// Allow checks if the request is allowed
func (r *RedisRateLimiter) Allow(key string) bool {
	count, err := r.client.IncrementRateLimit(key, r.window)
	if err != nil {
		// On error, allow the request
		return true
	}
	return count <= int64(r.rps)
}

// RateLimit creates a rate limiting middleware
func RateLimit(limiter RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate rate limit key based on IP and endpoint
		key := fmt.Sprintf("%s:%s:%s", c.ClientIP(), c.Request.Method, c.Request.URL.Path)

		if !limiter.Allow(key) {
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", 100))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Second).Unix()))
			c.Header("Retry-After", "1")

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate limit exceeded",
				"message": "Too many requests. Please retry after some time.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitByClient creates a rate limiting middleware that limits by client ID
func RateLimitByClient(limiter RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get client ID from context (set by auth middleware)
		clientID := c.GetString("client_id")
		if clientID == "" {
			// Fall back to IP-based rate limiting
			clientID = c.ClientIP()
		}

		key := fmt.Sprintf("client:%s", clientID)

		if !limiter.Allow(key) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate limit exceeded",
				"message": "Client has exceeded rate limit",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitByUser creates a rate limiting middleware that limits by user ID
func RateLimitByUser(limiter RateLimiter, rps int) gin.HandlerFunc {
	userLimiters := make(map[string]*rate.Limiter)

	return func(c *gin.Context) {
		// Get user ID from context (set by auth middleware)
		userID := c.GetString("user_id")
		if userID == "" {
			// No user context, proceed without rate limiting
			c.Next()
			return
		}

		// Get or create limiter for this user
		// Burst is set to rps for predictable rate limiting behavior
		userLimiter, exists := userLimiters[userID]
		if !exists {
			userLimiter = rate.NewLimiter(rate.Limit(rps), rps)
			userLimiters[userID] = userLimiter
		}

		if !userLimiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate limit exceeded",
				"message": "User has exceeded rate limit",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// AdaptiveRateLimit creates an adaptive rate limiting middleware
func AdaptiveRateLimit(baseRPS int, burstMultiplier int) gin.HandlerFunc {
	limiters := make(map[string]*adaptiveLimiter)

	return func(c *gin.Context) {
		key := c.ClientIP()

		limiter, exists := limiters[key]
		if !exists {
			limiter = newAdaptiveLimiter(baseRPS, burstMultiplier)
			limiters[key] = limiter
		}

		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate limit exceeded",
				"message": "Please slow down your requests",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// adaptiveLimiter adjusts rate limits based on behavior
type adaptiveLimiter struct {
	limiter         *rate.Limiter
	baseRPS         int
	burstMultiplier int
	violations      int
	lastViolation   time.Time
}

func newAdaptiveLimiter(baseRPS, burstMultiplier int) *adaptiveLimiter {
	return &adaptiveLimiter{
		limiter:         rate.NewLimiter(rate.Limit(baseRPS), baseRPS*burstMultiplier),
		baseRPS:         baseRPS,
		burstMultiplier: burstMultiplier,
		violations:      0,
		lastViolation:   time.Time{},
	}
}

func (a *adaptiveLimiter) Allow() bool {
	allowed := a.limiter.Allow()

	if !allowed {
		now := time.Now()
		// Reset violations if last violation was more than 5 minutes ago
		if now.Sub(a.lastViolation) > 5*time.Minute {
			a.violations = 0
		}

		a.violations++
		a.lastViolation = now

		// Reduce rate limit for repeat offenders
		if a.violations > 3 {
			newRate := rate.Limit(a.baseRPS / 2)
			a.limiter.SetLimit(newRate)
		}
	} else if a.violations > 0 && time.Since(a.lastViolation) > time.Minute {
		// Gradually restore rate limit
		a.violations--
		if a.violations == 0 {
			a.limiter.SetLimit(rate.Limit(a.baseRPS))
		}
	}

	return allowed
}
