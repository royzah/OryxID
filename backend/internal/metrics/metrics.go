package metrics

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds all application metrics
type Metrics struct {
	startTime time.Time

	// Token issuance counters (by client_id and grant_type)
	tokenIssuance sync.Map // key: "client_id:grant_type" -> *uint64

	// Token validation latency (histogram buckets in milliseconds)
	validationLatency struct {
		sync.RWMutex
		count   uint64
		sum     float64
		buckets map[float64]uint64 // bucket upper bound -> count
	}

	// Failed authentication counter (by reason)
	failedAuth sync.Map // key: reason -> *uint64

	// Rate limit violations counter (by client_id)
	rateLimitViolations sync.Map // key: client_id -> *uint64

	// Active tokens gauge
	activeTokens int64
}

var (
	instance *Metrics
	once     sync.Once
)

// Get returns the singleton metrics instance
func Get() *Metrics {
	once.Do(func() {
		instance = &Metrics{
			startTime: time.Now(),
		}
		instance.validationLatency.buckets = map[float64]uint64{
			5:    0, // 5ms
			10:   0, // 10ms
			25:   0, // 25ms
			50:   0, // 50ms
			100:  0, // 100ms
			250:  0, // 250ms
			500:  0, // 500ms
			1000: 0, // 1s
		}
	})
	return instance
}

// RecordTokenIssuance increments the token issuance counter
func (m *Metrics) RecordTokenIssuance(clientID, grantType string) {
	key := clientID + ":" + grantType
	val, _ := m.tokenIssuance.LoadOrStore(key, new(uint64))
	atomic.AddUint64(val.(*uint64), 1)
}

// RecordValidationLatency records a token validation latency
func (m *Metrics) RecordValidationLatency(duration time.Duration) {
	ms := float64(duration.Milliseconds())

	m.validationLatency.Lock()
	defer m.validationLatency.Unlock()

	m.validationLatency.count++
	m.validationLatency.sum += ms

	// Update histogram buckets
	for bucket := range m.validationLatency.buckets {
		if ms <= bucket {
			m.validationLatency.buckets[bucket]++
		}
	}
}

// RecordFailedAuth increments the failed authentication counter
func (m *Metrics) RecordFailedAuth(reason string) {
	val, _ := m.failedAuth.LoadOrStore(reason, new(uint64))
	atomic.AddUint64(val.(*uint64), 1)
}

// RecordRateLimitViolation increments the rate limit violation counter
func (m *Metrics) RecordRateLimitViolation(clientID string) {
	val, _ := m.rateLimitViolations.LoadOrStore(clientID, new(uint64))
	atomic.AddUint64(val.(*uint64), 1)
}

// SetActiveTokens sets the active tokens gauge
func (m *Metrics) SetActiveTokens(count int64) {
	atomic.StoreInt64(&m.activeTokens, count)
}

// IncrementActiveTokens increments the active tokens gauge
func (m *Metrics) IncrementActiveTokens() {
	atomic.AddInt64(&m.activeTokens, 1)
}

// DecrementActiveTokens decrements the active tokens gauge
func (m *Metrics) DecrementActiveTokens() {
	atomic.AddInt64(&m.activeTokens, -1)
}

// Export returns metrics in Prometheus exposition format
func (m *Metrics) Export() string {
	var sb strings.Builder

	// Runtime metrics
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	sb.WriteString("# HELP oryxid_uptime_seconds Server uptime in seconds\n")
	sb.WriteString("# TYPE oryxid_uptime_seconds counter\n")
	sb.WriteString(fmt.Sprintf("oryxid_uptime_seconds %.0f\n\n", time.Since(m.startTime).Seconds()))

	sb.WriteString("# HELP oryxid_memory_alloc_bytes Current memory allocation in bytes\n")
	sb.WriteString("# TYPE oryxid_memory_alloc_bytes gauge\n")
	sb.WriteString(fmt.Sprintf("oryxid_memory_alloc_bytes %d\n\n", mem.Alloc))

	sb.WriteString("# HELP oryxid_goroutines_count Number of goroutines\n")
	sb.WriteString("# TYPE oryxid_goroutines_count gauge\n")
	sb.WriteString(fmt.Sprintf("oryxid_goroutines_count %d\n\n", runtime.NumGoroutine()))

	// Token issuance counter
	sb.WriteString("# HELP oryxid_tokens_issued_total Total number of tokens issued\n")
	sb.WriteString("# TYPE oryxid_tokens_issued_total counter\n")
	m.tokenIssuance.Range(func(key, value interface{}) bool {
		parts := strings.SplitN(key.(string), ":", 2)
		if len(parts) == 2 {
			clientID := parts[0]
			grantType := parts[1]
			count := atomic.LoadUint64(value.(*uint64))
			sb.WriteString(fmt.Sprintf("oryxid_tokens_issued_total{client_id=\"%s\",grant_type=\"%s\"} %d\n",
				clientID, grantType, count))
		}
		return true
	})
	sb.WriteString("\n")

	// Token validation latency histogram
	m.validationLatency.RLock()
	sb.WriteString("# HELP oryxid_token_validation_duration_milliseconds Token validation duration in milliseconds\n")
	sb.WriteString("# TYPE oryxid_token_validation_duration_milliseconds histogram\n")

	buckets := []float64{5, 10, 25, 50, 100, 250, 500, 1000}
	for _, bucket := range buckets {
		count := m.validationLatency.buckets[bucket]
		sb.WriteString(fmt.Sprintf("oryxid_token_validation_duration_milliseconds_bucket{le=\"%.0f\"} %d\n", bucket, count))
	}
	sb.WriteString(fmt.Sprintf("oryxid_token_validation_duration_milliseconds_bucket{le=\"+Inf\"} %d\n", m.validationLatency.count))
	sb.WriteString(fmt.Sprintf("oryxid_token_validation_duration_milliseconds_sum %.2f\n", m.validationLatency.sum))
	sb.WriteString(fmt.Sprintf("oryxid_token_validation_duration_milliseconds_count %d\n\n", m.validationLatency.count))
	m.validationLatency.RUnlock()

	// Failed authentication counter
	sb.WriteString("# HELP oryxid_auth_failures_total Total number of authentication failures\n")
	sb.WriteString("# TYPE oryxid_auth_failures_total counter\n")
	m.failedAuth.Range(func(key, value interface{}) bool {
		reason := key.(string)
		count := atomic.LoadUint64(value.(*uint64))
		sb.WriteString(fmt.Sprintf("oryxid_auth_failures_total{reason=\"%s\"} %d\n", reason, count))
		return true
	})
	sb.WriteString("\n")

	// Rate limit violations counter
	sb.WriteString("# HELP oryxid_rate_limit_violations_total Total number of rate limit violations\n")
	sb.WriteString("# TYPE oryxid_rate_limit_violations_total counter\n")
	m.rateLimitViolations.Range(func(key, value interface{}) bool {
		clientID := key.(string)
		count := atomic.LoadUint64(value.(*uint64))
		sb.WriteString(fmt.Sprintf("oryxid_rate_limit_violations_total{client_id=\"%s\"} %d\n", clientID, count))
		return true
	})
	sb.WriteString("\n")

	// Active tokens gauge
	sb.WriteString("# HELP oryxid_active_tokens Current number of active (non-revoked, non-expired) tokens\n")
	sb.WriteString("# TYPE oryxid_active_tokens gauge\n")
	sb.WriteString(fmt.Sprintf("oryxid_active_tokens %d\n", atomic.LoadInt64(&m.activeTokens)))

	return sb.String()
}
