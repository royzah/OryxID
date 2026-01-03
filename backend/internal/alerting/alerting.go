package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/tiiuae/oryxid/internal/logger"
)

// Severity levels for alerts
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Alert represents an alert event
type Alert struct {
	Name        string            `json:"name"`
	Severity    Severity          `json:"severity"`
	Message     string            `json:"message"`
	Source      string            `json:"source"`
	Timestamp   time.Time         `json:"timestamp"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// WebhookPayload is the payload sent to webhook endpoints
type WebhookPayload struct {
	Version string  `json:"version"`
	Alerts  []Alert `json:"alerts"`
}

// Config holds alerting configuration
type Config struct {
	Enabled     bool          `json:"enabled"`
	WebhookURL  string        `json:"webhook_url"`
	Timeout     time.Duration `json:"timeout"`
	MaxRetries  int           `json:"max_retries"`
	RateLimitMS int           `json:"rate_limit_ms"`
}

// Manager handles alert dispatching
type Manager struct {
	config     Config
	client     *http.Client
	mu         sync.Mutex
	lastAlert  map[string]time.Time
	alertQueue chan Alert
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

var (
	instance *Manager
	once     sync.Once
)

// Initialize creates the global alerting manager
func Initialize(cfg Config) *Manager {
	once.Do(func() {
		instance = NewManager(cfg)
	})
	return instance
}

// Get returns the global alerting manager
func Get() *Manager {
	return instance
}

// NewManager creates a new alert manager
func NewManager(cfg Config) *Manager {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RateLimitMS == 0 {
		cfg.RateLimitMS = 1000 // 1 second default
	}

	m := &Manager{
		config: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		lastAlert:  make(map[string]time.Time),
		alertQueue: make(chan Alert, 100),
		stopCh:     make(chan struct{}),
	}

	if cfg.Enabled && cfg.WebhookURL != "" {
		m.wg.Add(1)
		go m.processAlerts()
	}

	return m
}

// Close shuts down the alert manager
func (m *Manager) Close() {
	close(m.stopCh)
	m.wg.Wait()
}

// Send queues an alert for dispatch
func (m *Manager) Send(alert Alert) {
	if m == nil || !m.config.Enabled {
		return
	}

	// Apply rate limiting
	m.mu.Lock()
	key := fmt.Sprintf("%s:%s", alert.Name, alert.Severity)
	lastTime, exists := m.lastAlert[key]
	now := time.Now()

	if exists && now.Sub(lastTime) < time.Duration(m.config.RateLimitMS)*time.Millisecond {
		m.mu.Unlock()
		return // Rate limited
	}

	m.lastAlert[key] = now
	m.mu.Unlock()

	// Set timestamp if not set
	if alert.Timestamp.IsZero() {
		alert.Timestamp = now
	}

	// Set source if not set
	if alert.Source == "" {
		alert.Source = "oryxid"
	}

	// Queue alert
	select {
	case m.alertQueue <- alert:
	default:
		logger.Warn("alert queue full, dropping alert", "name", alert.Name)
	}
}

// processAlerts processes queued alerts
func (m *Manager) processAlerts() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopCh:
			return
		case alert := <-m.alertQueue:
			if err := m.dispatch(alert); err != nil {
				logger.Error("failed to dispatch alert", "error", err, "name", alert.Name)
			}
		}
	}
}

// dispatch sends an alert to the webhook endpoint
func (m *Manager) dispatch(alert Alert) error {
	payload := WebhookPayload{
		Version: "1.0",
		Alerts:  []Alert{alert},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	var lastErr error
	for i := 0; i < m.config.MaxRetries; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.config.WebhookURL, bytes.NewReader(data))
		if err != nil {
			cancel()
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "OryxID-Alerting/1.0")

		resp, err := m.client.Do(req)
		cancel()

		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(i+1) * 500 * time.Millisecond) // Exponential backoff
			continue
		}

		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			logger.Debug("alert dispatched", "name", alert.Name, "severity", alert.Severity)
			return nil
		}

		lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
		time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
	}

	return fmt.Errorf("failed after %d retries: %w", m.config.MaxRetries, lastErr)
}

// Helper functions for common alerts

// AlertHighAuthFailures sends an alert for high authentication failure rate
func (m *Manager) AlertHighAuthFailures(count int, threshold int, clientID string) {
	m.Send(Alert{
		Name:     "high_auth_failures",
		Severity: SeverityWarning,
		Message:  fmt.Sprintf("High authentication failure rate: %d failures (threshold: %d)", count, threshold),
		Labels: map[string]string{
			"client_id": clientID,
		},
		Annotations: map[string]string{
			"description": "Authentication failures exceeded threshold",
			"runbook":     "Check client credentials and review audit logs",
		},
	})
}

// AlertRateLimitViolation sends an alert for rate limit violations
func (m *Manager) AlertRateLimitViolation(clientID string, count int) {
	m.Send(Alert{
		Name:     "rate_limit_violation",
		Severity: SeverityInfo,
		Message:  fmt.Sprintf("Client %s exceeded rate limit (%d violations)", clientID, count),
		Labels: map[string]string{
			"client_id": clientID,
		},
	})
}

// AlertDatabaseDown sends an alert when database is unreachable
func (m *Manager) AlertDatabaseDown(err error) {
	m.Send(Alert{
		Name:     "database_down",
		Severity: SeverityCritical,
		Message:  "Database connection failed",
		Labels: map[string]string{
			"component": "database",
		},
		Annotations: map[string]string{
			"error": err.Error(),
		},
	})
}

// AlertRedisDown sends an alert when Redis is unreachable
func (m *Manager) AlertRedisDown(err error) {
	m.Send(Alert{
		Name:     "redis_down",
		Severity: SeverityWarning,
		Message:  "Redis connection failed",
		Labels: map[string]string{
			"component": "redis",
		},
		Annotations: map[string]string{
			"error": err.Error(),
		},
	})
}

// AlertTokenRevocationSpike sends an alert for unusual token revocation activity
func (m *Manager) AlertTokenRevocationSpike(count int, period time.Duration) {
	m.Send(Alert{
		Name:     "token_revocation_spike",
		Severity: SeverityWarning,
		Message:  fmt.Sprintf("Unusual token revocation activity: %d revocations in %s", count, period),
		Annotations: map[string]string{
			"description": "May indicate compromised credentials or attack",
		},
	})
}

// AlertServiceStarted sends an informational alert when service starts
func (m *Manager) AlertServiceStarted(version string) {
	m.Send(Alert{
		Name:     "service_started",
		Severity: SeverityInfo,
		Message:  "OryxID service started",
		Labels: map[string]string{
			"version": version,
		},
	})
}

// AlertSecurityEvent sends an alert for security-related events
func (m *Manager) AlertSecurityEvent(event string, details map[string]string) {
	m.Send(Alert{
		Name:     "security_event",
		Severity: SeverityWarning,
		Message:  event,
		Labels:   details,
	})
}
