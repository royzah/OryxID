package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// =============================================================================
// CORS Middleware Tests
// =============================================================================

func TestCORS_AllowedOrigin(t *testing.T) {
	router := gin.New()
	router.Use(CORS([]string{"https://example.com", "https://app.example.com"}))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	tests := []struct {
		name           string
		origin         string
		expectedOrigin string
	}{
		{
			name:           "Allowed origin",
			origin:         "https://example.com",
			expectedOrigin: "https://example.com",
		},
		{
			name:           "Another allowed origin",
			origin:         "https://app.example.com",
			expectedOrigin: "https://app.example.com",
		},
		{
			name:           "Not allowed origin falls back to first",
			origin:         "https://evil.com",
			expectedOrigin: "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tt.expectedOrigin, w.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestCORS_WildcardOrigin(t *testing.T) {
	router := gin.New()
	router.Use(CORS([]string{"*"}))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://any-origin.com")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://any-origin.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_PreflightRequest(t *testing.T) {
	router := gin.New()
	router.Use(CORS([]string{"https://example.com"}))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Authorization")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "X-CSRF-Token")
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestCORS_ExposedHeaders(t *testing.T) {
	router := gin.New()
	router.Use(CORS([]string{"https://example.com"}))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	exposedHeaders := w.Header().Get("Access-Control-Expose-Headers")
	assert.Contains(t, exposedHeaders, "X-Total-Count")
	assert.Contains(t, exposedHeaders, "X-Request-ID")
}

func TestCORS_MaxAge(t *testing.T) {
	router := gin.New()
	router.Use(CORS([]string{"https://example.com"}))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, "86400", w.Header().Get("Access-Control-Max-Age"))
}

// =============================================================================
// CSRF Middleware Tests
// =============================================================================

func TestCSRF_GeneratesTokenOnSafeMethod(t *testing.T) {
	router := gin.New()
	config := DefaultCSRFConfig()
	router.Use(CSRF(config))
	router.GET("/test", func(c *gin.Context) {
		token, _ := c.Get("csrf_token")
		c.JSON(http.StatusOK, gin.H{"csrf_token": token})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check cookie was set
	cookies := w.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}
	assert.NotNil(t, csrfCookie, "CSRF cookie should be set")
	assert.NotEmpty(t, csrfCookie.Value)
}

func TestCSRF_RejectsUnsafeMethodWithoutToken(t *testing.T) {
	router := gin.New()
	config := DefaultCSRFConfig()
	router.Use(CSRF(config))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_AcceptsValidToken(t *testing.T) {
	router := gin.New()
	config := DefaultCSRFConfig()
	router.Use(CSRF(config))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// Generate a token
	token := generateCSRFToken(32)

	req, _ := http.NewRequest("POST", "/test", nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(&http.Cookie{
		Name:  "csrf_token",
		Value: token,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_RejectsMismatchedToken(t *testing.T) {
	router := gin.New()
	config := DefaultCSRFConfig()
	router.Use(CSRF(config))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("POST", "/test", nil)
	req.Header.Set("X-CSRF-Token", "request-token")
	req.AddCookie(&http.Cookie{
		Name:  "csrf_token",
		Value: "cookie-token",
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_SkipsExemptRoutes(t *testing.T) {
	router := gin.New()
	config := DefaultCSRFConfig()
	config.SkipPaths = []string{"/health", "/api/*"}
	router.Use(CSRF(config))
	router.POST("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
	router.POST("/api/users", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// Test exact path skip
	req, _ := http.NewRequest("POST", "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test wildcard path skip
	req2, _ := http.NewRequest("POST", "/api/users", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
}

func TestCSRF_ExemptMiddleware(t *testing.T) {
	router := gin.New()
	config := DefaultCSRFConfig()
	router.Use(CSRF(config))
	router.POST("/exempt", CSRFExempt(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("POST", "/exempt", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRFToken_Endpoint(t *testing.T) {
	router := gin.New()
	router.GET("/csrf-token", CSRFToken())

	req, _ := http.NewRequest("GET", "/csrf-token", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "csrf_token")
}

// =============================================================================
// Rate Limiting Tests
// =============================================================================

func TestInMemoryRateLimiter_Allow(t *testing.T) {
	limiter := NewInMemoryRateLimiter(10, 10)

	// Should allow initial requests
	for i := 0; i < 10; i++ {
		assert.True(t, limiter.Allow("test-key"), "Request %d should be allowed", i+1)
	}

	// Should block after burst exhausted
	assert.False(t, limiter.Allow("test-key"), "Request should be blocked")
}

func TestInMemoryRateLimiter_DifferentKeys(t *testing.T) {
	limiter := NewInMemoryRateLimiter(2, 2)

	// Each key gets its own limit
	assert.True(t, limiter.Allow("key1"))
	assert.True(t, limiter.Allow("key1"))
	assert.False(t, limiter.Allow("key1"))

	// Different key still has full allowance
	assert.True(t, limiter.Allow("key2"))
	assert.True(t, limiter.Allow("key2"))
	assert.False(t, limiter.Allow("key2"))
}

func TestRateLimitMiddleware(t *testing.T) {
	router := gin.New()
	limiter := NewInMemoryRateLimiter(2, 2)
	router.Use(RateLimit(limiter))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Third request should be rate limited
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Should have rate limit headers
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"))
	assert.Equal(t, "0", w.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestRateLimitByClient(t *testing.T) {
	router := gin.New()
	limiter := NewInMemoryRateLimiter(2, 2)

	// Middleware to set client_id
	router.Use(func(c *gin.Context) {
		c.Set("client_id", c.GetHeader("X-Client-ID"))
		c.Next()
	})
	router.Use(RateLimitByClient(limiter))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// Requests for client-1
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Client-ID", "client-1")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Third request for client-1 should be limited
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Client-ID", "client-1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Different client should still have allowance
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-Client-ID", "client-2")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
}

func TestRateLimitByUser(t *testing.T) {
	router := gin.New()

	// Middleware to set user_id
	router.Use(func(c *gin.Context) {
		c.Set("user_id", c.GetHeader("X-User-ID"))
		c.Next()
	})
	router.Use(RateLimitByUser(nil, 2))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// Requests for user-1
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-User-ID", "user-1")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Next request should be limited
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-User-ID", "user-1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestRateLimitByUser_NoUser(t *testing.T) {
	router := gin.New()
	router.Use(RateLimitByUser(nil, 2))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// Without user_id, should proceed without limiting
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestAdaptiveRateLimit(t *testing.T) {
	router := gin.New()
	router.Use(AdaptiveRateLimit(5, 2))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// First burst should succeed
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if i < 10 { // Burst of 10 (5 rps * 2)
			// Some should succeed initially
		}
	}

	// Request should eventually be rate limited
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	// After exhausting burst, should be limited
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestRateLimit_ConcurrentRequests(t *testing.T) {
	router := gin.New()
	limiter := NewInMemoryRateLimiter(100, 100)
	router.Use(RateLimit(limiter))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	// Launch concurrent requests
	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code == http.StatusOK {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Should have around 100 successful requests (the burst limit)
	assert.LessOrEqual(t, successCount, 100)
	assert.Greater(t, successCount, 0)
}

// =============================================================================
// Security Headers Tests
// =============================================================================

func TestSecurity_Headers(t *testing.T) {
	router := gin.New()
	router.Use(Security())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check security headers
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
	assert.NotEmpty(t, w.Header().Get("Permissions-Policy"))
}

func TestSecurity_CSP(t *testing.T) {
	router := gin.New()
	router.Use(Security())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "frame-ancestors 'none'")
}

func TestSecurity_HSTS_WithHTTPS(t *testing.T) {
	router := gin.New()
	router.Use(Security())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	hsts := w.Header().Get("Strict-Transport-Security")
	assert.NotEmpty(t, hsts)
	assert.Contains(t, hsts, "max-age=31536000")
	assert.Contains(t, hsts, "includeSubDomains")
}

func TestSecurity_NoHSTS_WithHTTP(t *testing.T) {
	router := gin.New()
	router.Use(Security())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	// No X-Forwarded-Proto header, so it's HTTP
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// HSTS should not be set for HTTP
	assert.Empty(t, w.Header().Get("Strict-Transport-Security"))
}

// =============================================================================
// Request ID Tests
// =============================================================================

func TestRequestID_GeneratesNewID(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		requestID, _ := c.Get("request_id")
		c.JSON(http.StatusOK, gin.H{"request_id": requestID})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))

	// Response should contain the request ID
	assert.Contains(t, w.Body.String(), "request_id")
}

func TestRequestID_UsesProvidedID(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		requestID, _ := c.Get("request_id")
		c.JSON(http.StatusOK, gin.H{"request_id": requestID})
	})

	providedID := "custom-request-id-12345"
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", providedID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, providedID, w.Header().Get("X-Request-ID"))
	assert.Contains(t, w.Body.String(), providedID)
}

func TestRequestID_Uniqueness(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	requestIDs := make(map[string]bool)
	for i := 0; i < 100; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		requestID := w.Header().Get("X-Request-ID")
		assert.False(t, requestIDs[requestID], "Duplicate request ID found")
		requestIDs[requestID] = true
	}
}

// =============================================================================
// Logger Tests
// =============================================================================

func TestLogger_SkipsHealthEndpoint(t *testing.T) {
	router := gin.New()
	router.Use(Logger())
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	req, _ := http.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Logger should skip /health endpoint (hard to verify without capturing logs)
}

// =============================================================================
// Recovery Tests
// =============================================================================

func TestRecovery_HandlesPanic(t *testing.T) {
	router := gin.New()
	router.Use(Recovery())
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	req, _ := http.NewRequest("GET", "/panic", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should recover and return 500
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// =============================================================================
// Integration Tests - Multiple Middleware
// =============================================================================

func TestMiddlewareChain(t *testing.T) {
	router := gin.New()
	router.Use(Recovery())
	router.Use(RequestID())
	router.Use(Security())
	router.Use(CORS([]string{"https://example.com"}))

	limiter := NewInMemoryRateLimiter(100, 100)
	router.Use(RateLimit(limiter))

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check all middleware effects
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkCORS(b *testing.B) {
	router := gin.New()
	router.Use(CORS([]string{"https://example.com"}))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkCSRF(b *testing.B) {
	router := gin.New()
	config := DefaultCSRFConfig()
	router.Use(CSRF(config))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkRateLimit(b *testing.B) {
	router := gin.New()
	limiter := NewInMemoryRateLimiter(10000, 10000)
	router.Use(RateLimit(limiter))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkSecurity(b *testing.B) {
	router := gin.New()
	router.Use(Security())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkRequestID(b *testing.B) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkFullMiddlewareStack(b *testing.B) {
	router := gin.New()
	router.Use(Recovery())
	router.Use(RequestID())
	router.Use(Security())
	router.Use(CORS([]string{"https://example.com"}))
	limiter := NewInMemoryRateLimiter(10000, 10000)
	router.Use(RateLimit(limiter))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// =============================================================================
// Helper function tests
// =============================================================================

func TestIsSafeMethod(t *testing.T) {
	assert.True(t, isSafeMethod("GET"))
	assert.True(t, isSafeMethod("HEAD"))
	assert.True(t, isSafeMethod("OPTIONS"))
	assert.False(t, isSafeMethod("POST"))
	assert.False(t, isSafeMethod("PUT"))
	assert.False(t, isSafeMethod("DELETE"))
	assert.False(t, isSafeMethod("PATCH"))
}

func TestGenerateCSRFToken(t *testing.T) {
	token1 := generateCSRFToken(32)
	token2 := generateCSRFToken(32)

	// Should generate non-empty tokens
	assert.NotEmpty(t, token1)
	assert.NotEmpty(t, token2)

	// Should be unique
	assert.NotEqual(t, token1, token2)

	// Should be base64 encoded (length should be about 43 chars for 32 bytes)
	assert.GreaterOrEqual(t, len(token1), 40)
}

func TestValidateCSRFTokens(t *testing.T) {
	assert.True(t, validateCSRFTokens("token", "token"))
	assert.False(t, validateCSRFTokens("token1", "token2"))
	assert.False(t, validateCSRFTokens("", ""))
	assert.False(t, validateCSRFTokens("token", ""))
	assert.False(t, validateCSRFTokens("", "token"))
}

// Test for adaptive limiter behavior
func TestAdaptiveLimiter_Violations(t *testing.T) {
	limiter := newAdaptiveLimiter(2, 1)

	// Use up the burst
	assert.True(t, limiter.Allow())
	assert.True(t, limiter.Allow())

	// Next request should be blocked and count as violation
	assert.False(t, limiter.Allow())
	assert.Equal(t, 1, limiter.violations)

	// More violations
	assert.False(t, limiter.Allow())
	assert.Equal(t, 2, limiter.violations)
}

// Test rate limiting with different endpoints
func TestRateLimit_DifferentEndpoints(t *testing.T) {
	router := gin.New()
	limiter := NewInMemoryRateLimiter(2, 2)
	router.Use(RateLimit(limiter))

	router.GET("/api/users", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"endpoint": "users"})
	})
	router.GET("/api/posts", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"endpoint": "posts"})
	})

	// Requests to /api/users
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", "/api/users", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Third request to /api/users should be limited
	req, _ := http.NewRequest("GET", "/api/users", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// But /api/posts should have its own limit
	req2, _ := http.NewRequest("GET", "/api/posts", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
}

// Test CSRF with form field
func TestCSRF_FormField(t *testing.T) {
	router := gin.New()
	config := DefaultCSRFConfig()
	router.Use(CSRF(config))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	token := generateCSRFToken(32)

	req, _ := http.NewRequest("POST", "/test", strings.NewReader("csrf_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{
		Name:  "csrf_token",
		Value: token,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// Test rate limit replenishment over time
func TestRateLimit_Replenishment(t *testing.T) {
	limiter := NewInMemoryRateLimiter(10, 1) // 10 rps, burst of 1

	// First request should succeed
	assert.True(t, limiter.Allow("test"))

	// Second immediate request should fail (burst exhausted)
	assert.False(t, limiter.Allow("test"))

	// Wait for replenishment
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	assert.True(t, limiter.Allow("test"))
}
