package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/tiiuae/oryxid/internal/metrics"
)

// MetricsHandler returns application metrics in Prometheus format
func MetricsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		m := metrics.Get()
		c.Header("Content-Type", "text/plain; version=0.0.4")
		c.String(200, m.Export())
	}
}
