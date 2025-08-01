package handlers

import (
	"fmt"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	startTime = time.Now()
)

// MetricsHandler returns application metrics in Prometheus format
func MetricsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		metrics := fmt.Sprintf(`# HELP oryxid_uptime_seconds Server uptime in seconds
# TYPE oryxid_uptime_seconds counter
oryxid_uptime_seconds %.0f

# HELP oryxid_memory_alloc_bytes Current memory allocation in bytes
# TYPE oryxid_memory_alloc_bytes gauge
oryxid_memory_alloc_bytes %d

# HELP oryxid_memory_total_alloc_bytes Total memory allocated in bytes
# TYPE oryxid_memory_total_alloc_bytes counter
oryxid_memory_total_alloc_bytes %d

# HELP oryxid_memory_sys_bytes System memory in bytes
# TYPE oryxid_memory_sys_bytes gauge
oryxid_memory_sys_bytes %d

# HELP oryxid_goroutines_count Number of goroutines
# TYPE oryxid_goroutines_count gauge
oryxid_goroutines_count %d

# HELP oryxid_gc_runs_total Total number of GC runs
# TYPE oryxid_gc_runs_total counter
oryxid_gc_runs_total %d

# HELP oryxid_gc_pause_seconds_total Total GC pause time in seconds
# TYPE oryxid_gc_pause_seconds_total counter
oryxid_gc_pause_seconds_total %f
`,
			time.Since(startTime).Seconds(),
			m.Alloc,
			m.TotalAlloc,
			m.Sys,
			runtime.NumGoroutine(),
			m.NumGC,
			float64(m.PauseTotalNs)/1e9,
		)

		c.Header("Content-Type", "text/plain; version=0.0.4")
		c.String(200, metrics)
	}
}
