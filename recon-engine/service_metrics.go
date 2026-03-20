package main

import (
	"context"
	"runtime"
	"time"
)

func publishServiceMetric(ctx context.Context, sessionID, service, phase, impact string, extra map[string]interface{}) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	data := map[string]interface{}{
		"session_id":    sessionID,
		"service":       service,
		"phase":         phase,
		"impact":        impact,
		"goroutines":    runtime.NumGoroutine(),
		"heap_alloc_mb": float64(mem.Alloc) / 1024.0 / 1024.0,
		"sys_mb":        float64(mem.Sys) / 1024.0 / 1024.0,
		"timestamp":     time.Now().Format(time.RFC3339Nano),
		"type":          "service-metric",
	}
	for key, value := range extra {
		data[key] = value
	}

	_, _ = redisClient.Publish(ctx, "service-metrics", data)
}
