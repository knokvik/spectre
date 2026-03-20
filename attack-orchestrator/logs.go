package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type LogSignals struct {
	TotalEntries     int      `json:"total_entries"`
	ErrorEvents      int      `json:"error_events"`
	ErrorRate        float64  `json:"error_rate"`
	AuthFailures     int      `json:"auth_failures"`
	DBErrors         int      `json:"db_errors"`
	UnusualRequests  int      `json:"unusual_requests"`
	RequestSpikes    int      `json:"request_spikes"`
	StackTraces      int      `json:"stack_traces"`
	AnomalyCount     int      `json:"anomaly_count"`
	CollectedSources []string `json:"collected_sources"`
}

type NormalizedLogEvent struct {
	SessionID string `json:"session_id"`
	Timestamp string `json:"timestamp"`
	Service   string `json:"service"`
	Address   string `json:"address"`
	URLPath   string `json:"url_path"`
	LogType   string `json:"log_type"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Source    string `json:"source"`
	Anomaly   bool   `json:"anomaly"`
	Type      string `json:"type"`
}

func collectApprovedLogs(ctx context.Context, sessionID, targetURL string, collector *ReconCollector) LogSignals {
	signals := LogSignals{CollectedSources: []string{}}
	if !collector.AllowLogs || len(collector.SelectedLogSources) == 0 {
		return signals
	}
	if !isLocalOrPrivateTarget(targetURL, collector.ServiceInventory) {
		publishAttackEvent(ctx, sessionID, "warning", "Log collection skipped because the selected target is not local/private.")
		return signals
	}

	for _, source := range collector.SelectedLogSources {
		lines, serviceLabel, address := collectLogSource(ctx, source, collector)
		if len(lines) == 0 {
			continue
		}
		signals.CollectedSources = append(signals.CollectedSources, source)
		for _, line := range lines {
			event := normalizeLogLine(sessionID, source, serviceLabel, address, line)
			signals.TotalEntries++
			switch event.LogType {
			case "db_error":
				signals.DBErrors++
				signals.ErrorEvents++
			case "auth_failure":
				signals.AuthFailures++
				signals.ErrorEvents++
			case "stack_trace":
				signals.StackTraces++
				signals.ErrorEvents++
			case "app_error":
				signals.ErrorEvents++
			case "unusual_request":
				signals.UnusualRequests++
			}
			if event.Anomaly {
				signals.AnomalyCount++
			}
			publishSecurityLog(ctx, event)
		}
	}

	if signals.TotalEntries > 0 {
		signals.ErrorRate = round2(float64(signals.ErrorEvents) / float64(signals.TotalEntries))
	}
	if signals.UnusualRequests >= 5 {
		signals.RequestSpikes = signals.UnusualRequests / 5
	}
	publishLogSummary(ctx, sessionID, signals)
	return signals
}

func collectLogSource(ctx context.Context, source string, collector *ReconCollector) ([]string, string, string) {
	switch source {
	case "system":
		return collectSystemLogs(ctx), "system", "local"
	case "application":
		address := firstApprovedServiceOfType(collector, "backend", "frontend", "internal-service", "ops")
		return collectFileLogs(envPaths("SPECTRE_APP_LOG_PATHS", []string{
			"./logs/app.log",
			"./logs/backend.log",
			"./logs/server.log",
			"/tmp/app.log",
		})), "application", address
	case "database":
		address := firstApprovedServiceOfType(collector, "database")
		return collectFileLogs(envPaths("SPECTRE_DB_LOG_PATHS", []string{
			"/var/log/postgresql/postgresql.log",
			"/var/log/postgresql/postgresql-15-main.log",
			"/var/log/mongodb/mongod.log",
			"/var/log/redis/redis-server.log",
		})), "database", address
	default:
		return nil, "", ""
	}
}

func collectSystemLogs(ctx context.Context) []string {
	if _, err := exec.LookPath("journalctl"); err == nil {
		cmd := exec.CommandContext(ctx, "journalctl", "-n", "40", "--no-pager", "-o", "short-iso")
		if out, err := cmd.Output(); err == nil {
			return splitLines(string(out), 40)
		}
	}
	return collectFileLogs(envPaths("SPECTRE_SYSTEM_LOG_PATHS", []string{"/var/log/system.log", "/var/log/syslog"}))
}

func collectFileLogs(paths []string) []string {
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		expanded := path
		if strings.HasPrefix(path, "./") {
			expanded = filepath.Clean(path)
		}
		file, err := os.Open(expanded)
		if err != nil {
			continue
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		lines := make([]string, 0, 64)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
			if len(lines) > 120 {
				lines = lines[len(lines)-120:]
			}
		}
		if len(lines) == 0 {
			continue
		}
		return lines
	}
	return nil
}

func normalizeLogLine(sessionID, source, serviceLabel, address, line string) NormalizedLogEvent {
	lower := strings.ToLower(strings.TrimSpace(line))
	event := NormalizedLogEvent{
		SessionID: sessionID,
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Service:   serviceLabel,
		Address:   address,
		URLPath:   extractURLPath(lower),
		LogType:   "info",
		Severity:  "info",
		Message:   strings.TrimSpace(line),
		Source:    source,
		Anomaly:   false,
		Type:      "security-log",
	}

	switch {
	case strings.Contains(lower, "sql") && (strings.Contains(lower, "error") || strings.Contains(lower, "syntax")):
		event.LogType = "db_error"
		event.Severity = "warning"
		event.Anomaly = true
	case strings.Contains(lower, "auth fail") || strings.Contains(lower, "authentication failed") || strings.Contains(lower, "invalid token") || strings.Contains(lower, "unauthorized"):
		event.LogType = "auth_failure"
		event.Severity = "warning"
		event.Anomaly = true
	case strings.Contains(lower, "traceback") || strings.Contains(lower, "exception") || strings.Contains(lower, "panic:") || strings.Contains(lower, "stack trace"):
		event.LogType = "stack_trace"
		event.Severity = "warning"
		event.Anomaly = true
	case strings.Contains(lower, "500") || strings.Contains(lower, "internal server error"):
		event.LogType = "app_error"
		event.Severity = "warning"
	case strings.Contains(lower, "../") || strings.Contains(lower, "union select") || strings.Contains(lower, "or 1=1") || strings.Contains(lower, "sleep(") || strings.Contains(lower, "/graphql") || strings.Contains(lower, "wp-login"):
		event.LogType = "unusual_request"
		event.Severity = "warning"
		event.Anomaly = true
	}

	return event
}

func publishSecurityLog(ctx context.Context, event NormalizedLogEvent) {
	payload, _ := json.Marshal(map[string]interface{}{
		"@timestamp":      event.Timestamp,
		"service.name":    event.Service,
		"service.address": event.Address,
		"log.level":       event.Severity,
		"message":         event.Message,
		"url.path":        event.URLPath,
		"event.dataset":   event.Source,
		"event.kind":      event.LogType,
		"anomaly":         event.Anomaly,
	})
	_, _ = redisClient.Publish(ctx, "security-logs", map[string]interface{}{
		"session_id":      event.SessionID,
		"@timestamp":      event.Timestamp,
		"service.name":    event.Service,
		"service.address": event.Address,
		"log.level":       event.Severity,
		"message":         event.Message,
		"url.path":        event.URLPath,
		"event.dataset":   event.Source,
		"event.kind":      event.LogType,
		"anomaly":         event.Anomaly,
		"type":            "security-log",
		"payload":         string(payload),
		"source":          event.Source,
	})
}

func publishLogSummary(ctx context.Context, sessionID string, signals LogSignals) {
	_, _ = redisClient.Publish(ctx, "security-logs", map[string]interface{}{
		"session_id":        sessionID,
		"timestamp":         time.Now().Format(time.RFC3339Nano),
		"type":              "log-summary",
		"message":           fmt.Sprintf("Log analysis summary: %d entries, %d anomaly signal(s), %d auth failure(s), %d DB error(s).", signals.TotalEntries, signals.AnomalyCount, signals.AuthFailures, signals.DBErrors),
		"error_rate":        signals.ErrorRate,
		"auth_failures":     signals.AuthFailures,
		"db_errors":         signals.DBErrors,
		"unusual_requests":  signals.UnusualRequests,
		"request_spikes":    signals.RequestSpikes,
		"stack_traces":      signals.StackTraces,
		"anomaly_count":     signals.AnomalyCount,
		"collected_sources": signals.CollectedSources,
	})
}

func extractURLPath(lower string) string {
	for _, token := range strings.Fields(lower) {
		if strings.HasPrefix(token, "/") {
			return token
		}
		if idx := strings.Index(token, "/api/"); idx != -1 {
			return token[idx:]
		}
	}
	return ""
}

func envPaths(key string, defaults []string) []string {
	if raw := os.Getenv(key); raw != "" {
		parts := strings.Split(raw, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return defaults
}

func splitLines(raw string, max int) []string {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) > max {
		return lines[len(lines)-max:]
	}
	return lines
}

func round2(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}

func countServicesByType(services []DiscoveredService, kind string) int {
	total := 0
	for _, service := range services {
		if service.Type == kind {
			total++
		}
	}
	return total
}

func countExternalServices(services []DiscoveredService) int {
	total := 0
	for _, service := range services {
		if !service.Internal {
			total++
		}
	}
	return total
}

func firstApprovedServiceOfType(collector *ReconCollector, kinds ...string) string {
	for _, service := range collector.ServiceInventory {
		if len(collector.ApprovedServices) > 0 && !collector.ApprovedServices[service.Address] {
			continue
		}
		for _, kind := range kinds {
			if service.Type == kind {
				return service.Address
			}
		}
	}
	return "local"
}

func isLocalOrPrivateTarget(targetURL string, services []DiscoveredService) bool {
	if strings.Contains(targetURL, "localhost") || strings.Contains(targetURL, "127.0.0.1") {
		return true
	}
	for _, service := range services {
		if service.Internal {
			return true
		}
	}
	return false
}
