package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type ReconOptions struct {
	ObserveTraffic    bool
	AllowLogIngestion bool
	LogPaths          []string
}

type BehaviorObservationResult struct {
	RequestCount int
	Services     map[string]string
	Endpoints    []BackendEndpoint
}

var (
	scriptSrcRe        = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	formActionRe       = regexp.MustCompile(`(?i)<form[^>]+action=["']([^"']+)["']`)
	absoluteURLRe      = regexp.MustCompile(`https?://[^\s"'<>\\]+`)
	relativeEndpointRe = regexp.MustCompile(`(?i)(/((api|auth|graphql|v1|v2)[a-z0-9_/\-?=&.%]*))`)
)

func observeBehavior(ctx context.Context, sessionID, targetURL string, options ReconOptions) BehaviorObservationResult {
	result := BehaviorObservationResult{
		Services:  make(map[string]string),
		Endpoints: []BackendEndpoint{},
	}
	if !options.ObserveTraffic {
		publishEvent(ctx, sessionID, "warning", "behavior-discovery", "Traffic observation was not approved; behavior discovery skipped.", nil)
		return result
	}

	publishEvent(ctx, sessionID, "recon", "behavior-discovery", "Observing application behavior from the provided target only...", nil)

	client := newHTTPClient()
	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		publishEvent(ctx, sessionID, "error", "behavior-discovery", fmt.Sprintf("Failed to parse target for behavior observation: %v", err), nil)
		return result
	}

	frontendAddress := normalizedAddress(parsedTarget)
	result.Services[frontendAddress] = "frontend"
	recordRequest := func(requestURL string) {
		result.RequestCount++
		u, err := url.Parse(requestURL)
		if err != nil {
			return
		}
		address := normalizedAddress(u)
		if address == "" {
			return
		}
		if sameObservedHost(parsedTarget, u) {
			if _, exists := result.Services[address]; !exists {
				result.Services[address] = "backend"
			}
			if endpoint, ok := endpointFromObservedURL(sessionID, targetURL, u.String(), "traffic"); ok {
				result.Endpoints = append(result.Endpoints, endpoint)
			}
			return
		}
		if u.Hostname() != "" {
			result.Services[address] = "external"
		}
	}

	body := fetchObservedBody(ctx, client, targetURL)
	if body != "" {
		recordRequest(targetURL)
		for _, candidate := range extractObservedURLs(body, targetURL) {
			recordRequest(candidate)
		}
		for _, scriptURL := range extractScriptURLs(body, targetURL) {
			if !sameObservedHost(parsedTarget, mustParseURL(scriptURL)) {
				recordRequest(scriptURL)
				continue
			}
			recordRequest(scriptURL)
			scriptBody := fetchObservedBody(ctx, client, scriptURL)
			for _, candidate := range extractObservedURLs(scriptBody, targetURL) {
				recordRequest(candidate)
			}
		}
	}

	if options.AllowLogIngestion && len(options.LogPaths) > 0 {
		endpoints, services := ingestObservedLogs(ctx, sessionID, targetURL, options.LogPaths)
		for _, endpoint := range endpoints {
			result.Endpoints = append(result.Endpoints, endpoint)
		}
		for address, serviceType := range services {
			if _, exists := result.Services[address]; !exists {
				result.Services[address] = serviceType
			}
		}
	}

	result.Endpoints = dedupeBehaviorEndpoints(result.Endpoints)

	publishEvent(ctx, sessionID, "recon", "behavior-discovery",
		fmt.Sprintf("Observed %d request(s), %d service(s), %d API endpoint(s)", result.RequestCount, len(result.Services), len(result.Endpoints)),
		map[string]interface{}{
			"request_count": result.RequestCount,
			"services":      result.Services,
			"endpoints":     len(result.Endpoints),
		})

	return result
}

func fetchObservedBody(ctx context.Context, client httpClientWrapper, targetURL string) string {
	resp, err := client.Get(targetURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return string(body)
}

// httpClientWrapper keeps behavior discovery decoupled from the concrete client type.
type httpClientWrapper interface {
	Get(string) (*http.Response, error)
}

func extractObservedURLs(body, baseURL string) []string {
	if body == "" {
		return nil
	}
	candidates := []string{}
	for _, match := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		candidates = append(candidates, match[1])
	}
	for _, match := range formActionRe.FindAllStringSubmatch(body, -1) {
		candidates = append(candidates, match[1])
	}
	for _, match := range absoluteURLRe.FindAllString(body, -1) {
		candidates = append(candidates, match)
	}
	for _, match := range relativeEndpointRe.FindAllStringSubmatch(body, -1) {
		candidates = append(candidates, match[1])
	}

	return resolveObservedCandidates(baseURL, candidates)
}

func extractScriptURLs(body, baseURL string) []string {
	if body == "" {
		return nil
	}
	candidates := []string{}
	for _, match := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		candidates = append(candidates, match[1])
	}
	return resolveObservedCandidates(baseURL, candidates)
}

func resolveObservedCandidates(baseURL string, candidates []string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || strings.HasPrefix(candidate, "data:") || strings.HasPrefix(candidate, "javascript:") {
			continue
		}
		resolved, err := base.Parse(candidate)
		if err != nil || resolved.Scheme == "" || resolved.Host == "" {
			continue
		}
		value := resolved.String()
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func endpointFromObservedURL(sessionID, parentTarget, rawURL, source string) (BackendEndpoint, bool) {
	resolved, err := url.Parse(rawURL)
	if err != nil || resolved.Host == "" {
		return BackendEndpoint{}, false
	}
	path := strings.ToLower(resolved.Path)
	if !strings.Contains(path, "/api") && !strings.Contains(path, "auth") && !strings.Contains(path, "graphql") && len(resolved.Query()) == 0 {
		return BackendEndpoint{}, false
	}

	scopeType := "internal"
	selectable := true
	if !sameObservedHost(mustParseURL(parentTarget), resolved) {
		scopeType = "external"
		selectable = false
	}
	apiType := "rest"
	if strings.Contains(path, "graphql") {
		apiType = "graphql"
	}
	reason := "Observed through application traffic"
	if scopeType == "external" {
		reason = "Observed external dependency via application traffic"
	}

	return BackendEndpoint{
		SessionID:          sessionID,
		Event:              "behavior_discovery",
		DiscoveredEndpoint: resolved.String(),
		Normalized:         normalizeEndpointQuery(resolved),
		Source:             source,
		Confidence:         0.9,
		APIType:            apiType,
		Type:               "backend-api",
		ParentTarget:       parentTarget,
		ScopeType:          scopeType,
		Risk:               "medium",
		Reason:             reason,
		Selectable:         selectable,
		Recommended:        selectable,
	}, true
}

func normalizeEndpointQuery(u *url.URL) string {
	clone := *u
	query := clone.Query()
	for key := range query {
		query.Set(key, "*")
	}
	clone.RawQuery = query.Encode()
	return clone.String()
}

func normalizedAddress(u *url.URL) string {
	if u == nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return fmt.Sprintf("%s:%s", u.Hostname(), port)
}

func sameObservedHost(base, candidate *url.URL) bool {
	if base == nil || candidate == nil {
		return false
	}
	return strings.EqualFold(base.Hostname(), candidate.Hostname())
}

func mustParseURL(raw string) *url.URL {
	u, _ := url.Parse(raw)
	return u
}

func dedupeBehaviorEndpoints(endpoints []BackendEndpoint) []BackendEndpoint {
	seen := make(map[string]bool)
	out := make([]BackendEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		key := endpoint.Normalized
		if key == "" {
			key = endpoint.DiscoveredEndpoint
		}
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, endpoint)
	}
	return out
}

func ingestObservedLogs(ctx context.Context, sessionID, targetURL string, logPaths []string) ([]BackendEndpoint, map[string]string) {
	endpoints := []BackendEndpoint{}
	services := map[string]string{}
	for _, path := range logPaths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			publishEvent(ctx, sessionID, "warning", "log-ingestion", fmt.Sprintf("Could not open log path %s: %v", path, err), nil)
			continue
		}
		linesRead := 0
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 1024), 1024*1024)
		for scanner.Scan() {
			linesRead++
			line := scanner.Text()
			event, endpoint, serviceAddress, serviceType := normalizeObservedLogLine(sessionID, targetURL, line)
			if event != nil {
				_, _ = redisClient.Publish(ctx, "security-logs", event)
			}
			if endpoint.DiscoveredEndpoint != "" {
				endpoints = append(endpoints, endpoint)
			}
			if serviceAddress != "" {
				services[serviceAddress] = serviceType
			}
		}
		file.Close()
		publishEvent(ctx, sessionID, "recon", "log-ingestion", fmt.Sprintf("Observed %d log line(s) from %s", linesRead, path), map[string]interface{}{"log_path": path, "line_count": linesRead})
	}
	return dedupeBehaviorEndpoints(endpoints), services
}

func normalizeObservedLogLine(sessionID, targetURL, line string) (map[string]interface{}, BackendEndpoint, string, string) {
	now := time.Now().Format(time.RFC3339Nano)
	ecs := map[string]interface{}{
		"session_id":    sessionID,
		"@timestamp":    now,
		"type":          "security-log",
		"log.level":     "info",
		"message":       strings.TrimSpace(line),
		"event.dataset": "application",
	}

	serviceAddress := ""
	serviceType := "backend"
	if parsed := parseJSONLogLine(line); len(parsed) > 0 {
		for key, value := range parsed {
			ecs[key] = value
		}
		if v, ok := parsed["service.name"].(string); ok && v != "" {
			ecs["service.name"] = v
		}
		if v, ok := parsed["service.address"].(string); ok && v != "" {
			serviceAddress = v
		}
		if v, ok := parsed["log.level"].(string); ok && v != "" {
			ecs["log.level"] = strings.ToLower(v)
		}
		if v, ok := parsed["url.path"].(string); ok && v != "" {
			rawURL := strings.TrimRight(targetURL, "/") + v
			if endpoint, ok := endpointFromObservedURL(sessionID, targetURL, rawURL, "logs"); ok {
				return ecs, endpoint, firstServiceAddress(serviceAddress, mustParseURL(rawURL)), serviceType
			}
		}
	}

	for _, candidate := range extractObservedURLs(line, targetURL) {
		if endpoint, ok := endpointFromObservedURL(sessionID, targetURL, candidate, "logs"); ok {
			return ecs, endpoint, firstServiceAddress(serviceAddress, mustParseURL(candidate)), serviceType
		}
	}

	lower := strings.ToLower(line)
	if strings.Contains(lower, "error") {
		ecs["log.level"] = "error"
	}
	return ecs, BackendEndpoint{}, serviceAddress, serviceType
}

func parseJSONLogLine(line string) map[string]interface{} {
	out := map[string]interface{}{}
	if json.Unmarshal([]byte(line), &out) == nil {
		return out
	}
	return nil
}

func firstServiceAddress(existing string, u *url.URL) string {
	if existing != "" {
		return existing
	}
	return normalizedAddress(u)
}
