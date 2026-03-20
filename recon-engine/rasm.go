package main

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

var urlPattern = regexp.MustCompile(`https?://[^\s"'<>]+|/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)

func runRASM(ctx context.Context, sessionID, targetURL string, classRes ClassificationResult) RASMResult {
	result := RASMResult{
		Triggered:           false,
		Reason:              "classification did not require RASM",
		DiscoveredEndpoints: []BackendEndpoint{},
		ReviewEndpoints:     []BackendEndpoint{},
	}

	if classRes.Class != "frontend-only" && classRes.Confidence >= 0.8 {
		return result
	}

	result.Triggered = true
	result.Reason = fmt.Sprintf("Triggered because class=%s confidence=%.2f", classRes.Class, classRes.Confidence)
	publishEvent(ctx, sessionID, "recon", "rasm", "Triggering RASM endpoint discovery", map[string]interface{}{
		"class":      classRes.Class,
		"confidence": classRes.Confidence,
	})
	publishServiceMetric(ctx, sessionID, "recon-engine", "recon", "RASM endpoint discovery running", map[string]interface{}{
		"load_pct": 74,
		"reason":   result.Reason,
	})

	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		publishEvent(ctx, sessionID, "warning", "rasm", fmt.Sprintf("Skipping RASM: invalid target URL (%v)", err), nil)
		return result
	}

	seenKey := fmt.Sprintf("seen_targets:%s", sessionID)
	collector := newRASMCollector(parsedTarget, targetURL, sessionID, seenKey)

	katanaTool, katanaErr := findTool("katana")
	if katanaErr == nil {
		stdout, stderr, err := runTool(ctx, 45*time.Second, katanaTool, "-u", targetURL, "-jc", "-js-crawl", "-d", "3", "-kf", "-filter-similar", "-rate-limit", "8")
		if err != nil {
			publishEvent(ctx, sessionID, "warning", "rasm", fmt.Sprintf("katana failed: %v", err), map[string]interface{}{"stderr": truncateText(stderr, 240)})
		}
		collector.consumeURLs("katana", stdout)
		collector.consumeURLs("katana", stderr)
		sleepBetweenTools(ctx)
	} else {
		publishEvent(ctx, sessionID, "warning", "rasm", "katana not found in runtime; RASM skipped for this source", nil)
	}

	paramSpiderTool, paramSpiderErr := findTool("ParamSpider", "paramspider")
	if paramSpiderErr == nil {
		stdout, stderr, err := runTool(ctx, 45*time.Second, paramSpiderTool, "-d", parsedTarget.Hostname())
		if err != nil {
			publishEvent(ctx, sessionID, "warning", "rasm", fmt.Sprintf("ParamSpider failed: %v", err), map[string]interface{}{"stderr": truncateText(stderr, 240)})
		}
		collector.consumeURLs("paramspider", stdout)
		collector.consumeURLs("paramspider", stderr)
		sleepBetweenTools(ctx)
	} else {
		publishEvent(ctx, sessionID, "warning", "rasm", "ParamSpider not found in runtime; RASM skipped for this source", nil)
	}

	enumAPIsTool, enumErr := findTool("enumapis")
	if enumErr == nil {
		jsTargets := collector.jsTargets()
		for _, jsURL := range jsTargets {
			stdout, stderr, err := runTool(ctx, 30*time.Second, enumAPIsTool, "-u", jsURL)
			if err != nil {
				publishEvent(ctx, sessionID, "warning", "rasm", fmt.Sprintf("enumapis failed for %s: %v", jsURL, err), map[string]interface{}{"stderr": truncateText(stderr, 240)})
				continue
			}
			collector.consumeURLs("enumapis", stdout)
			collector.consumeURLs("enumapis", stderr)
		}
		sleepBetweenTools(ctx)
	} else {
		publishEvent(ctx, sessionID, "warning", "rasm", "enumapis not found in runtime; JS API enumeration skipped", nil)
	}

	arjunTool, arjunErr := findTool("Arjun", "arjun")
	if arjunErr == nil {
		for _, endpoint := range collector.promisingTargets() {
			stdout, stderr, err := runTool(ctx, 30*time.Second, arjunTool, "-u", endpoint, "-m", "GET")
			if err != nil {
				publishEvent(ctx, sessionID, "warning", "rasm", fmt.Sprintf("Arjun failed for %s: %v", endpoint, err), map[string]interface{}{"stderr": truncateText(stderr, 240)})
				continue
			}
			collector.consumeURLs("arjun", stdout)
			collector.consumeURLs("arjun", stderr)
		}
	} else {
		publishEvent(ctx, sessionID, "warning", "rasm", "Arjun not found in runtime; parameter expansion skipped", nil)
	}

	result.DiscoveredEndpoints = collector.endpoints()
	result.ReviewEndpoints = collector.reviewEndpoints()
	publishEvent(ctx, sessionID, "recon", "rasm", fmt.Sprintf("RASM finished with %d approved API candidates and %d review items", len(result.DiscoveredEndpoints), len(result.ReviewEndpoints)), map[string]interface{}{
		"backend_endpoints": len(result.DiscoveredEndpoints),
		"review_endpoints":  len(result.ReviewEndpoints),
	})
	publishServiceMetric(ctx, sessionID, "recon-engine", "recon", "RASM endpoint discovery completed", map[string]interface{}{
		"backend_endpoints": len(result.DiscoveredEndpoints),
		"review_endpoints":  len(result.ReviewEndpoints),
		"load_pct":          42,
	})
	return result
}

type rasmCollector struct {
	target       *url.URL
	parentTarget string
	sessionID    string
	seenKey      string
	jsSeen       map[string]struct{}
	items        map[string]BackendEndpoint
	reviewItems  map[string]BackendEndpoint
}

func newRASMCollector(target *url.URL, parentTarget, sessionID, seenKey string) *rasmCollector {
	return &rasmCollector{
		target:       target,
		parentTarget: parentTarget,
		sessionID:    sessionID,
		seenKey:      seenKey,
		jsSeen:       make(map[string]struct{}),
		items:        make(map[string]BackendEndpoint),
		reviewItems:  make(map[string]BackendEndpoint),
	}
}

func (c *rasmCollector) consumeURLs(source, raw string) {
	for _, token := range extractCandidateURLs(raw) {
		c.addCandidate(source, token)
	}
}

func (c *rasmCollector) addCandidate(source, candidate string) {
	resolved, ok := resolveCandidateURL(c.target, candidate)
	if !ok {
		return
	}

	if isJavaScriptURL(resolved.String()) {
		c.jsSeen[resolved.String()] = struct{}{}
	}

	apiType := inferAPIType(resolved)
	reviewEndpoint, reviewable := buildReviewEndpoint(c, source, resolved, apiType)
	if !reviewable {
		return
	}
	if _, exists := c.reviewItems[reviewEndpoint.Normalized]; !exists {
		c.reviewItems[reviewEndpoint.Normalized] = reviewEndpoint
		publishDiscoveredEndpoint(context.Background(), reviewEndpoint)
	}

	if !reviewEndpoint.Selectable || !strictSameDomain(c.target, resolved) || !looksLikeBackendEndpoint(resolved, apiType) {
		return
	}

	normalized := normalizeEndpoint(resolved)
	confidence := scoreEndpointConfidence(source, resolved, apiType)
	endpoint := BackendEndpoint{
		SessionID:          c.sessionID,
		Event:              "rasm_discovery",
		DiscoveredEndpoint: resolved.String(),
		Normalized:         normalized,
		Source:             source,
		Confidence:         confidence,
		APIType:            apiType,
		Type:               "backend-api",
		ParentTarget:       c.parentTarget,
		ScopeType:          reviewEndpoint.ScopeType,
		Risk:               reviewEndpoint.Risk,
		Reason:             reviewEndpoint.Reason,
		Selectable:         true,
		Recommended:        reviewEndpoint.Recommended,
	}

	added, err := redisClient.SAdd(context.Background(), c.seenKey, normalized)
	if err != nil || added == 0 {
		return
	}
	_ = redisClient.Expire(context.Background(), c.seenKey, 24*time.Hour)
	c.items[normalized] = endpoint
	publishDiscoveredEndpoint(context.Background(), endpoint)
}

func (c *rasmCollector) jsTargets() []string {
	out := make([]string, 0, len(c.jsSeen))
	for jsURL := range c.jsSeen {
		out = append(out, jsURL)
	}
	sort.Strings(out)
	if len(out) > 8 {
		return out[:8]
	}
	return out
}

func (c *rasmCollector) promisingTargets() []string {
	out := make([]string, 0, len(c.items))
	for _, endpoint := range c.items {
		u, err := url.Parse(endpoint.DiscoveredEndpoint)
		if err != nil {
			continue
		}
		if endpoint.APIType == "graphql" || len(u.Query()) > 0 || strings.Contains(strings.ToLower(u.Path), "api") || strings.Contains(strings.ToLower(u.Path), "auth") {
			out = append(out, endpoint.DiscoveredEndpoint)
		}
	}
	sort.Strings(out)
	if len(out) > 10 {
		return out[:10]
	}
	return out
}

func (c *rasmCollector) endpoints() []BackendEndpoint {
	out := make([]BackendEndpoint, 0, len(c.items))
	for _, endpoint := range c.items {
		out = append(out, endpoint)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence == out[j].Confidence {
			return out[i].Normalized < out[j].Normalized
		}
		return out[i].Confidence > out[j].Confidence
	})
	return out
}

func (c *rasmCollector) reviewEndpoints() []BackendEndpoint {
	out := make([]BackendEndpoint, 0, len(c.reviewItems))
	for _, endpoint := range c.reviewItems {
		out = append(out, endpoint)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Selectable == out[j].Selectable {
			if out[i].Confidence == out[j].Confidence {
				return out[i].Normalized < out[j].Normalized
			}
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Selectable && !out[j].Selectable
	})
	return out
}

func publishDiscoveredEndpoint(ctx context.Context, endpoint BackendEndpoint) {
	payload := map[string]interface{}{
		"session_id":          endpoint.SessionID,
		"event":               endpoint.Event,
		"discovered_endpoint": endpoint.DiscoveredEndpoint,
		"normalized":          endpoint.Normalized,
		"source":              endpoint.Source,
		"confidence":          endpoint.Confidence,
		"api_type":            endpoint.APIType,
		"type":                endpoint.Type,
		"parent_target":       endpoint.ParentTarget,
		"scope_type":          endpoint.ScopeType,
		"risk":                endpoint.Risk,
		"reason":              endpoint.Reason,
		"selectable":          endpoint.Selectable,
		"recommended":         endpoint.Recommended,
	}
	if _, err := redisClient.Publish(ctx, "recon-results", payload); err != nil {
		fmt.Printf("[recon-engine] failed to publish RASM discovery: %v\n", err)
	}
}

func runTool(parent context.Context, timeout time.Duration, name string, args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err == nil {
		return string(out), "", nil
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), string(exitErr.Stderr), err
	}
	return string(out), "", err
}

func findTool(names ...string) (string, error) {
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("tool not found")
}

func sleepBetweenTools(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
}

func extractCandidateURLs(raw string) []string {
	matches := urlPattern.FindAllString(raw, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		match = strings.TrimSpace(strings.Trim(match, `"'.,)`))
		if match != "" {
			out = append(out, match)
		}
	}
	return out
}

func resolveCandidateURL(target *url.URL, candidate string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(candidate))
	if err != nil {
		return nil, false
	}
	if u.Scheme == "" && strings.HasPrefix(candidate, "/") {
		return target.ResolveReference(u), true
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, false
	}
	return u, true
}

func strictSameDomain(target, candidate *url.URL) bool {
	return strings.EqualFold(target.Hostname(), candidate.Hostname())
}

func normalizeEndpoint(u *url.URL) string {
	normalized := *u
	normalized.Fragment = ""
	query := normalized.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	normalizedQuery := make(url.Values, len(keys))
	for _, key := range keys {
		normalizedQuery.Set(key, "*")
	}
	normalized.RawQuery = normalizedQuery.Encode()
	return normalized.String()
}

func inferAPIType(u *url.URL) string {
	path := strings.ToLower(u.Path)
	if strings.Contains(path, "graphql") {
		return "graphql"
	}
	if strings.HasPrefix(path, "/api") || regexp.MustCompile(`^/v\d+/`).MatchString(path) || len(u.Query()) > 0 {
		return "rest"
	}
	return "unknown"
}

func looksLikeBackendEndpoint(u *url.URL, apiType string) bool {
	if apiType == "graphql" || apiType == "rest" {
		return true
	}
	path := strings.ToLower(u.Path)
	keywords := []string{"login", "auth", "token", "session", "admin", "graphql", "users", "orders", "accounts", "internal"}
	for _, keyword := range keywords {
		if strings.Contains(path, keyword) {
			return true
		}
	}
	return false
}

func scoreEndpointConfidence(source string, u *url.URL, apiType string) float64 {
	base := map[string]float64{
		"katana":      0.92,
		"paramspider": 0.81,
		"enumapis":    0.86,
		"arjun":       0.9,
	}[source]
	if base == 0 {
		base = 0.7
	}
	path := strings.ToLower(u.Path)
	if len(u.Query()) > 0 {
		base += 0.03
	}
	if strings.Contains(path, "/api") || strings.Contains(path, "/v1/") || strings.Contains(path, "/v2/") {
		base += 0.03
	}
	if apiType == "graphql" {
		base += 0.04
	}
	if strings.Contains(path, "auth") || strings.Contains(path, "login") || strings.Contains(path, "user") {
		base += 0.02
	}
	if base > 0.99 {
		base = 0.99
	}
	return float64(int(base*100)) / 100
}

func buildReviewEndpoint(c *rasmCollector, source string, resolved *url.URL, apiType string) (BackendEndpoint, bool) {
	sameDomain := strictSameDomain(c.target, resolved)
	path := strings.ToLower(resolved.Path)
	host := strings.ToLower(resolved.Hostname())
	relevantExternal := strings.Contains(host, "api") || strings.Contains(host, "stripe") || strings.Contains(host, "mongo") || strings.Contains(host, "graphql") || strings.Contains(host, "auth") || strings.Contains(host, "vapi")
	reviewable := sameDomain && looksLikeBackendEndpoint(resolved, apiType)
	if !reviewable && !sameDomain && !(relevantExternal || apiType == "graphql" || len(resolved.Query()) > 0) {
		return BackendEndpoint{}, false
	}

	normalized := normalizeEndpoint(resolved)
	scopeType := "internal"
	risk := "medium"
	reason := "Same-domain endpoint discovered during endpoint discovery"
	selectable := sameDomain

	if !sameDomain {
		scopeType = "external"
		risk = "restricted"
		reason = "Different host discovered during crawling; excluded until explicitly reviewed"
		selectable = false
	} else if apiType == "graphql" || strings.Contains(path, "auth") || strings.Contains(path, "login") || len(resolved.Query()) > 0 {
		risk = "high"
		reason = "Sensitive or parameterized application surface"
	}

	recommended := selectable && (apiType == "graphql" || strings.Contains(path, "auth") || strings.Contains(path, "login") || strings.Contains(path, "/api") || len(resolved.Query()) > 0)

	return BackendEndpoint{
		SessionID:          c.sessionID,
		Event:              "endpoint_discovery",
		DiscoveredEndpoint: resolved.String(),
		Normalized:         normalized,
		Source:             source,
		Confidence:         scoreEndpointConfidence(source, resolved, apiType),
		APIType:            apiType,
		Type:               "endpoint-discovery",
		ParentTarget:       c.parentTarget,
		ScopeType:          scopeType,
		Risk:               risk,
		Reason:             reason,
		Selectable:         selectable,
		Recommended:        recommended,
	}, true
}

func isJavaScriptURL(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, ".js")
}

func truncateText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
