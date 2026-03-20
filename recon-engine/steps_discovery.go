package main

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// ─── Step 8: robots.txt + sitemap.xml Harvesting ───

func fetchRobotsSitemap(ctx context.Context, sessionID, targetURL string) RobotsSitemapResult {
	publishEvent(ctx, sessionID, "recon", "discovery", "Fetching robots.txt and sitemap.xml...", nil)

	result := RobotsSitemapResult{Entries: []string{}}
	client := newHTTPClient()

	baseURL := strings.TrimRight(targetURL, "/")

	// robots.txt
	resp, err := client.Get(baseURL + "/robots.txt")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			result.RobotsTxtFound = true
			lines := strings.Split(string(body), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				lower := strings.ToLower(line)
				if strings.HasPrefix(lower, "disallow:") {
					path := strings.TrimSpace(line[len("disallow:"):])
					if path != "" {
						result.Entries = append(result.Entries, "disallow:"+path)
					}
				} else if strings.HasPrefix(lower, "allow:") {
					path := strings.TrimSpace(line[len("allow:"):])
					if path != "" {
						result.Entries = append(result.Entries, "allow:"+path)
					}
				} else if strings.HasPrefix(lower, "sitemap:") {
					path := strings.TrimSpace(line[len("sitemap:"):])
					if path != "" {
						result.Entries = append(result.Entries, "sitemap:"+path)
					}
				}
			}
		}
	}

	// sitemap.xml
	resp2, err := client.Get(baseURL + "/sitemap.xml")
	if err == nil {
		defer resp2.Body.Close()
		if resp2.StatusCode == 200 {
			result.SitemapFound = true
			body, _ := io.ReadAll(io.LimitReader(resp2.Body, 16384))
			// Extract <loc> entries
			locRe := regexp.MustCompile(`<loc>([^<]+)</loc>`)
			matches := locRe.FindAllStringSubmatch(string(body), 50)
			for _, m := range matches {
				result.Entries = append(result.Entries, "sitemap-loc:"+m[1])
			}
		}
	}

	msg := fmt.Sprintf("robots.txt: %s | sitemap.xml: %s",
		boolStr(result.RobotsTxtFound, "found", "not found"),
		boolStr(result.SitemapFound, "found", "not found"))
	publishEvent(ctx, sessionID, "recon", "discovery", msg,
		map[string]interface{}{
			"robots_found":  result.RobotsTxtFound,
			"sitemap_found": result.SitemapFound,
			"entries_count": len(result.Entries),
		})

	return result
}

// ─── Step 9: JavaScript File Discovery + Framework Hints ───

func jsDiscovery(ctx context.Context, sessionID, targetURL string) ([]string, []string) {
	publishEvent(ctx, sessionID, "recon", "js-discovery", "Scanning for JavaScript files and frameworks...", nil)

	client := newHTTPClient()
	resp, err := client.Get(targetURL)
	if err != nil {
		publishEvent(ctx, sessionID, "recon", "js-discovery", "JS discovery failed (no response)", nil)
		return []string{}, []string{}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 131072))
	resp.Body.Close()

	bodyStr := string(body)

	// Extract <script src="..."> paths
	scriptRe := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRe.FindAllStringSubmatch(bodyStr, -1)

	jsFiles := []string{}
	seen := make(map[string]bool)
	for _, m := range matches {
		src := m[1]
		// Extract just the filename
		parts := strings.Split(src, "/")
		filename := parts[len(parts)-1]
		// Remove query strings
		if idx := strings.Index(filename, "?"); idx != -1 {
			filename = filename[:idx]
		}
		if filename != "" && !seen[filename] {
			seen[filename] = true
			jsFiles = append(jsFiles, filename)
		}
	}

	// Detect framework hints from JS filenames and page content
	frameworkSignatures := map[string][]string{
		"vue.js":    {"vue.min.js", "vue.js", "vue.runtime", "vue.global"},
		"react":     {"react.min.js", "react.js", "react-dom", "react.production"},
		"angular":   {"angular.min.js", "angular.js", "zone.js", "ng-", "angular.io"},
		"jquery":    {"jquery.min.js", "jquery.js", "jquery-"},
		"axios":     {"axios.min.js", "axios.js"},
		"lodash":    {"lodash.min.js", "lodash.js"},
		"bootstrap": {"bootstrap.min.js", "bootstrap.js", "bootstrap.bundle"},
		"next.js":   {"_next/", "__next", "next/"},
		"nuxt":      {"_nuxt/", "nuxt.js"},
		"svelte":    {"svelte", "__svelte"},
		"ember":     {"ember.min.js", "ember.js"},
		"backbone":  {"backbone.min.js", "backbone.js"},
		"express":   {"express"},
		"node":      {"node_modules", "node"},
	}

	hints := []string{}
	lowerBody := strings.ToLower(bodyStr)
	allJSLower := strings.ToLower(strings.Join(jsFiles, " "))

	for framework, sigs := range frameworkSignatures {
		for _, sig := range sigs {
			if strings.Contains(allJSLower, strings.ToLower(sig)) ||
				strings.Contains(lowerBody, strings.ToLower(sig)) {
				hints = append(hints, framework)
				break
			}
		}
	}

	publishEvent(ctx, sessionID, "recon", "js-discovery",
		fmt.Sprintf("Found %d JS files, %d framework hints", len(jsFiles), len(hints)),
		map[string]interface{}{"js_files": jsFiles, "framework_hints": hints})

	return jsFiles, hints
}

// ─── Step 10: Error Page Probing → Stack Trace Harvesting ───

func probeErrorPages(ctx context.Context, sessionID, targetURL string) ErrorResult {
	publishEvent(ctx, sessionID, "recon", "error-probe", "Probing error pages for information leakage...", nil)

	result := ErrorResult{StackSamples: []string{}}
	client := newHTTPClient()
	baseURL := strings.TrimRight(targetURL, "/")

	probes := []struct {
		path string
		desc string
	}{
		{"/nonexistent123456", "404 error page"},
		{"/debug", "debug endpoint"},
		{"/admin", "admin endpoint"},
		{"/api/../../etc/passwd", "path traversal probe"},
		{"/?id=1'", "SQL injection probe"},
		{"/wp-debug.log", "WordPress debug log"},
		{"/server-status", "Apache server-status"},
		{"/elmah.axd", ".NET error log"},
		{"/.env", "environment file"},
		{"/trace", "trace endpoint"},
	}

	stackTracePatterns := []string{
		"at ", "Traceback", "Exception", "Error:", "stack trace",
		".js:", ".py:", ".java:", ".php:", ".go:", ".rb:",
		"TypeError", "ReferenceError", "SyntaxError",
		"NullPointerException", "ClassNotFoundException",
	}

	sqlErrorPatterns := []string{
		"sql syntax", "mysql", "postgresql", "ora-", "sqlite",
		"odbc", "syntax error", "query failed", "sequelize",
		"prisma", "typeorm", "knex",
	}

	phpPatterns := []string{
		"fatal error", "warning:", "notice:", "parse error",
		"on line", ".php on line",
	}

	laravelPatterns := []string{
		"laravel", "illuminate\\", "whoops",
		"symfony\\component", "blade.php",
	}

	for _, probe := range probes {
		probeURL := baseURL + probe.path
		resp, err := client.Get(probeURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()

		bodyStr := string(body)
		lowerBody := strings.ToLower(bodyStr)

		// Check stack traces
		for _, pat := range stackTracePatterns {
			if strings.Contains(bodyStr, pat) {
				result.StackTracesFound = true
				// Extract a sample (first occurrence, ~80 chars)
				idx := strings.Index(bodyStr, pat)
				end := idx + 80
				if end > len(bodyStr) {
					end = len(bodyStr)
				}
				sample := strings.TrimSpace(bodyStr[idx:end])
				if len(result.StackSamples) < 5 {
					result.StackSamples = append(result.StackSamples, sample)
				}
				publishEvent(ctx, sessionID, "warning", "error-probe",
					fmt.Sprintf("Stack trace detected on %s", probe.desc),
					map[string]interface{}{"probe": probe.desc, "url": probeURL})
				break
			}
		}

		// Check SQL errors
		for _, pat := range sqlErrorPatterns {
			if strings.Contains(lowerBody, pat) {
				result.DBErrors++
				publishEvent(ctx, sessionID, "warning", "error-probe",
					fmt.Sprintf("SQL error keyword '%s' found in %s", pat, probe.desc),
					map[string]interface{}{"probe": probe.desc, "sql_keyword": pat})
				break
			}
		}

		// Check PHP errors
		for _, pat := range phpPatterns {
			if strings.Contains(lowerBody, pat) {
				result.StackTracesFound = true
				publishEvent(ctx, sessionID, "warning", "error-probe",
					fmt.Sprintf("PHP error pattern found in %s", probe.desc),
					map[string]interface{}{"probe": probe.desc, "pattern": pat})
				break
			}
		}

		// Check Laravel/Symfony patterns
		for _, pat := range laravelPatterns {
			if strings.Contains(lowerBody, pat) {
				result.StackTracesFound = true
				publishEvent(ctx, sessionID, "warning", "error-probe",
					fmt.Sprintf("Laravel/Symfony error found in %s", probe.desc),
					map[string]interface{}{"probe": probe.desc, "pattern": pat})
				break
			}
		}
	}

	publishEvent(ctx, sessionID, "recon", "error-probe",
		fmt.Sprintf("Error probing complete — stack traces: %v, DB errors: %d",
			result.StackTracesFound, result.DBErrors),
		map[string]interface{}{
			"stack_traces_found": result.StackTracesFound,
			"db_errors":          result.DBErrors,
			"stack_samples":      result.StackSamples,
		})

	return result
}

// ─── Helpers ───

func publishEvent(ctx context.Context, sessionID, eventType, step, message string, extra map[string]interface{}) {
	data := map[string]interface{}{
		"session_id": sessionID,
		"type":       eventType,
		"step":       step,
		"message":    message,
		"timestamp":  time.Now().Format(time.RFC3339Nano),
	}
	for k, v := range extra {
		data[k] = v
	}

	_, err := redisClient.Publish(ctx, "recon-results", data)
	if err != nil {
		fmt.Printf("[recon-engine] failed to publish event: %v\n", err)
	}
}

func boolStr(val bool, t, f string) string {
	if val {
		return t
	}
	return f
}
