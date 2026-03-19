package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	spectreRedis "github.com/spectre/pkg/redis"
)

var redisClient *spectreRedis.Client

func main() {
	log.Println("[recon-engine] starting...")

	redisClient = spectreRedis.NewClient()
	defer redisClient.Close()

	ctx := context.Background()

	// Subscribe to session-start stream
	log.Println("[recon-engine] waiting for session-start events...")
	err := redisClient.Subscribe(ctx, "session-start", "recon-group", "recon-worker-1", func(msg spectreRedis.StreamMessage) error {
		targetURL, _ := msg.Data["target_url"].(string)
		sessionID, _ := msg.Data["session_id"].(string)

		if targetURL == "" || sessionID == "" {
			log.Println("[recon-engine] skipping message: missing target_url or session_id")
			return nil
		}

		log.Printf("[recon-engine] starting recon for session %s → %s", sessionID, targetURL)
		runRecon(ctx, sessionID, targetURL)
		return nil
	})
	if err != nil {
		log.Fatalf("[recon-engine] subscribe error: %v", err)
	}
}

// runRecon launches all recon goroutines concurrently.
func runRecon(ctx context.Context, sessionID, targetURL string) {
	publishEvent(ctx, sessionID, "recon", "start", fmt.Sprintf("Starting reconnaissance on %s", targetURL), nil)

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		publishEvent(ctx, sessionID, "error", "url-parse", fmt.Sprintf("Failed to parse URL: %v", err), nil)
		return
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	var wg sync.WaitGroup
	startTime := time.Now()

	// Goroutine 1: TCP Port Scan
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanPorts(ctx, sessionID, host)
	}()

	// Goroutine 2: HTTP Header Harvest
	wg.Add(1)
	go func() {
		defer wg.Done()
		harvestHeaders(ctx, sessionID, targetURL)
	}()

	// Goroutine 3: TLS/SSL Analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		analyzeTLS(ctx, sessionID, host, port)
	}()

	// Goroutine 4: robots.txt + sitemap.xml
	wg.Add(1)
	go func() {
		defer wg.Done()
		fetchRobotsSitemap(ctx, sessionID, targetURL)
	}()

	// Goroutine 5: Error Page Probing
	wg.Add(1)
	go func() {
		defer wg.Done()
		probeErrorPages(ctx, sessionID, targetURL)
	}()

	wg.Wait()

	elapsed := time.Since(startTime)
	publishEvent(ctx, sessionID, "recon", "complete", fmt.Sprintf("Reconnaissance complete in %s", elapsed.Round(time.Millisecond)), nil)
}

// scanPorts scans the top 100 common ports concurrently.
func scanPorts(ctx context.Context, sessionID, host string) {
	publishEvent(ctx, sessionID, "recon", "port-scan", "Starting TCP port scan (top 100 ports)...", nil)

	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
		143, 443, 445, 465, 587, 631, 993, 995, 1433, 1521,
		2049, 2082, 2083, 2086, 2087, 3000, 3306, 3389, 5432, 5900,
		5985, 6379, 8000, 8008, 8080, 8443, 8888, 9090, 9200, 9300,
		27017, 27018, 28017, 11211, 11434, 4444, 6000, 6667, 8081, 8082,
		1080, 1194, 1723, 2222, 3128, 3690, 4000, 4040, 4443, 4848,
		5000, 5001, 5050, 5222, 5269, 5555, 5601, 5672, 5984, 6060,
		6443, 7000, 7001, 7002, 7070, 7071, 7443, 7474, 7777, 8001,
		8009, 8010, 8020, 8040, 8069, 8083, 8084, 8085, 8086, 8087,
		8088, 8089, 8090, 8091, 8161, 8200, 8280, 8300, 8500, 8600,
	}

	openPorts := []int{}
	var mu sync.Mutex

	sem := make(chan struct{}, 20) // concurrency limit
	var wg sync.WaitGroup

	for _, port := range commonPorts {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := fmt.Sprintf("%s:%d", host, p)
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()

				// Publish each open port as found
				publishEvent(ctx, sessionID, "recon", "port-scan", fmt.Sprintf("Port %d OPEN", p), map[string]interface{}{
					"port":   p,
					"status": "open",
				})
			}
		}(port)
	}

	wg.Wait()

	publishEvent(ctx, sessionID, "recon", "port-scan", fmt.Sprintf("Port scan complete — %d open ports found", len(openPorts)), map[string]interface{}{
		"open_ports": openPorts,
		"total":      len(openPorts),
	})
}

// harvestHeaders fetches HTTP headers and security headers.
func harvestHeaders(ctx context.Context, sessionID, targetURL string) {
	publishEvent(ctx, sessionID, "recon", "headers", "Harvesting HTTP response headers...", nil)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		publishEvent(ctx, sessionID, "error", "headers", fmt.Sprintf("Failed to fetch headers: %v", err), nil)
		return
	}
	defer resp.Body.Close()

	headers := map[string]interface{}{
		"status_code": resp.StatusCode,
	}

	interestingHeaders := []string{
		"Server", "X-Powered-By", "X-Frame-Options", "X-Content-Type-Options",
		"X-XSS-Protection", "Content-Security-Policy", "Strict-Transport-Security",
		"Referrer-Policy", "Permissions-Policy", "Access-Control-Allow-Origin",
		"Set-Cookie",
	}

	for _, h := range interestingHeaders {
		val := resp.Header.Get(h)
		if val != "" {
			headers[strings.ToLower(strings.ReplaceAll(h, "-", "_"))] = val
		}
	}

	// Check missing security headers
	missingHeaders := []string{}
	securityHeaders := []string{
		"X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy",
		"Strict-Transport-Security", "Referrer-Policy",
	}
	for _, h := range securityHeaders {
		if resp.Header.Get(h) == "" {
			missingHeaders = append(missingHeaders, h)
		}
	}
	headers["missing_security_headers"] = missingHeaders

	publishEvent(ctx, sessionID, "recon", "headers", fmt.Sprintf("Headers harvested — %d security headers missing", len(missingHeaders)), headers)
}

// analyzeTLS checks TLS configuration and certificate details.
func analyzeTLS(ctx context.Context, sessionID, host, port string) {
	publishEvent(ctx, sessionID, "recon", "tls", "Analyzing TLS/SSL configuration...", nil)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%s", host, port),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		publishEvent(ctx, sessionID, "recon", "tls", fmt.Sprintf("TLS not available or error: %v", err), map[string]interface{}{
			"tls_available": false,
		})
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	tlsVersion := "unknown"
	switch state.Version {
	case tls.VersionTLS10:
		tlsVersion = "TLS 1.0"
	case tls.VersionTLS11:
		tlsVersion = "TLS 1.1"
	case tls.VersionTLS12:
		tlsVersion = "TLS 1.2"
	case tls.VersionTLS13:
		tlsVersion = "TLS 1.3"
	}

	certInfo := map[string]interface{}{
		"tls_available": true,
		"tls_version":   tlsVersion,
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		certInfo["subject"] = cert.Subject.CommonName
		certInfo["issuer"] = cert.Issuer.CommonName
		certInfo["not_after"] = cert.NotAfter.Format(time.RFC3339)
		certInfo["expired"] = time.Now().After(cert.NotAfter)

		dnsNames := cert.DNSNames
		if len(dnsNames) > 5 {
			dnsNames = dnsNames[:5]
		}
		certInfo["dns_names"] = dnsNames
	}

	// Flag weak TLS
	if state.Version < tls.VersionTLS12 {
		certInfo["weakness"] = fmt.Sprintf("Weak TLS version: %s", tlsVersion)
	}

	publishEvent(ctx, sessionID, "recon", "tls", fmt.Sprintf("TLS analysis complete — %s", tlsVersion), certInfo)
}

// fetchRobotsSitemap fetches robots.txt and sitemap.xml.
func fetchRobotsSitemap(ctx context.Context, sessionID, targetURL string) {
	publishEvent(ctx, sessionID, "recon", "discovery", "Fetching robots.txt and sitemap.xml...", nil)

	client := &http.Client{
		Timeout:   8 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	// robots.txt
	robotsURL := strings.TrimRight(targetURL, "/") + "/robots.txt"
	resp, err := client.Get(robotsURL)
	robotsFound := false
	robotsContent := ""
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			robotsContent = string(body)
			robotsFound = true
		}
	}

	// sitemap.xml
	sitemapURL := strings.TrimRight(targetURL, "/") + "/sitemap.xml"
	resp2, err := client.Get(sitemapURL)
	sitemapFound := false
	if err == nil {
		defer resp2.Body.Close()
		sitemapFound = resp2.StatusCode == 200
	}

	result := map[string]interface{}{
		"robots_found":  robotsFound,
		"sitemap_found": sitemapFound,
	}

	if robotsFound {
		// Extract disallowed paths
		lines := strings.Split(robotsContent, "\n")
		disallowed := []string{}
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "disallow:") {
				path := strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
				path = strings.TrimSpace(strings.TrimPrefix(path, "disallow:"))
				if path != "" {
					disallowed = append(disallowed, path)
				}
			}
		}
		result["disallowed_paths"] = disallowed
	}

	msg := fmt.Sprintf("robots.txt: %s | sitemap.xml: %s",
		boolStr(robotsFound, "found", "not found"),
		boolStr(sitemapFound, "found", "not found"))
	publishEvent(ctx, sessionID, "recon", "discovery", msg, result)
}

// probeErrorPages triggers error responses to detect stack traces.
func probeErrorPages(ctx context.Context, sessionID, targetURL string) {
	publishEvent(ctx, sessionID, "recon", "error-probe", "Probing error pages for information leakage...", nil)

	client := &http.Client{
		Timeout:   8 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	probes := []struct {
		path string
		desc string
	}{
		{"/this-page-does-not-exist-spectre-404", "404 error page"},
		{"/api/../../etc/passwd", "path traversal probe"},
		{"/?id=1'", "SQL injection probe (single quote)"},
	}

	for _, probe := range probes {
		probeURL := strings.TrimRight(targetURL, "/") + probe.path
		resp, err := client.Get(probeURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		bodyStr := string(body)
		findings := map[string]interface{}{
			"probe":       probe.desc,
			"url":         probeURL,
			"status_code": resp.StatusCode,
		}

		// Check for stack traces and verbose errors
		stackTraceKeywords := []string{
			"at ", "Traceback", "Exception", "Error:", "stack trace",
			"line ", ".js:", ".py:", ".java:", ".php:", ".go:",
		}
		for _, kw := range stackTraceKeywords {
			if strings.Contains(bodyStr, kw) {
				findings["stack_trace_detected"] = true
				findings["keyword_matched"] = kw
				publishEvent(ctx, sessionID, "warning", "error-probe",
					fmt.Sprintf("Stack trace or verbose error detected on %s", probe.desc), findings)
				break
			}
		}

		// Check for SQL error keywords
		sqlKeywords := []string{
			"SQL syntax", "mysql", "PostgreSQL", "ORA-", "sqlite",
			"ODBC", "syntax error", "query failed", "Sequelize",
		}
		for _, kw := range sqlKeywords {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(kw)) {
				findings["sql_error_detected"] = true
				findings["sql_keyword"] = kw
				publishEvent(ctx, sessionID, "warning", "error-probe",
					fmt.Sprintf("SQL error keyword '%s' found in %s response", kw, probe.desc), findings)
				break
			}
		}

		// Check for server info leak
		serverHeader := resp.Header.Get("Server")
		if serverHeader != "" {
			findings["server_header"] = serverHeader
		}
	}

	publishEvent(ctx, sessionID, "recon", "error-probe", "Error page probing complete", nil)
}

// publishEvent sends a recon event to the recon-results Redis stream.
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
		log.Printf("[recon-engine] failed to publish event: %v", err)
	}
}

func boolStr(val bool, t, f string) string {
	if val {
		return t
	}
	return f
}
