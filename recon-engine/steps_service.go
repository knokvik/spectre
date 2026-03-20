package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ─── Step 3: Service Version Banner Grab ───

func bannerGrab(ctx context.Context, sessionID, host string, openPorts []int) map[string]string {
	publishEvent(ctx, sessionID, "recon", "banner-grab",
		fmt.Sprintf("Banner grabbing on %d open ports...", len(openPorts)), nil)

	services := make(map[string]string)
	var mu sync.Mutex
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

	for _, p := range openPorts {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))

			// Send a probe for HTTP-like ports
			if port == 80 || port == 8080 || port == 8000 || port == 8443 || port == 443 || port == 3000 {
				fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
			}

			buf := make([]byte, 512)
			n, _ := conn.Read(buf)
			if n > 0 {
				banner := strings.TrimSpace(string(buf[:n]))
				svc := parseServiceBanner(banner, port)
				mu.Lock()
				services[fmt.Sprintf("%d", port)] = svc
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	publishEvent(ctx, sessionID, "recon", "banner-grab",
		fmt.Sprintf("Banner grab complete — %d services identified", len(services)),
		map[string]interface{}{"services": services})

	return services
}

func parseServiceBanner(banner string, port int) string {
	lower := strings.ToLower(banner)

	// HTTP server header
	if strings.Contains(lower, "http/") {
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return strings.TrimSpace(line[7:])
			}
		}
		return "HTTP server"
	}

	if strings.Contains(lower, "ssh-") {
		return extractFirst(banner, 40)
	}
	if strings.Contains(lower, "mysql") {
		return "mysql/" + extractVersion(banner)
	}
	if strings.Contains(lower, "mariadb") {
		return "mariadb/" + extractVersion(banner)
	}
	if strings.Contains(lower, "postgresql") {
		return "postgresql"
	}
	if strings.Contains(lower, "smtp") {
		return extractFirst(banner, 60)
	}
	if strings.Contains(lower, "ftp") {
		return extractFirst(banner, 60)
	}
	if strings.Contains(lower, "redis") {
		return "redis"
	}
	if strings.Contains(lower, "mongodb") {
		return "mongodb"
	}
	if strings.Contains(lower, "elasticsearch") {
		return "elasticsearch"
	}

	// Fallback by well-known port
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 25, 587:
		return "smtp"
	case 53:
		return "dns"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	}

	if len(banner) > 60 {
		return banner[:60]
	}
	return banner
}

func extractFirst(s string, maxLen int) string {
	s = strings.TrimSpace(strings.Split(s, "\n")[0])
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

func extractVersion(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			end := i
			for end < len(s) && (s[end] == '.' || (s[end] >= '0' && s[end] <= '9')) {
				end++
			}
			return s[i:end]
		}
	}
	return "unknown"
}

// ─── Step 4: HTTP/S Header Harvest ───

func harvestHeaders(ctx context.Context, sessionID, targetURL string) map[string]interface{} {
	publishEvent(ctx, sessionID, "recon", "headers", "Harvesting HTTP response headers...", nil)

	client := newHTTPClient()
	headers := make(map[string]interface{})

	// GET request
	resp, err := client.Get(targetURL)
	if err != nil {
		publishEvent(ctx, sessionID, "error", "headers", fmt.Sprintf("Failed to fetch headers: %v", err), nil)
		return headers
	}
	defer resp.Body.Close()
	io.ReadAll(io.LimitReader(resp.Body, 1)) // drain

	// Collect all headers
	for k, vals := range resp.Header {
		key := strings.ToLower(k)
		if len(vals) == 1 {
			headers[key] = vals[0]
		} else {
			headers[key] = vals
		}
	}

	// Also do HEAD request to cross-check
	headResp, err := client.Head(targetURL)
	if err == nil {
		defer headResp.Body.Close()
		for k, vals := range headResp.Header {
			key := strings.ToLower(k)
			if _, exists := headers[key]; !exists {
				if len(vals) == 1 {
					headers[key] = vals[0]
				} else {
					headers[key] = vals
				}
			}
		}
	}

	// Parse Set-Cookie flags
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) > 0 {
		parsedCookies := []string{}
		for _, c := range cookies {
			parsedCookies = append(parsedCookies, c)
		}
		headers["set-cookie"] = parsedCookies
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

	publishEvent(ctx, sessionID, "recon", "headers",
		fmt.Sprintf("Headers harvested — %d security headers missing", len(missingHeaders)), headers)

	return headers
}

// ─── Step 5: TLS/SSL Certificate Analysis ───

func analyzeTLS(ctx context.Context, sessionID, host, port string) TLSResult {
	publishEvent(ctx, sessionID, "recon", "tls", "Analyzing TLS/SSL configuration...", nil)

	result := TLSResult{Version: "N/A", CertIssuer: "N/A"}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%s", host, port),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		publishEvent(ctx, sessionID, "recon", "tls",
			fmt.Sprintf("TLS not available or error: %v", err),
			map[string]interface{}{"tls_available": false})
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()

	switch state.Version {
	case tls.VersionTLS10:
		result.Version = "TLSv1.0"
	case tls.VersionTLS11:
		result.Version = "TLSv1.1"
	case tls.VersionTLS12:
		result.Version = "TLSv1.2"
	case tls.VersionTLS13:
		result.Version = "TLSv1.3"
	}

	// Check weak TLS versions
	if state.Version <= tls.VersionTLS11 {
		result.WeakCiphers = true
	}

	// Check weak cipher suites (RC4-based)
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	if strings.Contains(strings.ToLower(cipherName), "rc4") ||
		strings.Contains(strings.ToLower(cipherName), "3des") ||
		strings.Contains(strings.ToLower(cipherName), "null") {
		result.WeakCiphers = true
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.CertIssuer = cert.Issuer.CommonName
		result.CertValid = time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore)
	}

	extra := map[string]interface{}{
		"tls_version":  result.Version,
		"weak_ciphers": result.WeakCiphers,
		"cert_valid":   result.CertValid,
		"cert_issuer":  result.CertIssuer,
		"cipher_suite": cipherName,
	}

	publishEvent(ctx, sessionID, "recon", "tls",
		fmt.Sprintf("TLS analysis complete — %s (weak: %v)", result.Version, result.WeakCiphers), extra)

	return result
}

// ─── Step 6: WAF Detection ───

func wafDetect(ctx context.Context, sessionID, targetURL string) WAFResult {
	publishEvent(ctx, sessionID, "recon", "waf", "Detecting WAF/CDN presence...", nil)

	result := WAFResult{}
	client := newHTTPClient()

	// Check normal response
	resp, err := client.Get(targetURL)
	if err != nil {
		publishEvent(ctx, sessionID, "recon", "waf", "WAF detection failed (no response)", nil)
		return result
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	resp.Body.Close()

	allHeaders := ""
	for k, vals := range resp.Header {
		for _, v := range vals {
			allHeaders += k + ": " + v + "\n"
		}
	}

	bodyStr := string(body)
	combined := strings.ToLower(allHeaders + bodyStr)

	wafSignatures := map[string][]string{
		"Cloudflare":  {"cf-ray", "cloudflare", "__cfduid", "cf-cache-status"},
		"Akamai":      {"akamai", "x-akamai", "akamaighost"},
		"AWS WAF":     {"x-amzn-requestid", "x-amz-cf-id", "awselb", "aws-waf"},
		"ModSecurity": {"mod_security", "modsecurity", "mod_sec"},
		"Sucuri":      {"sucuri", "x-sucuri"},
		"Imperva":     {"imperva", "incapsula", "x-iinfo", "visid_incap"},
		"F5 BIG-IP":   {"bigip", "f5", "x-wa-info"},
		"Barracuda":   {"barracuda", "barra_counter_session"},
	}

	for vendor, sigs := range wafSignatures {
		for _, sig := range sigs {
			if strings.Contains(combined, sig) {
				result.Detected = true
				result.Vendor = vendor
				break
			}
		}
		if result.Detected {
			break
		}
	}

	// Also try a suspicious request to trigger WAF
	probeURL := strings.TrimRight(targetURL, "/") + "/?id=1'+OR+'1'='1"
	probeResp, err := client.Get(probeURL)
	if err == nil {
		probeBody, _ := io.ReadAll(io.LimitReader(probeResp.Body, 8192))
		probeResp.Body.Close()

		if probeResp.StatusCode == 403 || probeResp.StatusCode == 406 {
			probeCombined := strings.ToLower(string(probeBody))
			for k, vals := range probeResp.Header {
				for _, v := range vals {
					probeCombined += strings.ToLower(k + ": " + v + "\n")
				}
			}
			for vendor, sigs := range wafSignatures {
				for _, sig := range sigs {
					if strings.Contains(probeCombined, sig) {
						result.Detected = true
						result.Vendor = vendor
						break
					}
				}
				if result.Detected {
					break
				}
			}
			if !result.Detected && (probeResp.StatusCode == 403 || probeResp.StatusCode == 406) {
				result.Detected = true
				result.Vendor = "Unknown"
			}
		}
	}

	msg := "No WAF detected"
	if result.Detected {
		msg = fmt.Sprintf("WAF detected: %s", result.Vendor)
	}
	publishEvent(ctx, sessionID, "recon", "waf", msg,
		map[string]interface{}{"detected": result.Detected, "vendor": result.Vendor})

	return result
}

// ─── Step 7: CMS Detection ───

func cmsDetect(ctx context.Context, sessionID, targetURL string) CMSResult {
	publishEvent(ctx, sessionID, "recon", "cms", "Detecting CMS and platform...", nil)

	result := CMSResult{Type: "unknown", Hints: []string{}}
	client := newHTTPClient()

	// Fetch main page
	resp, err := client.Get(targetURL)
	if err != nil {
		publishEvent(ctx, sessionID, "recon", "cms", "CMS detection failed (no response)", nil)
		return result
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	resp.Body.Close()
	bodyStr := string(body)
	lowerBody := strings.ToLower(bodyStr)

	// Check meta generator tag
	generatorRe := regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	if m := generatorRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		result.Hints = append(result.Hints, "generator:"+m[1])
		gen := strings.ToLower(m[1])
		if strings.Contains(gen, "wordpress") {
			result.Type = "WordPress"
			result.VersionHint = extractVersion(m[1])
		} else if strings.Contains(gen, "drupal") {
			result.Type = "Drupal"
			result.VersionHint = extractVersion(m[1])
		} else if strings.Contains(gen, "joomla") {
			result.Type = "Joomla"
			result.VersionHint = extractVersion(m[1])
		}
	}

	// Check body content for CMS signatures
	if strings.Contains(lowerBody, "wp-content") || strings.Contains(lowerBody, "wp-includes") {
		result.Type = "WordPress"
		result.Hints = append(result.Hints, "wp-content")
	}

	// Probe known CMS paths
	cmsPaths := map[string]string{
		"/wp-admin/":      "WordPress",
		"/wp-login.php":   "WordPress",
		"/administrator/": "Joomla",
		"/misc/drupal.js": "Drupal",
		"/sites/default/": "Drupal",
	}
	for path, cms := range cmsPaths {
		probeURL := strings.TrimRight(targetURL, "/") + path
		probeResp, err := client.Get(probeURL)
		if err == nil {
			probeResp.Body.Close()
			if probeResp.StatusCode == 200 || probeResp.StatusCode == 301 || probeResp.StatusCode == 302 {
				result.Type = cms
				result.Hints = append(result.Hints, strings.Trim(path, "/"))
			}
		}
	}

	msg := fmt.Sprintf("CMS: %s", result.Type)
	if result.VersionHint != "" {
		msg += " v" + result.VersionHint
	}
	publishEvent(ctx, sessionID, "recon", "cms", msg,
		map[string]interface{}{"type": result.Type, "hints": result.Hints})

	return result
}
