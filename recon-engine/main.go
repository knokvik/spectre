package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	spectreRedis "github.com/spectre/pkg/redis"
)

var redisClient *spectreRedis.Client
var sessionCancels sync.Map

// ─── Result structs matching the exact output schema ───

type ReconResult struct {
	SessionID     string                 `json:"session_id"`
	TargetURL     string                 `json:"target_url"`
	Scope         string                 `json:"scope"`
	OpenPorts     []int                  `json:"open_ports"`
	Services      map[string]string      `json:"services"`
	Headers       map[string]interface{} `json:"headers"`
	TLS           TLSResult              `json:"tls"`
	WAF           WAFResult              `json:"waf"`
	CMS           CMSResult              `json:"cms"`
	DNS           DNSResult              `json:"dns"`
	RobotsSitemap RobotsSitemapResult    `json:"robots_sitemap"`
	JSFiles       []string               `json:"js_files"`
	FrameworkHints []string              `json:"framework_hints"`
	Errors        ErrorResult            `json:"errors"`
}

type TLSResult struct {
	Version     string `json:"version"`
	WeakCiphers bool   `json:"weak_ciphers"`
	CertValid   bool   `json:"cert_valid"`
	CertIssuer  string `json:"cert_issuer"`
}

type WAFResult struct {
	Detected bool   `json:"detected"`
	Vendor   string `json:"vendor"`
}

type CMSResult struct {
	Type        string   `json:"type"`
	VersionHint string   `json:"version_hint"`
	Hints       []string `json:"hints"`
}

type DNSResult struct {
	ResolvedIP string      `json:"resolved_ip"`
	ReverseDNS string      `json:"reverse_dns"`
	WHOIS      WHOISResult `json:"whois"`
}

type WHOISResult struct {
	Org       string `json:"org"`
	Registrar string `json:"registrar"`
}

type RobotsSitemapResult struct {
	RobotsTxtFound bool     `json:"robots_txt_found"`
	SitemapFound   bool     `json:"sitemap_found"`
	Entries        []string `json:"entries"`
}

type ErrorResult struct {
	StackTracesFound bool     `json:"stack_traces_found"`
	DBErrors         int      `json:"db_errors"`
	StackSamples     []string `json:"stack_samples"`
}

func main() {
	log.Println("[recon-engine] starting...")

	redisClient = spectreRedis.NewClient()
	defer redisClient.Close()

	ctx := context.Background()

	// Listen for session-stop events to cancel running recon
	go func() {
		log.Println("[recon-engine] listening for session-stop...")
		err := redisClient.Subscribe(ctx, "session-stop", "recon-stop-group", "recon-stop-worker", func(msg spectreRedis.StreamMessage) error {
			sessionID, _ := msg.Data["session_id"].(string)
			if sessionID == "" {
				return nil
			}
			if cancelFn, ok := sessionCancels.LoadAndDelete(sessionID); ok {
				log.Printf("[recon-engine] STOP received — cancelling recon for session %s", sessionID)
				cancelFn.(context.CancelFunc)()
			}
			return nil
		})
		if err != nil {
			log.Printf("[recon-engine] session-stop stream error: %v", err)
		}
	}()

	// Subscribe to session-start stream
	log.Println("[recon-engine] waiting for session-start events...")
	err := redisClient.Subscribe(ctx, "session-start", "recon-group", "recon-worker-1", func(msg spectreRedis.StreamMessage) error {
		targetURL, _ := msg.Data["target_url"].(string)
		sessionID, _ := msg.Data["session_id"].(string)
		scope, _ := msg.Data["scope"].(string)

		if scope == "" {
			scope = "web+server"
		}

		if targetURL == "" || sessionID == "" {
			log.Println("[recon-engine] skipping message: missing target_url or session_id")
			return nil
		}

		// Support multiple comma-separated targets
		targets := strings.Split(targetURL, ",")
		for i := range targets {
			targets[i] = strings.TrimSpace(targets[i])
		}

		sessionCtx, cancel := context.WithCancel(ctx)
		sessionCancels.Store(sessionID, cancel)

		if len(targets) == 1 {
			log.Printf("[recon-engine] starting recon for session %s → %s (Scope: %s)", sessionID, targets[0], scope)
			runRecon(sessionCtx, sessionID, targets[0], scope)
		} else {
			log.Printf("[recon-engine] starting recon for session %s → %d targets (Scope: %s)", sessionID, len(targets), scope)
			sem := make(chan struct{}, 10)
			var wg sync.WaitGroup
			for _, t := range targets {
				wg.Add(1)
				sem <- struct{}{}
				go func(target string) {
					defer wg.Done()
					defer func() { <-sem }()
					runRecon(sessionCtx, sessionID, target, scope)
				}(t)
			}
			wg.Wait()
		}

		cancel()
		sessionCancels.Delete(sessionID)
		return nil
	})
	if err != nil {
		log.Fatalf("[recon-engine] subscribe error: %v", err)
	}
}

func newHTTPClient() *http.Client {
	return &http.Client{
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
}

// runRecon launches all 10 recon goroutines concurrently for a single target.
func runRecon(ctx context.Context, sessionID, targetURL, scope string) {
	publishEvent(ctx, sessionID, "recon", "start", fmt.Sprintf("Starting reconnaissance on %s (Scope: %s)", targetURL, scope), nil)

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
	isHTTPS := parsedURL.Scheme == "https"

	var wg sync.WaitGroup
	startTime := time.Now()

	// Shared result (thread-safe via mutex)
	result := &ReconResult{
		SessionID:      sessionID,
		TargetURL:      targetURL,
		Scope:          scope,
		OpenPorts:      []int{},
		Services:       make(map[string]string),
		Headers:        make(map[string]interface{}),
		JSFiles:        []string{},
		FrameworkHints: []string{},
	}
	result.RobotsSitemap.Entries = []string{}
	result.CMS.Hints = []string{}
	result.Errors.StackSamples = []string{}
	var mu sync.Mutex

	// Step 1: DNS
	wg.Add(1)
	go func() {
		defer wg.Done()
		dns := dnsRecon(ctx, sessionID, host)
		mu.Lock()
		result.DNS = dns
		mu.Unlock()
	}()

	// Step 2+3: Port scan then banner grab (sequential dependency)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ports := scanPorts(ctx, sessionID, host, scope)
		mu.Lock()
		result.OpenPorts = ports
		mu.Unlock()

		services := bannerGrab(ctx, sessionID, host, ports)
		mu.Lock()
		result.Services = services
		mu.Unlock()
	}()

	// Step 4: Headers
	if scope != "server" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hdrs := harvestHeaders(ctx, sessionID, targetURL)
			mu.Lock()
			result.Headers = hdrs
			mu.Unlock()
		}()
	}

	// Step 5: TLS
	wg.Add(1)
	go func() {
		defer wg.Done()
		if isHTTPS {
			tlsR := analyzeTLS(ctx, sessionID, host, port)
			mu.Lock()
			result.TLS = tlsR
			mu.Unlock()
		}
	}()

	// Step 6: WAF
	if scope != "server" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			waf := wafDetect(ctx, sessionID, targetURL)
			mu.Lock()
			result.WAF = waf
			mu.Unlock()
		}()
	}

	// Step 7: CMS
	if scope != "server" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cms := cmsDetect(ctx, sessionID, targetURL)
			mu.Lock()
			result.CMS = cms
			mu.Unlock()
		}()
	}

	// Step 8: robots + sitemap
	if scope != "server" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rs := fetchRobotsSitemap(ctx, sessionID, targetURL)
			mu.Lock()
			result.RobotsSitemap = rs
			mu.Unlock()
		}()
	}

	// Step 9: JS discovery
	if scope != "server" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jsFiles, hints := jsDiscovery(ctx, sessionID, targetURL)
			mu.Lock()
			result.JSFiles = jsFiles
			result.FrameworkHints = hints
			mu.Unlock()
		}()
	}

	// Step 10: Error pages
	if scope != "server" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs := probeErrorPages(ctx, sessionID, targetURL)
			mu.Lock()
			result.Errors = errs
			mu.Unlock()
		}()
	}

	wg.Wait()
	elapsed := time.Since(startTime)

	// Publish final structured recon-results JSON
	resultJSON, _ := json.Marshal(result)
	var resultMap map[string]interface{}
	json.Unmarshal(resultJSON, &resultMap)
	resultMap["type"] = "recon"
	resultMap["step"] = "recon-results"
	resultMap["message"] = "Final structured recon results"
	resultMap["timestamp"] = time.Now().Format(time.RFC3339Nano)

	_, pubErr := redisClient.Publish(ctx, "recon-results", resultMap)
	if pubErr != nil {
		log.Printf("[recon-engine] failed to publish final results: %v", pubErr)
	}

	// Create and publish a small human-readable summary before completion
	wafVendor := result.WAF.Vendor
	if !result.WAF.Detected {
		wafVendor = "None"
	}
	summaryMsg := fmt.Sprintf("📊 Recon Summary (Scope: %s): %d open ports | TLS: %s | WAF: %s | CMS: %s | JS Files: %d",
		scope, len(result.OpenPorts), result.TLS.Version, wafVendor, result.CMS.Type, len(result.JSFiles))
	publishEvent(ctx, sessionID, "recon", "summary", summaryMsg, nil)

	// Publish recon-complete event
	publishEvent(ctx, sessionID, "recon", "complete",
		fmt.Sprintf("Reconnaissance complete in %s", elapsed.Round(time.Millisecond)),
		map[string]interface{}{
			"target_url":   targetURL,
			"scope":        scope,
			"elapsed_ms":   elapsed.Milliseconds(),
		})

	log.Printf("[recon-engine] recon complete for %s in %s", targetURL, elapsed.Round(time.Millisecond))
}
