package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	spectreRedis "github.com/spectre/pkg/redis"
)

// Unique worker suffix to avoid consumer group contention across restarts
var workerID = fmt.Sprintf("w-%d", time.Now().UnixNano())

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
var (
	redisClient *spectreRedis.Client
	sessionMap  sync.Map // Maps sessionID -> targetURL
	sessionCtxs sync.Map // Maps sessionID -> context.CancelFunc

	mlEngineURL      = getEnv("ML_ENGINE_URL", "http://localhost:5001")
	llmClassifierURL = getEnv("LLM_CLASSIFIER_URL", "http://localhost:5002")
	scoringEngineURL = getEnv("SCORING_ENGINE_URL", "http://localhost:5003")
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Recon Data Collector (accumulated per session)
// ---------------------------------------------------------------------------
type ReconCollector struct {
	mu                sync.Mutex
	OpenPorts         []int    `json:"open_ports"`
	MissingHeaders    []string `json:"missing_headers"`
	TLSVersion        string   `json:"tls_version"`
	TLSAvailable      bool     `json:"tls_available"`
	ServerHeader      string   `json:"server_header"`
	XPoweredBy        string   `json:"x_powered_by"`
	ErrorProbeSQLi    bool     `json:"error_probe_sqli"`
	ErrorProbeTraversal bool   `json:"error_probe_traversal"`
	StackTraceDetected bool    `json:"stack_trace_detected"`
	RobotsFound       bool     `json:"robots_found"`
	DisallowedPaths   []string `json:"disallowed_paths"`
	TotalOpenPorts    int      `json:"total_open_ports"`
	RiskyPortsOpen    int      `json:"risky_ports_open"`
}

var reconData sync.Map // sessionID -> *ReconCollector

func getCollector(sessionID string) *ReconCollector {
	val, loaded := reconData.LoadOrStore(sessionID, &ReconCollector{
		TLSAvailable: true,
	})
	if !loaded {
		log.Printf("[attack-orchestrator] Created recon collector for session %s", sessionID)
	}
	return val.(*ReconCollector)
}

var riskyPorts = map[int]bool{
	21: true, 22: true, 23: true, 25: true, 3306: true,
	5432: true, 6379: true, 27017: true, 11211: true,
	9200: true, 5900: true, 1433: true, 1521: true,
	445: true, 139: true,
}

// collectReconEvent processes a recon event and enriches the collector
func collectReconEvent(sessionID string, data map[string]interface{}) {
	c := getCollector(sessionID)
	c.mu.Lock()
	defer c.mu.Unlock()

	step, _ := data["step"].(string)

	switch step {
	case "port-scan":
		// Single port open event
		if port, ok := data["port"]; ok {
			if p, ok := toInt(port); ok {
				c.OpenPorts = append(c.OpenPorts, p)
				c.TotalOpenPorts = len(c.OpenPorts)
				if riskyPorts[p] {
					c.RiskyPortsOpen++
				}
			}
		}
		// Bulk open_ports from final scan summary
		if ports, ok := data["open_ports"]; ok {
			if portList, ok := ports.([]interface{}); ok && len(c.OpenPorts) == 0 {
				for _, p := range portList {
					if pi, ok := toInt(p); ok {
						c.OpenPorts = append(c.OpenPorts, pi)
						if riskyPorts[pi] {
							c.RiskyPortsOpen++
						}
					}
				}
				c.TotalOpenPorts = len(c.OpenPorts)
			}
		}

	case "headers":
		if sh, ok := data["server"].(string); ok && sh != "" {
			c.ServerHeader = sh
		}
		if xp, ok := data["x_powered_by"].(string); ok && xp != "" {
			c.XPoweredBy = xp
		}
		if mh, ok := data["missing_security_headers"]; ok {
			if headers, ok := mh.([]interface{}); ok {
				for _, h := range headers {
					if hs, ok := h.(string); ok {
						c.MissingHeaders = append(c.MissingHeaders, hs)
					}
				}
			}
		}

	case "tls":
		if tv, ok := data["tls_version"].(string); ok {
			c.TLSVersion = tv
		}
		if ta, ok := data["tls_available"]; ok {
			if available, ok := ta.(bool); ok {
				c.TLSAvailable = available
			}
		}

	case "error-probe":
		if _, ok := data["sql_error_detected"]; ok {
			c.ErrorProbeSQLi = true
		}
		if _, ok := data["stack_trace_detected"]; ok {
			c.StackTraceDetected = true
		}

	case "discovery":
		if rf, ok := data["robots_found"]; ok {
			if found, ok := rf.(bool); ok {
				c.RobotsFound = found
			}
		}
		if dp, ok := data["disallowed_paths"]; ok {
			if paths, ok := dp.([]interface{}); ok {
				for _, p := range paths {
					if ps, ok := p.(string); ok {
						c.DisallowedPaths = append(c.DisallowedPaths, ps)
					}
				}
			}
		}
	}
}

func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// ML Engine / LLM Classifier / Scoring Engine HTTP Clients
// ---------------------------------------------------------------------------
type MLPrediction struct {
	Category           string   `json:"category"`
	Confidence         float64  `json:"confidence"`
	Reasoning          string   `json:"reasoning"`
	RecommendedPayloads []string `json:"recommended_payloads"`
}

type MLPredictionResponse struct {
	SessionID     string         `json:"session_id"`
	Predictions   []MLPrediction `json:"predictions"`
	FeatureVector map[string]interface{} `json:"feature_vector"`
}

type ClassifyResponse struct {
	Severity      string  `json:"severity"`
	SeverityScore float64 `json:"severity_score"`
	Description   string  `json:"description"`
	Remediation   string  `json:"remediation"`
	ClassifiedBy  string  `json:"classified_by"`
}

type ScoreFinding struct {
	Type          string  `json:"type"`
	Severity      string  `json:"severity"`
	SeverityScore float64 `json:"severity_score"`
	Confirmed     bool    `json:"confirmed"`
}

type ScoreResponse struct {
	RiskScore float64 `json:"risk_score"`
	RiskLevel string  `json:"risk_level"`
	RiskGrade string  `json:"risk_grade"`
	Summary   string  `json:"summary"`
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

func callMLPredict(sessionID string, collector *ReconCollector) (*MLPredictionResponse, error) {
	collector.mu.Lock()
	payload := map[string]interface{}{
		"session_id":            sessionID,
		"open_ports":            collector.OpenPorts,
		"missing_headers":      collector.MissingHeaders,
		"tls_version":          collector.TLSVersion,
		"tls_available":        collector.TLSAvailable,
		"server_header":        collector.ServerHeader,
		"x_powered_by":         collector.XPoweredBy,
		"error_probe_sqli":     collector.ErrorProbeSQLi,
		"error_probe_traversal": collector.ErrorProbeTraversal,
		"stack_trace_detected":  collector.StackTraceDetected,
		"robots_found":          collector.RobotsFound,
		"disallowed_paths":      collector.DisallowedPaths,
	}
	collector.mu.Unlock()

	body, _ := json.Marshal(payload)
	resp, err := httpClient.Post(mlEngineURL+"/predict", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ML Engine request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ML Engine returned %d: %s", resp.StatusCode, string(b))
	}

	var result MLPredictionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ML Engine response decode failed: %w", err)
	}
	return &result, nil
}

func callClassify(sessionID, vulnType, attackResult string, httpStatus int, confidence float64, targetURL string) (*ClassifyResponse, error) {
	payload := map[string]interface{}{
		"session_id":       sessionID,
		"vulnerability_type": vulnType,
		"attack_result":    attackResult,
		"http_status":      httpStatus,
		"confidence":       confidence,
		"target_url":       targetURL,
	}
	body, _ := json.Marshal(payload)
	resp, err := httpClient.Post(llmClassifierURL+"/classify", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("LLM Classifier request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("LLM Classifier returned %d: %s", resp.StatusCode, string(b))
	}

	var result ClassifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("LLM Classifier response decode failed: %w", err)
	}
	return &result, nil
}

func callScoring(sessionID, targetURL string, findings []ScoreFinding, collector *ReconCollector) (*ScoreResponse, error) {
	collector.mu.Lock()
	payload := map[string]interface{}{
		"session_id":              sessionID,
		"target_url":             targetURL,
		"findings":               findings,
		"missing_security_headers": len(collector.MissingHeaders),
		"weak_tls":               collector.TLSVersion == "TLS 1.0" || collector.TLSVersion == "TLS 1.1" || !collector.TLSAvailable,
		"total_open_ports":       collector.TotalOpenPorts,
		"risky_ports_open":       collector.RiskyPortsOpen,
	}
	collector.mu.Unlock()

	body, _ := json.Marshal(payload)
	resp, err := httpClient.Post(scoringEngineURL+"/score", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("Scoring Engine request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Scoring Engine returned %d: %s", resp.StatusCode, string(b))
	}

	var result ScoreResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("Scoring Engine response decode failed: %w", err)
	}
	return &result, nil
}

// ---------------------------------------------------------------------------
// Main — Event loop
// ---------------------------------------------------------------------------
func main() {
	log.Println("[attack-orchestrator] starting ML-powered attack pipeline...")

	redisClient = spectreRedis.NewClient()
	defer redisClient.Close()

	ctx := context.Background()

	// 1. Listen for new sessions to grab the Target URL
	go func() {
		log.Println("[attack-orchestrator] listening for session-start...")
		err := redisClient.Subscribe(ctx, "session-start", "atk-session-group", "atk-session-"+workerID, func(msg spectreRedis.StreamMessage) error {
			sessionID, _ := msg.Data["session_id"].(string)
			targetURL, _ := msg.Data["target_url"].(string)

			if sessionID != "" && targetURL != "" {
				sessionMap.Store(sessionID, targetURL)
				log.Printf("[attack-orchestrator] Tracking URL %s for session %s", targetURL, sessionID)
			}
			return nil
		})
		if err != nil {
			log.Fatalf("[attack-orchestrator] session-start stream error: %v", err)
		}
	}()

	// 2. Listen for session-stop events to cancel running pipelines
	go func() {
		log.Println("[attack-orchestrator] listening for session-stop...")
		err := redisClient.Subscribe(ctx, "session-stop", "atk-stop-group", "atk-stop-"+workerID, func(msg spectreRedis.StreamMessage) error {
			sessionID, _ := msg.Data["session_id"].(string)
			if sessionID == "" {
				return nil
			}
			if cancelFn, ok := sessionCtxs.LoadAndDelete(sessionID); ok {
				log.Printf("[attack-orchestrator] STOP received — cancelling session %s", sessionID)
				cancelFn.(context.CancelFunc)()
			}
			return nil
		})
		if err != nil {
			log.Printf("[attack-orchestrator] session-stop stream error: %v", err)
		}
	}()

	// 3. Listen for recon events to collect data AND trigger attacks on completion
	log.Println("[attack-orchestrator] waiting for recon events...")
	err := redisClient.Subscribe(ctx, "recon-results", "atk-recon-group", "atk-recon-"+workerID, func(msg spectreRedis.StreamMessage) error {
		sessionID, _ := msg.Data["session_id"].(string)
		if sessionID == "" {
			return nil
		}

		step, _ := msg.Data["step"].(string)
		eventType, _ := msg.Data["type"].(string)

		log.Printf("[attack-orchestrator] recon event: session=%s type=%s step=%s", sessionID, eventType, step)

		// Collect recon data as it streams in
		if eventType == "recon" || eventType == "warning" {
			collectReconEvent(sessionID, msg.Data)
		}

		// When recon completes, launch the ML-powered attack pipeline
		if step == "complete" {
			// BUG FIX: Read target_url directly from the completion event
			// instead of relying on sessionMap (eliminates race condition)
			targetURL, _ := msg.Data["target_url"].(string)
			if targetURL == "" {
				// Fallback to sessionMap if not in event
				if val, ok := sessionMap.Load(sessionID); ok {
					targetURL = val.(string)
				}
			}
			if targetURL == "" {
				log.Printf("[attack-orchestrator] WARNING: no target_url for session %s, skipping", sessionID)
				return nil
			}

			log.Printf("[attack-orchestrator] Recon complete for %s → %s. Starting ML pipeline...", sessionID, targetURL)

			// Create a cancellable context for this session
			sessionCtx, cancel := context.WithCancel(ctx)
			sessionCtxs.Store(sessionID, cancel)

			// Update Dashboard Phase
			publishPhaseUpdate(sessionCtx, sessionID, "ml-analysis")
			
			// Launch ML-powered attacks in background
			go func() {
				defer cancel()
				defer sessionCtxs.Delete(sessionID)
				runMLPipeline(sessionCtx, sessionID, targetURL)
			}()
		}
		return nil
	})

	if err != nil {
		log.Fatalf("[attack-orchestrator] recon-results stream error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ML-Powered Attack Pipeline
// ---------------------------------------------------------------------------
func runMLPipeline(ctx context.Context, sessionID, targetURL string) {
	baseURL := strings.TrimRight(targetURL, "/")
	collector := getCollector(sessionID)

	// Check if already cancelled
	if ctx.Err() != nil {
		log.Printf("[attack-orchestrator] session %s cancelled before ML pipeline", sessionID)
		return
	}

	// ── Phase 1: ML Prediction ──────────────────────────────────────
	publishAttackEvent(ctx, sessionID, "info", "🧠 Sending recon data to ML Engine for vulnerability prediction...")
	time.Sleep(500 * time.Millisecond)

	mlResult, err := callMLPredict(sessionID, collector)
	if err != nil {
		publishAttackEvent(ctx, sessionID, "error", fmt.Sprintf("ML Engine unavailable: %v. Falling back to static attacks.", err))
		// Fallback: run static attacks if ML Engine is down
		executeStaticAttacks(ctx, sessionID, baseURL)
		return
	}

	if len(mlResult.Predictions) == 0 {
		publishAttackEvent(ctx, sessionID, "success", "✅ ML Engine found no likely vulnerabilities. Target appears secure.")
		publishPhaseUpdate(ctx, sessionID, "score")
		callFinalScoring(ctx, sessionID, baseURL, nil, collector)
		return
	}

	publishAttackEvent(ctx, sessionID, "info", fmt.Sprintf("🎯 ML Engine predicted %d vulnerability categories", len(mlResult.Predictions)))
	time.Sleep(500 * time.Millisecond)

	for _, pred := range mlResult.Predictions {
		publishAttackEvent(ctx, sessionID, "ml-prediction",
			fmt.Sprintf("[%.0f%% confidence] %s — %s", pred.Confidence*100, pred.Category, pred.Reasoning))
		time.Sleep(300 * time.Millisecond)
	}

	// ── Phase 2: Targeted Attacks ──────────────────────────────────
	publishPhaseUpdate(ctx, sessionID, "attack")
	publishAttackEvent(ctx, sessionID, "info", "⚔️ Launching targeted attacks based on ML predictions...")
	time.Sleep(1 * time.Second)

	var findings []ScoreFinding

	for _, pred := range mlResult.Predictions {
		// Check cancellation between attacks
		if ctx.Err() != nil {
			publishAttackEvent(context.Background(), sessionID, "warning", "⛔ Assessment stopped by user.")
			publishPhaseUpdate(context.Background(), sessionID, "report")
			return
		}

		if len(pred.RecommendedPayloads) == 0 {
			// Config-based finding (e.g. weak TLS) — no active attack needed
			publishAttackEvent(ctx, sessionID, "warning",
				fmt.Sprintf("[%s] Configuration issue detected (no active exploit needed)", pred.Category))
			
			classification := classifyFinding(ctx, sessionID, pred.Category, "Configuration weakness detected", 0, pred.Confidence, baseURL)
			findings = append(findings, ScoreFinding{
				Type:          pred.Category,
				Severity:      classification.Severity,
				SeverityScore: classification.SeverityScore,
				Confirmed:     false,
			})
			continue
		}

		// Fire up to 2 payloads per category
		payloads := pred.RecommendedPayloads
		if len(payloads) > 2 {
			payloads = payloads[:2]
		}

		for _, payload := range payloads {
			if ctx.Err() != nil {
				publishAttackEvent(context.Background(), sessionID, "warning", "⛔ Assessment stopped by user.")
				publishPhaseUpdate(context.Background(), sessionID, "report")
				return
			}

			attackURL := buildAttackURL(baseURL, pred.Category, payload)
			result, status, confirmed := fireMLPayload(ctx, sessionID, pred.Category, attackURL, payload)

			classification := classifyFinding(ctx, sessionID, pred.Category, result, status, pred.Confidence, baseURL)
			findings = append(findings, ScoreFinding{
				Type:          pred.Category,
				Severity:      classification.Severity,
				SeverityScore: classification.SeverityScore,
				Confirmed:     confirmed,
			})

			time.Sleep(800 * time.Millisecond)
		}
	}

	// ── Phase 3: Scoring ──────────────────────────────────────────
	publishPhaseUpdate(ctx, sessionID, "score")
	publishAttackEvent(ctx, sessionID, "info", "📊 Computing final risk score...")
	time.Sleep(500 * time.Millisecond)

	callFinalScoring(ctx, sessionID, baseURL, findings, collector)

	// Cleanup
	reconData.Delete(sessionID)
}

func buildAttackURL(baseURL, category, payload string) string {
	switch category {
	case "SQL Injection":
		return fmt.Sprintf("%s/?id=%s", baseURL, payload)
	case "Cross-Site Scripting (XSS)":
		return fmt.Sprintf("%s/?search=%s", baseURL, payload)
	case "Path Traversal / LFI":
		return fmt.Sprintf("%s/%s", baseURL, payload)
	case "Information Disclosure", "Security Misconfiguration":
		return fmt.Sprintf("%s%s", baseURL, payload)
	default:
		return fmt.Sprintf("%s/%s", baseURL, payload)
	}
}

func fireMLPayload(ctx context.Context, sessionID, category, targetURL, payload string) (result string, httpStatus int, confirmed bool) {
	publishAttackEvent(ctx, sessionID, "attack",
		fmt.Sprintf("Executing [%s] → %s", category, payload))

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(targetURL)

	if err != nil {
		publishAttackEvent(ctx, sessionID, "error",
			fmt.Sprintf("[%s] Connection failed: %v", category, err))
		return fmt.Sprintf("Connection failed: %v", err), 0, false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := string(bodyBytes)
	httpStatus = resp.StatusCode

	// Detection heuristics
	confirmed = false
	switch category {
	case "SQL Injection":
		sqlKeywords := []string{"SQL syntax", "mysql", "PostgreSQL", "ORA-", "sqlite", "syntax error", "query failed"}
		for _, kw := range sqlKeywords {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(kw)) {
				confirmed = true
				break
			}
		}
	case "Cross-Site Scripting (XSS)":
		if strings.Contains(bodyStr, payload) {
			confirmed = true
		}
	case "Path Traversal / LFI":
		traversalKeywords := []string{"root:x:0:0:", "[boot loader]", "\\windows\\"}
		for _, kw := range traversalKeywords {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(kw)) {
				confirmed = true
				break
			}
		}
	case "Information Disclosure":
		if resp.StatusCode == 200 {
			infoKeywords := []string{"DB_", "SECRET", "PASSWORD", "API_KEY", "[core]", "<?php"}
			for _, kw := range infoKeywords {
				if strings.Contains(bodyStr, kw) {
					confirmed = true
					break
				}
			}
		}
	}

	if confirmed {
		publishAttackEvent(ctx, sessionID, "critical",
			fmt.Sprintf("🔴 VULNERABILITY CONFIRMED: [%s] Exploit succeeded!", category))
		result = fmt.Sprintf("Vulnerability confirmed — payload reflected/matched in response (HTTP %d)", httpStatus)
	} else if resp.StatusCode == 200 {
		publishAttackEvent(ctx, sessionID, "warning",
			fmt.Sprintf("⚠️ [%s] HTTP 200 returned — needs manual review", category))
		result = fmt.Sprintf("HTTP 200 returned, no definitive match (possible false positive)")
	} else {
		publishAttackEvent(ctx, sessionID, "info",
			fmt.Sprintf("✓ [%s] Blocked or unaffected (HTTP %d)", category, resp.StatusCode))
		result = fmt.Sprintf("Blocked or unaffected (HTTP %d)", httpStatus)
	}

	return result, httpStatus, confirmed
}

func classifyFinding(ctx context.Context, sessionID, vulnType, attackResult string, httpStatus int, confidence float64, targetURL string) *ClassifyResponse {
	classification, err := callClassify(sessionID, vulnType, attackResult, httpStatus, confidence, targetURL)
	if err != nil {
		log.Printf("[attack-orchestrator] LLM Classifier error: %v, using defaults", err)
		return &ClassifyResponse{
			Severity:      "MEDIUM",
			SeverityScore: 5.0,
			Description:   "Classification unavailable — using default severity",
			Remediation:   "Manual review recommended",
			ClassifiedBy:  "fallback",
		}
	}

	publishAttackEvent(ctx, sessionID, "llm-classification",
		fmt.Sprintf("🏷️ [%s] Severity: %s (%.1f/10) — %s [via %s]",
			vulnType, classification.Severity, classification.SeverityScore,
			classification.Description, classification.ClassifiedBy))

	return classification
}

func callFinalScoring(ctx context.Context, sessionID, targetURL string, findings []ScoreFinding, collector *ReconCollector) {
	scoreResult, err := callScoring(sessionID, targetURL, findings, collector)
	if err != nil {
		log.Printf("[attack-orchestrator] Scoring Engine error: %v", err)
		publishAttackEvent(ctx, sessionID, "error", fmt.Sprintf("Scoring Engine unavailable: %v", err))
		publishAttackEvent(ctx, sessionID, "success", "Assessment complete (scoring unavailable).")
		publishPhaseUpdate(ctx, sessionID, "report")
		return
	}

	publishAttackEvent(ctx, sessionID, "risk-score",
		fmt.Sprintf("📋 RISK SCORE: %.1f/10 (%s) — Grade: %s",
			scoreResult.RiskScore, scoreResult.RiskLevel, scoreResult.RiskGrade))
	time.Sleep(300 * time.Millisecond)
	publishAttackEvent(ctx, sessionID, "info", fmt.Sprintf("Summary: %s", scoreResult.Summary))
	publishAttackEvent(ctx, sessionID, "success", "✅ ML-powered assessment complete.")
	publishPhaseUpdate(ctx, sessionID, "report")
}

// ---------------------------------------------------------------------------
// Static Attack Fallback (if ML Engine is down)
// ---------------------------------------------------------------------------
func executeStaticAttacks(ctx context.Context, sessionID, baseURL string) {
	publishPhaseUpdate(ctx, sessionID, "attack")
	publishAttackEvent(ctx, sessionID, "warning", "⚠️ Running static fallback attacks (ML Engine unavailable)")
	time.Sleep(1 * time.Second)

	fireStaticPayload(ctx, sessionID, "Info Disclosure", baseURL+"/.env", "DB_PASSWORD")
	time.Sleep(1 * time.Second)
	fireStaticPayload(ctx, sessionID, "Path Traversal", baseURL+"/../../../../etc/passwd", "root:x:0:0:")
	time.Sleep(1 * time.Second)
	fireStaticPayload(ctx, sessionID, "SQLi Probe", baseURL+"/?id=1'+OR+'1'='1", "syntax error")
	time.Sleep(1 * time.Second)
	fireStaticPayload(ctx, sessionID, "XSS Probe", baseURL+"/?search=<script>alert('SPECTRE')</script>", "<script>alert('SPECTRE')</script>")
	time.Sleep(1 * time.Second)

	publishAttackEvent(ctx, sessionID, "success", "Static fallback attacks completed.")
	publishPhaseUpdate(ctx, sessionID, "score")
	publishPhaseUpdate(ctx, sessionID, "report")
}

func fireStaticPayload(ctx context.Context, sessionID, attackName, targetURL, errorSignature string) {
	publishAttackEvent(ctx, sessionID, "attack", fmt.Sprintf("Executing [%s] on %s", attackName, targetURL))

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(targetURL)

	if err != nil {
		publishAttackEvent(ctx, sessionID, "error", fmt.Sprintf("[%s] Connection failed: %v", attackName, err))
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	if strings.Contains(bodyStr, errorSignature) || resp.StatusCode == 200 {
		if attackName == "Info Disclosure" && resp.StatusCode == 200 {
			publishAttackEvent(ctx, sessionID, "critical", fmt.Sprintf("VULNERABILITY FOUND: [%s] Endpoint exposed!", attackName))
		} else if strings.Contains(bodyStr, errorSignature) {
			publishAttackEvent(ctx, sessionID, "critical", fmt.Sprintf("VULNERABILITY FOUND: [%s] Signature matched!", attackName))
		} else {
			publishAttackEvent(ctx, sessionID, "warning", fmt.Sprintf("[%s] returned HTTP %d, needs manual review.", attackName, resp.StatusCode))
		}
	} else {
		publishAttackEvent(ctx, sessionID, "info", fmt.Sprintf("[%s] Blocked or unaffected (HTTP %d).", attackName, resp.StatusCode))
	}
}

// ---------------------------------------------------------------------------
// Redis publishers
// BUG FIX: Publish to "attack-results" NOT "recon-results" — the old code
// caused a feedback loop because the orchestrator subscribes to recon-results.
// ---------------------------------------------------------------------------
func publishAttackEvent(ctx context.Context, sessionID, severity, message string) {
	_, err := redisClient.Publish(ctx, "attack-results", map[string]interface{}{
		"session_id": sessionID,
		"type":       severity,
		"message":    message,
		"timestamp":  time.Now().Format(time.RFC3339Nano),
	})
	if err != nil {
		log.Printf("Failed to publish attack event: %v", err)
	}
}

func publishPhaseUpdate(ctx context.Context, sessionID, newPhase string) {
	_, _ = redisClient.Publish(ctx, "session-state", map[string]interface{}{
		"session_id": sessionID,
		"phase":      newPhase,
	})
}
