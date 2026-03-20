package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
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
	intelServiceURL  = getEnv("INTEL_SERVICE_URL", "http://localhost:5004")
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
	mu                       sync.Mutex
	OpenPorts                []int               `json:"open_ports"`
	MissingHeaders           []string            `json:"missing_headers"`
	TLSVersion               string              `json:"tls_version"`
	TLSAvailable             bool                `json:"tls_available"`
	ServerHeader             string              `json:"server_header"`
	XPoweredBy               string              `json:"x_powered_by"`
	ErrorProbeSQLi           bool                `json:"error_probe_sqli"`
	ErrorProbeTraversal      bool                `json:"error_probe_traversal"`
	StackTraceDetected       bool                `json:"stack_trace_detected"`
	RobotsFound              bool                `json:"robots_found"`
	DisallowedPaths          []string            `json:"disallowed_paths"`
	TotalOpenPorts           int                 `json:"total_open_ports"`
	RiskyPortsOpen           int                 `json:"risky_ports_open"`
	URLClassification        string              `json:"url_classification"`
	ClassificationConfidence float64             `json:"classification_confidence"`
	BackendEndpoints         []BackendEndpoint   `json:"backend_endpoints"`
	BackendEndpointCount     int                 `json:"backend_endpoint_count"`
	RESTEndpointCount        int                 `json:"rest_endpoint_count"`
	GraphQLEndpointCount     int                 `json:"graphql_endpoint_count"`
	IDORCandidateCount       int                 `json:"idor_candidate_count"`
	AuthSurfaceCount         int                 `json:"auth_surface_count"`
	ConsentRequired          bool                `json:"consent_required"`
	ConsentResolved          bool                `json:"consent_resolved"`
	ConsentApproved          bool                `json:"consent_approved"`
	ConsentMessage           string              `json:"consent_message"`
	ApprovedEndpoints        map[string]bool     `json:"-"`
	ServiceInventory         []DiscoveredService `json:"service_inventory"`
	ApprovedServices         map[string]bool     `json:"-"`
	AllowLogs                bool                `json:"allow_logs"`
	SelectedLogSources       []string            `json:"selected_log_sources"`
	LogSignals               LogSignals          `json:"log_signals"`
	RequestCount             int                 `json:"request_count"`
}

type BackendEndpoint struct {
	DiscoveredEndpoint string  `json:"discovered_endpoint"`
	Normalized         string  `json:"normalized"`
	Source             string  `json:"source"`
	Confidence         float64 `json:"confidence"`
	APIType            string  `json:"api_type"`
}

type DiscoveredService struct {
	Address     string  `json:"address"`
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	Type        string  `json:"service_type"`
	Relation    string  `json:"relation"`
	Confidence  float64 `json:"confidence"`
	Source      string  `json:"source"`
	Reason      string  `json:"reason"`
	Selectable  bool    `json:"selectable"`
	Recommended bool    `json:"recommended"`
	Internal    bool    `json:"internal"`
}

type AttackPlan struct {
	Category  string
	Name      string
	Tool      string
	TargetURL string
	Reason    string
	Priority  int
	Command   []string
}

var reconData sync.Map // sessionID -> *ReconCollector
var pendingTargets sync.Map

func getCollector(sessionID string) *ReconCollector {
	val, loaded := reconData.LoadOrStore(sessionID, &ReconCollector{
		TLSAvailable:       true,
		OpenPorts:          []int{},
		MissingHeaders:     []string{},
		DisallowedPaths:    []string{},
		BackendEndpoints:   []BackendEndpoint{},
		ApprovedEndpoints:  make(map[string]bool),
		ServiceInventory:   []DiscoveredService{},
		ApprovedServices:   make(map[string]bool),
		SelectedLogSources: []string{},
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
	event, _ := data["event"].(string)
	eventType, _ := data["type"].(string)

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

	case "classification":
		if class, ok := data["class"].(string); ok && class != "" {
			c.URLClassification = class
		}
		if confidence, ok := data["confidence"].(float64); ok {
			c.ClassificationConfidence = confidence
		}

	case "behavior-discovery":
		if requestCount, ok := toInt(data["request_count"]); ok {
			c.RequestCount = requestCount
		}

	case "infrastructure-consent":
		if required, ok := data["required"].(bool); ok {
			c.ConsentRequired = required
		}
		if message, ok := data["message"].(string); ok {
			c.ConsentMessage = message
		}
		if services, ok := data["services"].([]interface{}); ok {
			for _, raw := range services {
				serviceMap, ok := raw.(map[string]interface{})
				if !ok {
					continue
				}
				service := DiscoveredService{}
				if address, ok := serviceMap["address"].(string); ok {
					service.Address = address
				}
				if host, ok := serviceMap["host"].(string); ok {
					service.Host = host
				}
				if port, ok := toInt(serviceMap["port"]); ok {
					service.Port = port
				}
				if serviceType, ok := serviceMap["type"].(string); ok {
					service.Type = serviceType
				} else if serviceType, ok := serviceMap["service_type"].(string); ok {
					service.Type = serviceType
				}
				if relation, ok := serviceMap["relation"].(string); ok {
					service.Relation = relation
				}
				if confidence, ok := serviceMap["confidence"].(float64); ok {
					service.Confidence = confidence
				}
				if source, ok := serviceMap["source"].(string); ok {
					service.Source = source
				}
				if reason, ok := serviceMap["reason"].(string); ok {
					service.Reason = reason
				}
				if selectable, ok := serviceMap["selectable"].(bool); ok {
					service.Selectable = selectable
				}
				if recommended, ok := serviceMap["recommended"].(bool); ok {
					service.Recommended = recommended
				}
				if internal, ok := serviceMap["internal"].(bool); ok {
					service.Internal = internal
				}
				if service.Address != "" {
					known := false
					for _, existing := range c.ServiceInventory {
						if existing.Address == service.Address {
							known = true
							break
						}
					}
					if !known {
						c.ServiceInventory = append(c.ServiceInventory, service)
					}
				}
			}
		}
	}

	if eventType == "service-discovery" {
		service := DiscoveredService{}
		if address, ok := data["address"].(string); ok {
			service.Address = address
		}
		if host, ok := data["host"].(string); ok {
			service.Host = host
		}
		if port, ok := toInt(data["port"]); ok {
			service.Port = port
		}
		if serviceType, ok := data["service_type"].(string); ok {
			service.Type = serviceType
		}
		if relation, ok := data["relation"].(string); ok {
			service.Relation = relation
		}
		if confidence, ok := data["confidence"].(float64); ok {
			service.Confidence = confidence
		}
		if source, ok := data["source"].(string); ok {
			service.Source = source
		}
		if reason, ok := data["reason"].(string); ok {
			service.Reason = reason
		}
		if selectable, ok := data["selectable"].(bool); ok {
			service.Selectable = selectable
		}
		if recommended, ok := data["recommended"].(bool); ok {
			service.Recommended = recommended
		}
		if internal, ok := data["internal"].(bool); ok {
			service.Internal = internal
		}
		if service.Address != "" {
			known := false
			for _, existing := range c.ServiceInventory {
				if existing.Address == service.Address {
					known = true
					break
				}
			}
			if !known {
				c.ServiceInventory = append(c.ServiceInventory, service)
			}
		}
	}

	if event == "rasm_discovery" || eventType == "backend-api" {
		endpoint := BackendEndpoint{}
		if fullURL, ok := data["discovered_endpoint"].(string); ok {
			endpoint.DiscoveredEndpoint = fullURL
		}
		if normalized, ok := data["normalized"].(string); ok {
			endpoint.Normalized = normalized
		}
		if source, ok := data["source"].(string); ok {
			endpoint.Source = source
		}
		if confidence, ok := data["confidence"].(float64); ok {
			endpoint.Confidence = confidence
		}
		if apiType, ok := data["api_type"].(string); ok {
			endpoint.APIType = apiType
		}
		if endpoint.Normalized != "" {
			known := false
			for _, existing := range c.BackendEndpoints {
				if existing.Normalized == endpoint.Normalized {
					known = true
					break
				}
			}
			if !known {
				c.BackendEndpoints = append(c.BackendEndpoints, endpoint)
				c.BackendEndpointCount = len(c.BackendEndpoints)
				if endpoint.APIType == "graphql" {
					c.GraphQLEndpointCount++
				}
				if endpoint.APIType == "rest" {
					c.RESTEndpointCount++
				}
				lowerURL := strings.ToLower(endpoint.Normalized)
				if strings.Contains(lowerURL, "id=") || strings.Contains(lowerURL, "/users/") || strings.Contains(lowerURL, "/orders/") || strings.Contains(lowerURL, "/accounts/") {
					c.IDORCandidateCount++
				}
				if strings.Contains(lowerURL, "login") || strings.Contains(lowerURL, "auth") || strings.Contains(lowerURL, "token") || strings.Contains(lowerURL, "session") {
					c.AuthSurfaceCount++
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

func toBool(v interface{}) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		switch strings.ToLower(strings.TrimSpace(b)) {
		case "true", "1", "yes":
			return true, true
		case "false", "0", "no":
			return false, true
		}
	}
	return false, false
}

func parseSelectedEndpoints(raw interface{}) []string {
	switch v := raw.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		var parsed []string
		if err := json.Unmarshal([]byte(v), &parsed); err == nil {
			return parsed
		}
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		return out
	default:
		return nil
	}
}

func applyApprovedEndpoints(c *ReconCollector, selected []string) {
	selectedSet := make(map[string]bool, len(selected))
	for _, endpoint := range selected {
		selectedSet[endpoint] = true
	}

	if len(selectedSet) == 0 {
		c.BackendEndpoints = []BackendEndpoint{}
		c.BackendEndpointCount = 0
		c.RESTEndpointCount = 0
		c.GraphQLEndpointCount = 0
		c.IDORCandidateCount = 0
		c.AuthSurfaceCount = 0
		c.ApprovedEndpoints = selectedSet
		return
	}

	filtered := make([]BackendEndpoint, 0, len(c.BackendEndpoints))
	restCount := 0
	graphqlCount := 0
	idorCount := 0
	authCount := 0
	for _, endpoint := range c.BackendEndpoints {
		if !selectedSet[endpoint.Normalized] && !selectedSet[endpoint.DiscoveredEndpoint] {
			continue
		}
		filtered = append(filtered, endpoint)
		if endpoint.APIType == "graphql" {
			graphqlCount++
		}
		if endpoint.APIType == "rest" {
			restCount++
		}
		lowerURL := strings.ToLower(endpoint.Normalized)
		if strings.Contains(lowerURL, "id=") || strings.Contains(lowerURL, "/users/") || strings.Contains(lowerURL, "/orders/") || strings.Contains(lowerURL, "/accounts/") {
			idorCount++
		}
		if strings.Contains(lowerURL, "login") || strings.Contains(lowerURL, "auth") || strings.Contains(lowerURL, "token") || strings.Contains(lowerURL, "session") {
			authCount++
		}
	}

	c.BackendEndpoints = filtered
	c.BackendEndpointCount = len(filtered)
	c.RESTEndpointCount = restCount
	c.GraphQLEndpointCount = graphqlCount
	c.IDORCandidateCount = idorCount
	c.AuthSurfaceCount = authCount
	c.ApprovedEndpoints = selectedSet
}

func applyApprovedServices(c *ReconCollector, selected []string) {
	selectedSet := make(map[string]bool, len(selected))
	for _, service := range selected {
		selectedSet[service] = true
	}
	c.ApprovedServices = selectedSet
}

// ---------------------------------------------------------------------------
// ML Engine / LLM Classifier / Scoring Engine HTTP Clients
// ---------------------------------------------------------------------------
type MLPrediction struct {
	Category            string   `json:"category"`
	Confidence          float64  `json:"confidence"`
	Reasoning           string   `json:"reasoning"`
	RecommendedPayloads []string `json:"recommended_payloads"`
}

type MLPredictionResponse struct {
	SessionID     string                 `json:"session_id"`
	Predictions   []MLPrediction         `json:"predictions"`
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
	RiskScore  float64 `json:"risk_score"`
	RiskLevel  string  `json:"risk_level"`
	RiskGrade  string  `json:"risk_grade"`
	EBSSScore  int     `json:"ebss_score"`
	EBSSGrade  string  `json:"ebss_grade"`
	Priority   string  `json:"priority"`
	Confidence float64 `json:"confidence"`
	Summary    string  `json:"summary"`
}

type IntelResponse struct {
	SessionID             string                   `json:"session_id"`
	HighestEPSS           float64                  `json:"highest_epss"`
	KEVCount              int                      `json:"kev_count"`
	ExploitReferenceCount int                      `json:"exploit_reference_count"`
	Priority              string                   `json:"priority"`
	PriorityScore         float64                  `json:"priority_score"`
	Rationale             string                   `json:"rationale"`
	CVEs                  []string                 `json:"cves"`
	IntelItems            []map[string]interface{} `json:"intel_items"`
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

func callMLPredict(sessionID string, collector *ReconCollector) (*MLPredictionResponse, error) {
	collector.mu.Lock()
	backendEndpoints := append([]BackendEndpoint{}, collector.BackendEndpoints...)
	serviceInventory := append([]DiscoveredService{}, collector.ServiceInventory...)
	payload := map[string]interface{}{
		"session_id":                sessionID,
		"open_ports":                collector.OpenPorts,
		"missing_headers":           collector.MissingHeaders,
		"tls_version":               collector.TLSVersion,
		"tls_available":             collector.TLSAvailable,
		"server_header":             collector.ServerHeader,
		"x_powered_by":              collector.XPoweredBy,
		"error_probe_sqli":          collector.ErrorProbeSQLi,
		"error_probe_traversal":     collector.ErrorProbeTraversal,
		"stack_trace_detected":      collector.StackTraceDetected,
		"robots_found":              collector.RobotsFound,
		"disallowed_paths":          collector.DisallowedPaths,
		"url_classification":        collector.URLClassification,
		"classification_confidence": collector.ClassificationConfidence,
		"backend_endpoints":         backendEndpoints,
		"backend_endpoint_count":    collector.BackendEndpointCount,
		"rest_endpoint_count":       collector.RESTEndpointCount,
		"graphql_endpoint_count":    collector.GraphQLEndpointCount,
		"idor_candidate_count":      collector.IDORCandidateCount,
		"auth_surface_count":        collector.AuthSurfaceCount,
		"service_inventory":         serviceInventory,
		"service_count":             len(serviceInventory),
		"backend_service_count":     countServicesByType(serviceInventory, "backend"),
		"db_service_count":          countServicesByType(serviceInventory, "database"),
		"external_service_count":    countExternalServices(serviceInventory),
		"log_signals":               collector.LogSignals,
		"logs_enabled":              collector.AllowLogs,
		"request_count":             collector.RequestCount,
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

func callClassify(sessionID, vulnType, attackResult string, httpStatus int, confidence float64, targetURL, urlClassification string) (*ClassifyResponse, error) {
	payload := map[string]interface{}{
		"session_id":         sessionID,
		"vulnerability_type": vulnType,
		"attack_result":      attackResult,
		"http_status":        httpStatus,
		"confidence":         confidence,
		"target_url":         targetURL,
		"url_classification": urlClassification,
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

func callScoring(sessionID, targetURL string, findings []ScoreFinding, collector *ReconCollector, intel *IntelResponse) (*ScoreResponse, error) {
	collector.mu.Lock()
	serviceCount := len(collector.ServiceInventory)
	apiCount := collector.BackendEndpointCount
	payload := map[string]interface{}{
		"session_id":               sessionID,
		"target_url":               targetURL,
		"findings":                 findings,
		"missing_security_headers": len(collector.MissingHeaders),
		"weak_tls":                 collector.TLSVersion == "TLS 1.0" || collector.TLSVersion == "TLS 1.1" || !collector.TLSAvailable,
		"total_open_ports":         collector.TotalOpenPorts,
		"risky_ports_open":         collector.RiskyPortsOpen,
		"service_count":            serviceCount,
		"api_count":                apiCount,
		"request_count":            collector.RequestCount,
		"error_rate":               collector.LogSignals.ErrorRate,
		"auth_failures":            collector.LogSignals.AuthFailures,
		"db_errors":                collector.LogSignals.DBErrors,
		"anomaly_count":            collector.LogSignals.AnomalyCount,
		"request_spikes":           collector.LogSignals.RequestSpikes,
	}
	collector.mu.Unlock()
	if intel != nil {
		payload["epss_score"] = intel.HighestEPSS
		payload["kev_hits"] = intel.KEVCount
		payload["exploit_references"] = intel.ExploitReferenceCount
	}

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

func callIntel(sessionID, targetURL, attackEvidence string, findings []ScoreFinding) (*IntelResponse, error) {
	if intelServiceURL == "" {
		return nil, nil
	}
	categories := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding.Type != "" {
			categories = append(categories, finding.Type)
		}
	}
	payload := map[string]interface{}{
		"session_id":    sessionID,
		"target_url":    targetURL,
		"finding_type":  strings.Join(categories, ", "),
		"attack_result": attackEvidence,
	}
	body, _ := json.Marshal(payload)
	resp, err := httpClient.Post(intelServiceURL+"/intel", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("intel service returned %d: %s", resp.StatusCode, string(b))
	}
	var result IntelResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
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
			pendingTargets.Delete(sessionID)
			return nil
		})
		if err != nil {
			log.Printf("[attack-orchestrator] session-stop stream error: %v", err)
		}
	}()

	// 2b. Listen for consent decisions before deeper server-side verification
	go func() {
		log.Println("[attack-orchestrator] listening for session-consent...")
		err := redisClient.Subscribe(ctx, "session-consent", "atk-consent-group", "atk-consent-"+workerID, func(msg spectreRedis.StreamMessage) error {
			sessionID, _ := msg.Data["session_id"].(string)
			action, _ := msg.Data["action"].(string)
			selectedEndpoints := parseSelectedEndpoints(msg.Data["selected_endpoints"])
			selectedServices := parseSelectedEndpoints(msg.Data["selected_services"])
			selectedLogSources := parseSelectedEndpoints(msg.Data["selected_log_sources"])
			allowLogs, _ := toBool(msg.Data["allow_logs"])
			if sessionID == "" || action == "" {
				return nil
			}

			collector := getCollector(sessionID)
			collector.mu.Lock()
			collector.ConsentResolved = true
			collector.ConsentApproved = action == "approve"
			if action == "approve" {
				applyApprovedEndpoints(collector, selectedEndpoints)
				applyApprovedServices(collector, selectedServices)
				collector.AllowLogs = allowLogs
				collector.SelectedLogSources = selectedLogSources
			}
			collector.mu.Unlock()

			targetVal, hasPending := pendingTargets.LoadAndDelete(sessionID)
			if !hasPending {
				return nil
			}

			targetURL := targetVal.(string)
			if action == "approve" {
				log.Printf("[attack-orchestrator] consent approved for session %s", sessionID)
				publishAttackEvent(ctx, sessionID, "info", fmt.Sprintf("Scope approved. Proceeding with %d endpoint(s), %d service(s), logs=%t.", len(selectedEndpoints), len(selectedServices), allowLogs))
				publishPhaseUpdate(ctx, sessionID, "ml-analysis")
				sessionCtx, cancel := context.WithCancel(ctx)
				sessionCtxs.Store(sessionID, cancel)
				go func() {
					defer cancel()
					defer sessionCtxs.Delete(sessionID)
					runMLPipeline(sessionCtx, sessionID, targetURL)
				}()
			} else {
				log.Printf("[attack-orchestrator] consent declined for session %s", sessionID)
				publishAttackEvent(ctx, sessionID, "warning", "Consent declined. Skipping backend attack phase and ending with recon-only results.")
				publishPhaseUpdate(ctx, sessionID, "report")
				reconData.Delete(sessionID)
				sessionCtxs.Delete(sessionID)
			}
			return nil
		})
		if err != nil {
			log.Printf("[attack-orchestrator] session-consent stream error: %v", err)
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

		// Collect recon data as it streams in, including consent and endpoint discoveries.
		if eventType == "recon" || eventType == "warning" || eventType == "consent-required" || eventType == "backend-api" || eventType == "service-discovery" {
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
			collector := getCollector(sessionID)
			collector.mu.Lock()
			consentRequired := collector.ConsentRequired
			consentResolved := collector.ConsentResolved
			consentApproved := collector.ConsentApproved
			consentMessage := collector.ConsentMessage
			collector.mu.Unlock()

			if (collector.BackendEndpointCount > 0 || consentRequired) && !consentResolved {
				pendingTargets.Store(sessionID, targetURL)
				publishPhaseUpdate(ctx, sessionID, "consent")
				if consentMessage == "" {
					consentMessage = "Endpoint discovery completed. Review discovered scope and approve only the endpoints you want SPECTRE to test."
				}
				publishAttackEvent(ctx, sessionID, "warning", consentMessage)
				publishAttackEvent(ctx, sessionID, "info", "Waiting for user scope selection before deep scan continues.")
				return nil
			}

			if consentRequired && consentResolved && !consentApproved {
				publishAttackEvent(ctx, sessionID, "warning", "Consent not granted. Ending after reconnaissance.")
				publishPhaseUpdate(ctx, sessionID, "report")
				return nil
			}

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
	if collector.AllowLogs && len(collector.SelectedLogSources) > 0 {
		publishAttackEvent(ctx, sessionID, "info", fmt.Sprintf("Collecting approved logs from %d selected service(s)...", len(collector.ApprovedServices)))
		signals := collectApprovedLogs(ctx, sessionID, targetURL, collector)
		collector.mu.Lock()
		collector.LogSignals = signals
		collector.mu.Unlock()
		publishAttackEvent(ctx, sessionID, "info", fmt.Sprintf("Log analysis captured %d events, %d anomaly signal(s), %d DB error(s).", signals.TotalEntries, signals.AnomalyCount, signals.DBErrors))
	}
	publishAttackEvent(ctx, sessionID, "info", "🧠 Sending recon data to ML Engine for vulnerability prediction...")
	publishServiceMetric(ctx, sessionID, "attack-orchestrator", "ml-analysis", "Collecting Model 1 features from recon output", map[string]interface{}{
		"backend_endpoints": collector.BackendEndpointCount,
		"service_count":     len(collector.ServiceInventory),
		"logs_enabled":      collector.AllowLogs,
		"load_pct":          61,
	})
	time.Sleep(500 * time.Millisecond)

	mlResult, err := callMLPredict(sessionID, collector)
	if err != nil {
		publishAttackEvent(ctx, sessionID, "error", fmt.Sprintf("ML Engine unavailable: %v. Falling back to static attacks.", err))
		// Fallback: run static attacks if ML Engine is down
		executeStaticAttacks(ctx, sessionID, baseURL, collector)
		return
	}

	if len(mlResult.Predictions) == 0 {
		publishAttackEvent(ctx, sessionID, "success", "✅ ML Engine found no likely vulnerabilities. Target appears secure.")
		publishPhaseUpdate(ctx, sessionID, "score")
		callFinalScoring(ctx, sessionID, baseURL, nil, collector, "")
		return
	}

	publishAttackEvent(ctx, sessionID, "info", fmt.Sprintf("🎯 ML Engine predicted %d vulnerability categories", len(mlResult.Predictions)))
	time.Sleep(500 * time.Millisecond)

	for _, pred := range mlResult.Predictions {
		publishAttackEvent(ctx, sessionID, "ml-prediction",
			fmt.Sprintf("[%.0f%% confidence] %s — %s", pred.Confidence*100, pred.Category, pred.Reasoning))
		time.Sleep(300 * time.Millisecond)
	}

	// ── Phase 2: Model 2 attack planning and optional execution ─────
	publishPhaseUpdate(ctx, sessionID, "attack")
	publishAttackEvent(ctx, sessionID, "info", "🔍 Prioritizing backend attack paths for discovered APIs...")
	publishServiceMetric(ctx, sessionID, "attack-orchestrator", "attack", "Model 2 prioritized API attack plans", map[string]interface{}{
		"backend_endpoints": collector.BackendEndpointCount,
		"graphql_endpoints": collector.GraphQLEndpointCount,
		"rest_endpoints":    collector.RESTEndpointCount,
		"load_pct":          57,
	})
	time.Sleep(1 * time.Second)

	plans := buildAttackPlans(baseURL, collector, mlResult.Predictions)
	for _, plan := range plans {
		publishAttackEvent(ctx, sessionID, "attack",
			fmt.Sprintf("[P%d] %s via %s → %s", plan.Priority, plan.Name, strings.ToUpper(plan.Tool), plan.TargetURL))
	}

	findings := make([]ScoreFinding, 0, len(mlResult.Predictions))
	attackEvidence := make([]string, 0, len(mlResult.Predictions))
	for _, pred := range mlResult.Predictions {
		if ctx.Err() != nil {
			publishAttackEvent(context.Background(), sessionID, "warning", "⛔ Assessment stopped by user.")
			publishPhaseUpdate(context.Background(), sessionID, "report")
			return
		}

		planResult, httpStatus, confirmed := executePlansForCategory(ctx, sessionID, pred.Category, plans)
		if planResult == "" {
			planResult = fmt.Sprintf("Model 2 prioritized no executable tool for %s; backend API focus retained in scoring.", pred.Category)
		}
		attackEvidence = append(attackEvidence, planResult)
		classification := classifyFinding(ctx, sessionID, pred.Category, planResult, httpStatus, pred.Confidence, baseURL, collector.URLClassification)
		findings = append(findings, ScoreFinding{
			Type:          pred.Category,
			Severity:      classification.Severity,
			SeverityScore: classification.SeverityScore,
			Confirmed:     confirmed,
		})

		time.Sleep(300 * time.Millisecond)
	}

	// ── Phase 3: Scoring ──────────────────────────────────────────
	publishPhaseUpdate(ctx, sessionID, "score")
	publishAttackEvent(ctx, sessionID, "info", "📊 Computing final risk score...")
	time.Sleep(500 * time.Millisecond)

	callFinalScoring(ctx, sessionID, baseURL, findings, collector, strings.Join(attackEvidence, "\n"))

	// Cleanup
	reconData.Delete(sessionID)
}

func buildAttackPlans(baseURL string, collector *ReconCollector, predictions []MLPrediction) []AttackPlan {
	collector.mu.Lock()
	defer collector.mu.Unlock()

	plans := []AttackPlan{}
	for _, pred := range predictions {
		switch pred.Category {
		case "SQL Injection":
			for _, endpoint := range collector.BackendEndpoints {
				if endpoint.APIType != "rest" {
					continue
				}
				if strings.Contains(endpoint.Normalized, "?") || strings.Contains(strings.ToLower(endpoint.Normalized), "id=") {
					plans = append(plans, AttackPlan{
						Category:  pred.Category,
						Name:      "SQLMap API probe",
						Tool:      "sqlmap",
						TargetURL: endpoint.DiscoveredEndpoint,
						Reason:    "Backend REST endpoint with parameter surface",
						Priority:  1,
						Command:   []string{"sqlmap", "-u", endpoint.DiscoveredEndpoint, "--batch", "--level=2", "--risk=1"},
					})
				}
			}
		case "Insecure Direct Object Reference (IDOR)", "Weak Authentication / Authorization":
			for _, endpoint := range collector.BackendEndpoints {
				lowerURL := strings.ToLower(endpoint.Normalized)
				if strings.Contains(lowerURL, "auth") || strings.Contains(lowerURL, "login") || strings.Contains(lowerURL, "token") || strings.Contains(lowerURL, "id=") || strings.Contains(lowerURL, "/users/") {
					plans = append(plans, AttackPlan{
						Category:  pred.Category,
						Name:      "Nuclei API auth template",
						Tool:      "nuclei",
						TargetURL: endpoint.DiscoveredEndpoint,
						Reason:    "Protected or object-oriented API path discovered in RASM",
						Priority:  2,
						Command:   []string{"nuclei", "-u", endpoint.DiscoveredEndpoint, "-tags", "auth,exposure,misconfig", "-severity", "medium,high,critical"},
					})
				}
			}
		}
	}

	for _, endpoint := range collector.BackendEndpoints {
		if endpoint.APIType == "graphql" {
			plans = append(plans, AttackPlan{
				Category:  "Weak Authentication / Authorization",
				Name:      "GraphQL introspection probe",
				Tool:      "graphql-probe",
				TargetURL: endpoint.DiscoveredEndpoint,
				Reason:    "GraphQL endpoint discovered during RASM",
				Priority:  1,
				Command:   []string{"POST", endpoint.DiscoveredEndpoint},
			})
		}
	}

	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].Priority == plans[j].Priority {
			return plans[i].TargetURL < plans[j].TargetURL
		}
		return plans[i].Priority < plans[j].Priority
	})
	if len(plans) > 12 {
		return plans[:12]
	}
	return plans
}

func executePlansForCategory(ctx context.Context, sessionID, category string, plans []AttackPlan) (string, int, bool) {
	var results []string
	httpStatus := 0
	confirmed := false

	for _, plan := range plans {
		if plan.Category != category {
			continue
		}
		result, status, ok := executeAttackPlan(ctx, sessionID, plan)
		if result != "" {
			results = append(results, result)
		}
		if status != 0 {
			httpStatus = status
		}
		if ok {
			confirmed = true
		}
	}

	return strings.Join(results, " | "), httpStatus, confirmed
}

func executeAttackPlan(ctx context.Context, sessionID string, plan AttackPlan) (string, int, bool) {
	switch plan.Tool {
	case "graphql-probe":
		return executeGraphQLProbe(ctx, sessionID, plan)
	}

	if _, err := exec.LookPath(plan.Tool); err != nil {
		msg := fmt.Sprintf("%s unavailable; skipped %s on %s", plan.Tool, plan.Name, plan.TargetURL)
		publishAttackEvent(ctx, sessionID, "warning", msg)
		return msg, 0, false
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, plan.Command[0], plan.Command[1:]...)
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		msg := fmt.Sprintf("%s failed on %s: %v", plan.Name, plan.TargetURL, err)
		publishAttackEvent(ctx, sessionID, "warning", msg)
		if text != "" {
			return msg + " | " + truncateText(text, 240), 0, false
		}
		return msg, 0, false
	}

	publishAttackEvent(ctx, sessionID, "info", fmt.Sprintf("%s completed on %s", plan.Name, plan.TargetURL))
	return fmt.Sprintf("%s on %s: %s", plan.Name, plan.TargetURL, truncateText(text, 240)), 200, true
}

func executeGraphQLProbe(ctx context.Context, sessionID string, plan AttackPlan) (string, int, bool) {
	payload := `{"query":"{__schema{types{name}}}"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, plan.TargetURL, strings.NewReader(payload))
	if err != nil {
		return fmt.Sprintf("GraphQL probe build failed: %v", err), 0, false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		msg := fmt.Sprintf("GraphQL probe failed on %s: %v", plan.TargetURL, err)
		publishAttackEvent(ctx, sessionID, "warning", msg)
		return msg, 0, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyText := string(body)
	confirmed := strings.Contains(bodyText, "__schema") || strings.Contains(strings.ToLower(bodyText), "introspection")
	if confirmed {
		publishAttackEvent(ctx, sessionID, "warning", fmt.Sprintf("GraphQL introspection exposed on %s", plan.TargetURL))
	}
	return fmt.Sprintf("GraphQL introspection probe on %s returned HTTP %d: %s", plan.TargetURL, resp.StatusCode, truncateText(bodyText, 220)), resp.StatusCode, confirmed
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

func classifyFinding(ctx context.Context, sessionID, vulnType, attackResult string, httpStatus int, confidence float64, targetURL, urlClassification string) *ClassifyResponse {
	classification, err := callClassify(sessionID, vulnType, attackResult, httpStatus, confidence, targetURL, urlClassification)
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

func callFinalScoring(ctx context.Context, sessionID, targetURL string, findings []ScoreFinding, collector *ReconCollector, attackEvidence string) {
	intelResult, intelErr := callIntel(sessionID, targetURL, attackEvidence, findings)
	if intelErr != nil {
		publishAttackEvent(ctx, sessionID, "warning", fmt.Sprintf("Threat intelligence enrichment unavailable: %v", intelErr))
	}
	scoreResult, err := callScoring(sessionID, targetURL, findings, collector, intelResult)
	if err != nil {
		log.Printf("[attack-orchestrator] Scoring Engine error: %v", err)
		publishAttackEvent(ctx, sessionID, "error", fmt.Sprintf("Scoring Engine unavailable: %v", err))
		publishAttackEvent(ctx, sessionID, "success", "Assessment complete (scoring unavailable).")
		publishPhaseUpdate(ctx, sessionID, "report")
		return
	}

	publishAttackEvent(ctx, sessionID, "risk-score",
		fmt.Sprintf("📋 RISK SCORE: %.1f/10 (%s) — Grade: %s | EBSS %d (%s, %s)",
			scoreResult.RiskScore, scoreResult.RiskLevel, scoreResult.RiskGrade, scoreResult.EBSSScore, scoreResult.EBSSGrade, scoreResult.Priority))
	publishServiceMetric(ctx, sessionID, "attack-orchestrator", "score", "Scoring finalized for session", map[string]interface{}{
		"risk_score": scoreResult.RiskScore,
		"risk_level": scoreResult.RiskLevel,
		"ebss_score": scoreResult.EBSSScore,
		"priority":   scoreResult.Priority,
		"load_pct":   28,
	})
	time.Sleep(300 * time.Millisecond)
	publishAttackEvent(ctx, sessionID, "info", fmt.Sprintf("Summary: %s", scoreResult.Summary))
	if intelResult != nil && intelResult.Priority != "" {
		publishAttackEvent(ctx, sessionID, "info", fmt.Sprintf("Threat intel: priority=%s, EPSS=%.3f, KEV hits=%d, exploit refs=%d", intelResult.Priority, intelResult.HighestEPSS, intelResult.KEVCount, intelResult.ExploitReferenceCount))
	}
	publishAttackEvent(ctx, sessionID, "success", "✅ ML-powered assessment complete.")
	publishPhaseUpdate(ctx, sessionID, "report")
}

// ---------------------------------------------------------------------------
// Static Attack Fallback (if ML Engine is down)
// ---------------------------------------------------------------------------
func executeStaticAttacks(ctx context.Context, sessionID, baseURL string, collector *ReconCollector) {
	publishPhaseUpdate(ctx, sessionID, "attack")
	publishAttackEvent(ctx, sessionID, "warning", "⚠️ Running behavior-constrained fallback attacks (ML Engine unavailable)")
	time.Sleep(1 * time.Second)

	plans := buildStaticFallbackPlans(collector)
	if len(plans) == 0 {
		publishAttackEvent(ctx, sessionID, "warning", "No approved observed endpoints are available for safe fallback probes. Skipping active attack execution.")
		publishPhaseUpdate(ctx, sessionID, "score")
		callFinalScoring(ctx, sessionID, baseURL, nil, collector, "")
		return
	}

	var findings []ScoreFinding
	var evidence []string
	for _, plan := range plans {
		if ctx.Err() != nil {
			publishAttackEvent(context.Background(), sessionID, "warning", "⛔ Assessment stopped by user.")
			publishPhaseUpdate(context.Background(), sessionID, "report")
			return
		}

		var (
			result    string
			httpCode  int
			confirmed bool
		)
		if plan.Tool == "graphql-probe" {
			result, httpCode, confirmed = executeGraphQLProbe(ctx, sessionID, plan)
		} else {
			result, httpCode, confirmed = fireStaticPayload(ctx, sessionID, plan.Name, plan.TargetURL, staticSignatureForPlan(plan))
		}
		evidence = append(evidence, result)
		findings = append(findings, ScoreFinding{
			Type:          staticFindingType(plan),
			Severity:      staticSeverity(confirmed),
			SeverityScore: staticSeverityScore(plan, confirmed, httpCode),
			Confirmed:     confirmed,
		})
		time.Sleep(500 * time.Millisecond)
	}

	publishAttackEvent(ctx, sessionID, "success", "Behavior-constrained fallback attacks completed.")
	publishPhaseUpdate(ctx, sessionID, "score")
	callFinalScoring(ctx, sessionID, baseURL, findings, collector, strings.Join(evidence, "\n"))
}

func buildStaticFallbackPlans(collector *ReconCollector) []AttackPlan {
	collector.mu.Lock()
	defer collector.mu.Unlock()

	plans := make([]AttackPlan, 0, len(collector.BackendEndpoints))
	seen := map[string]bool{}
	for _, endpoint := range collector.BackendEndpoints {
		normalized := strings.ToLower(endpoint.Normalized)
		switch {
		case endpoint.APIType == "graphql":
			key := "graphql:" + endpoint.DiscoveredEndpoint
			if seen[key] {
				continue
			}
			seen[key] = true
			plans = append(plans, AttackPlan{
				Category:  "Weak Authentication / Authorization",
				Name:      "GraphQL introspection probe",
				Tool:      "graphql-probe",
				TargetURL: endpoint.DiscoveredEndpoint,
				Reason:    "Observed GraphQL endpoint approved by the user",
				Priority:  1,
			})
		case endpoint.APIType == "rest" && (strings.Contains(endpoint.DiscoveredEndpoint, "?") || strings.Contains(normalized, "id=") || strings.Contains(normalized, "search=") || strings.Contains(normalized, "query=")):
			probeURL := mutateStaticProbeURL(endpoint.DiscoveredEndpoint)
			if probeURL == "" {
				continue
			}
			key := "sqli:" + probeURL
			if seen[key] {
				continue
			}
			seen[key] = true
			plans = append(plans, AttackPlan{
				Category:  "SQL Injection",
				Name:      "Observed API SQLi probe",
				Tool:      "static-http",
				TargetURL: probeURL,
				Reason:    "Observed REST endpoint with approved query surface",
				Priority:  1,
			})
		}
	}

	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].Priority == plans[j].Priority {
			return plans[i].TargetURL < plans[j].TargetURL
		}
		return plans[i].Priority < plans[j].Priority
	})
	return plans
}

func mutateStaticProbeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	query := parsed.Query()
	if len(query) == 0 {
		query.Set("id", "1' OR '1'='1")
	} else {
		for key := range query {
			query.Set(key, "1' OR '1'='1")
			break
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func staticSignatureForPlan(plan AttackPlan) string {
	switch plan.Name {
	case "Observed API SQLi probe":
		return "syntax error"
	default:
		return "__schema"
	}
}

func staticFindingType(plan AttackPlan) string {
	switch plan.Name {
	case "GraphQL introspection probe":
		return "Weak Authentication / Authorization"
	default:
		return plan.Category
	}
}

func staticSeverity(confirmed bool) string {
	if confirmed {
		return "HIGH"
	}
	return "LOW"
}

func staticSeverityScore(plan AttackPlan, confirmed bool, httpCode int) float64 {
	if confirmed {
		switch plan.Name {
		case "GraphQL introspection probe":
			return 7.2
		default:
			return 8.1
		}
	}
	if httpCode >= 500 {
		return 4.5
	}
	return 2.5
}

func fireStaticPayload(ctx context.Context, sessionID, attackName, targetURL, errorSignature string) (string, int, bool) {
	publishAttackEvent(ctx, sessionID, "attack", fmt.Sprintf("Executing [%s] on %s", attackName, targetURL))

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(targetURL)

	if err != nil {
		publishAttackEvent(ctx, sessionID, "error", fmt.Sprintf("[%s] Connection failed: %v", attackName, err))
		return fmt.Sprintf("%s failed: %v", attackName, err), 0, false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)
	confirmed := false

	if strings.Contains(bodyStr, errorSignature) || resp.StatusCode == 200 {
		if attackName == "Info Disclosure" && resp.StatusCode == 200 {
			publishAttackEvent(ctx, sessionID, "critical", fmt.Sprintf("VULNERABILITY FOUND: [%s] Endpoint exposed!", attackName))
			confirmed = true
		} else if strings.Contains(bodyStr, errorSignature) {
			publishAttackEvent(ctx, sessionID, "critical", fmt.Sprintf("VULNERABILITY FOUND: [%s] Signature matched!", attackName))
			confirmed = true
		} else {
			publishAttackEvent(ctx, sessionID, "warning", fmt.Sprintf("[%s] returned HTTP %d, needs manual review.", attackName, resp.StatusCode))
		}
	} else {
		publishAttackEvent(ctx, sessionID, "info", fmt.Sprintf("[%s] Blocked or unaffected (HTTP %d).", attackName, resp.StatusCode))
	}
	return fmt.Sprintf("%s returned HTTP %d: %s", attackName, resp.StatusCode, truncateText(bodyStr, 220)), resp.StatusCode, confirmed
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

func publishServiceMetric(ctx context.Context, sessionID, service, phase, impact string, extra map[string]interface{}) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	data := map[string]interface{}{
		"session_id":    sessionID,
		"service":       service,
		"phase":         phase,
		"impact":        impact,
		"type":          "service-metric",
		"goroutines":    runtime.NumGoroutine(),
		"heap_alloc_mb": float64(mem.Alloc) / 1024.0 / 1024.0,
		"sys_mb":        float64(mem.Sys) / 1024.0 / 1024.0,
		"timestamp":     time.Now().Format(time.RFC3339Nano),
	}
	for key, value := range extra {
		data[key] = value
	}
	_, _ = redisClient.Publish(ctx, "service-metrics", data)
}

func truncateText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
