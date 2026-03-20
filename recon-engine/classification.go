package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ClassificationResult struct {
	Class      string  `json:"class"`
	Confidence float64 `json:"confidence"`
	Details    string  `json:"details"`
}

// classifyTarget connects to the target, analyzes headers/body/JS/paths,
// determines the application type, and stores it in Redis.
func classifyTarget(ctx context.Context, sessionID, targetURL string) ClassificationResult {
	publishEvent(ctx, sessionID, "recon", "classification", fmt.Sprintf("Starting auto-classification for %s", targetURL), nil)

	result := ClassificationResult{
		Class:      "unknown",
		Confidence: 0.0,
		Details:    "",
	}

	client := newHTTPClient()
	baseURL := strings.TrimRight(targetURL, "/")

	// Concurrently test common paths
	paths := []string{"", "/api/", "/v1/", "/graphql", "/actuator", "/swagger", "/openapi"}
	pathResults := make(map[string]int)
	pathBodies := make(map[string]string)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, p := range paths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			reqURL := baseURL + path
			req, _ := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
			// Need a small timeout specific for these quick checks
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			req = req.WithContext(ctx)

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))

			mu.Lock()
			pathResults[path] = resp.StatusCode
			if path == "" {
				// Store root body and headers for analysis
				pathBodies["root"] = string(bodyBytes)

				// Header analysis
				for k, v := range resp.Header {
					pathBodies["header_"+k] = strings.Join(v, " ")
				}
			} else if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				pathBodies[path] = string(bodyBytes)
			}
			mu.Unlock()
		}(p)
	}

	wg.Wait()

	rootBody := strings.ToLower(pathBodies["root"])

	// Scoring system
	scores := map[string]float64{
		"frontend-only":        0.0,
		"api-only":             0.0,
		"full-backend":         0.0,
		"graphql":              0.0,
		"microservice-cluster": 0.0,
	}

	// 1. Check HTTP Headers
	// 'Server', 'X-Powered-By' can indicate full backend
	if server, ok := pathBodies["header_Server"]; ok {
		lowerServer := strings.ToLower(server)
		if strings.Contains(lowerServer, "apache") || strings.Contains(lowerServer, "nginx") {
			scores["full-backend"] += 0.2
			scores["frontend-only"] += 0.1 // CDNs often use these too
		}
	}

	if powered, ok := pathBodies["header_X-Powered-By"]; ok {
		lowerPowered := strings.ToLower(powered)
		if strings.Contains(lowerPowered, "express") || strings.Contains(lowerPowered, "php") || strings.Contains(lowerPowered, "asp.net") {
			scores["full-backend"] += 0.4
			scores["api-only"] += 0.2
		}
	}

	contentType := strings.ToLower(pathBodies["header_Content-Type"])
	if strings.Contains(contentType, "application/json") {
		scores["api-only"] += 0.5
	} else if strings.Contains(contentType, "text/html") {
		scores["frontend-only"] += 0.2
		scores["full-backend"] += 0.2
	}

	// 2. Analyse body and JS files for React/Vue/Angular/GraphQL signatures
	jsPatterns := []string{"vue.min.js", "react", "angular", "axios"}
	for _, pat := range jsPatterns {
		if strings.Contains(rootBody, pat) {
			scores["frontend-only"] += 0.3
		}
	}

	// Check if body has almost no HTML but loads big JS bundles (typical SPA)
	if strings.Contains(contentType, "text/html") && len(rootBody) < 2000 && strings.Contains(rootBody, "<script") {
		scores["frontend-only"] += 0.4
	}

	// 3. Response fingerprinting (GraphQL introspection hint, JSON-heavy responses)
	if strings.Contains(rootBody, "graphql") || strings.Contains(rootBody, "query") || strings.Contains(rootBody, "mutation") {
		scores["graphql"] += 0.3
	}

	// 4. Check common path patterns
	if status, ok := pathResults["/graphql"]; ok && status == 200 {
		body := strings.ToLower(pathBodies["/graphql"])
		if strings.Contains(body, "graphql") || strings.Contains(body, "must provide query") || strings.Contains(contentType, "json") {
			scores["graphql"] += 0.6
			scores["api-only"] += 0.2
		}
	}

	apiEndpoints := []string{"/api/", "/v1/"}
	apiFound := false
	for _, ep := range apiEndpoints {
		if status, ok := pathResults[ep]; ok && (status == 200 || status == 401 || status == 403 || status == 404) {
			body := strings.ToLower(pathBodies[ep])
			if strings.Contains(body, "json") || pathResults[ep] == 401 { // 401 usually means API
				scores["full-backend"] += 0.3
				scores["api-only"] += 0.2
				apiFound = true
			}
		}
	}

	if status, ok := pathResults["/actuator"]; ok && status == 200 {
		scores["microservice-cluster"] += 0.5
		scores["full-backend"] += 0.2
	}

	if status, ok := pathResults["/swagger"]; ok && status == 200 {
		scores["api-only"] += 0.4
		scores["full-backend"] += 0.2
	}

	if status, ok := pathResults["/openapi"]; ok && status == 200 {
		scores["api-only"] += 0.4
	}

	// Adjust logic based on combined factors
	if scores["api-only"] > 0 && !apiFound && scores["frontend-only"] > 0.5 {
		// Lots of JS, no API paths found -> strongly frontend
		scores["frontend-only"] += 0.2
	}

	// Determine max score
	maxClass := "unknown"
	maxScore := 0.0
	for class, score := range scores {
		if score > maxScore {
			maxScore = score
			maxClass = class
		}
	}

	// Normalize confidence to 0.0 - 1.0 (cap at 1.0)
	confidence := maxScore
	if confidence > 1.0 {
		confidence = 1.0
	} else if confidence == 0.0 {
		maxClass = "full-backend" // default assumption if nothing triggers
		confidence = 0.3          // low confidence
	}

	result.Class = maxClass
	result.Confidence = confidence
	result.Details = fmt.Sprintf("Scored based on HTTP patterns. JSON APIs: %v, SPA hints: %v", apiFound, scores["frontend-only"] > 0.4)

	// Publish to stream
	publishEvent(ctx, sessionID, "recon", "classification",
		fmt.Sprintf("Classified target as '%s' (confidence: %.2f)", result.Class, result.Confidence),
		map[string]interface{}{
			"class":      result.Class,
			"confidence": result.Confidence,
			"details":    result.Details,
		})

	// Store in Redis
	resultJSON, _ := json.Marshal(result)
	key := fmt.Sprintf("session:%s:classification", sessionID)
	err := redisClient.Set(ctx, key, resultJSON, 24*time.Hour)
	if err != nil {
		fmt.Printf("[recon-engine] error saving classification to redis: %v\n", err)
	}

	return result
}
