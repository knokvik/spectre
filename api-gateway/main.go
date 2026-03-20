package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	spectreRedis "github.com/spectre/pkg/redis"
)

//go:embed templates/*
var templateFS embed.FS

var (
	redisClient *spectreRedis.Client
	sessions    = &sync.Map{} // sessionID -> Session
	tmpl        *template.Template
)

// Session represents an active assessment session.
type Session struct {
	ID                     string    `json:"id"`
	TargetURL              string    `json:"target_url"`
	Scope                  string    `json:"scope"`
	Intensity              string    `json:"intensity"`
	Name                   string    `json:"name"`
	Organization           string    `json:"organization"`
	Address                string    `json:"address"`
	LogPaths               []string  `json:"log_paths"`
	AddressReused          bool      `json:"address_reused"`
	ObserveTraffic         bool      `json:"observe_traffic"`
	AllowLogIngestion      bool      `json:"allow_log_ingestion"`
	AuthorizationConfirmed bool      `json:"authorization_confirmed"`
	CreatedAt              time.Time `json:"created_at"`
	Phase                  string    `json:"phase"`
}

type createSessionRequest struct {
	TargetURL              string   `json:"target_url"`
	Intensity              string   `json:"intensity"`
	Name                   string   `json:"participant_name"`
	Organization           string   `json:"organization"`
	Address                string   `json:"address"`
	LogPaths               []string `json:"log_paths"`
	AddressReused          bool     `json:"address_reused"`
	ObserveTraffic         bool     `json:"observe_traffic"`
	AllowLogIngestion      bool     `json:"allow_log_ingestion"`
	AuthorizationConfirmed bool     `json:"authorization_confirmed"`
	ConsentSandbox         bool     `json:"consent_sandbox"`
	ConsentFakeDB          bool     `json:"consent_fakedb"`
	ConsentAuth            bool     `json:"consent_auth"`
	ConsentLoad            bool     `json:"consent_load"`
	ConsentResponsibility  bool     `json:"consent_responsibility"`
}

type consentRequest struct {
	SessionID          string   `json:"session_id"`
	Action             string   `json:"action"`
	Note               string   `json:"note"`
	SelectedEndpoints  []string `json:"selected_endpoints"`
	SelectedServices   []string `json:"selected_services"`
	AllowLogs          bool     `json:"allow_logs"`
	SelectedLogSources []string `json:"selected_log_sources"`
}

type stopSessionRequest struct {
	SessionID string `json:"session_id"`
}

func main() {
	log.Println("[api-gateway] starting...")

	// Parse embedded templates
	var err error
	tmpl, err = template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatalf("[api-gateway] template parse error: %v", err)
	}

	// Connect to Redis
	redisClient = spectreRedis.NewClient()
	defer redisClient.Close()

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/session", handleCreateSession)
	mux.HandleFunc("/api/session/status", handleSessionStatus)
	mux.HandleFunc("/api/session/consent", handleSessionConsent)
	mux.HandleFunc("/api/session/events", handleSSE)
	mux.HandleFunc("/api/session/stop", handleStopSession)
	mux.HandleFunc("/api/sessions", handleListSessions)
	mux.HandleFunc("/dashboard", handleDashboard)

	log.Println("[api-gateway] listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("[api-gateway] server error: %v", err)
	}
}

// handleIndex serves the consent form page.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	tmpl.ExecuteTemplate(w, "index.html", nil)
}

// handleDashboard serves the live dashboard page.
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "missing session parameter", http.StatusBadRequest)
		return
	}

	val, ok := sessions.Load(sessionID)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	session := val.(*Session)
	tmpl.ExecuteTemplate(w, "dashboard.html", session)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"service": "api-gateway",
		"time":    time.Now().Format(time.RFC3339),
	})
}

// handleCreateSession validates consent and starts an assessment.
func handleCreateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := parseCreateSessionRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.TargetURL == "" {
		http.Error(w, "target_url is required", http.StatusBadRequest)
		return
	}
	if !req.ConsentSandbox || !req.ConsentFakeDB || !req.ConsentAuth || !req.ConsentLoad || !req.ConsentResponsibility {
		http.Error(w, "all consent fields must be accepted", http.StatusBadRequest)
		return
	}
	if !req.ObserveTraffic {
		http.Error(w, "traffic observation consent is required", http.StatusBadRequest)
		return
	}
	if !req.AuthorizationConfirmed {
		http.Error(w, "authorization confirmation is required", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		req.Name = "operator"
	}
	if req.Organization == "" {
		req.Organization = "SPECTRE"
	}
	if req.Intensity == "" {
		req.Intensity = "safe"
	}

	// Create session
	sessionID := fmt.Sprintf("session-%d", time.Now().UnixNano())
	session := &Session{
		ID:                     sessionID,
		TargetURL:              req.TargetURL,
		Scope:                  "auto",
		Intensity:              req.Intensity,
		Name:                   req.Name,
		Organization:           req.Organization,
		Address:                req.Address,
		LogPaths:               req.LogPaths,
		AddressReused:          req.AddressReused,
		ObserveTraffic:         req.ObserveTraffic,
		AllowLogIngestion:      req.AllowLogIngestion,
		AuthorizationConfirmed: req.AuthorizationConfirmed,
		CreatedAt:              time.Now(),
		Phase:                  "recon",
	}
	sessions.Store(sessionID, session)

	// Publish session start event to Redis
	ctx := context.Background()
	_, err = redisClient.Publish(ctx, "session-start", map[string]interface{}{
		"session_id":              sessionID,
		"target_url":              req.TargetURL,
		"scope":                   session.Scope,
		"intensity":               session.Intensity,
		"address":                 session.Address,
		"log_paths":               session.LogPaths,
		"address_reused":          session.AddressReused,
		"observe_traffic":         session.ObserveTraffic,
		"allow_log_ingestion":     session.AllowLogIngestion,
		"authorization_confirmed": session.AuthorizationConfirmed,
		"timestamp":               session.CreatedAt.Format(time.RFC3339),
	})
	if err != nil {
		log.Printf("[api-gateway] failed to publish session-start: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[api-gateway] session %s created for target %s", sessionID, req.TargetURL)

	if wantsJSONResponse(r) {
		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"status":        "created",
			"session":       session,
			"dashboard_url": fmt.Sprintf("http://%s/dashboard?session=%s", r.Host, sessionID),
		})
		return
	}

	// Redirect to dashboard
	http.Redirect(w, r, fmt.Sprintf("/dashboard?session=%s", sessionID), http.StatusSeeOther)
}

func handleSessionConsent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := parseConsentRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.SessionID == "" || (req.Action != "approve" && req.Action != "decline") {
		http.Error(w, "session_id and valid action are required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	_, err = redisClient.Publish(ctx, "session-consent", map[string]interface{}{
		"session_id":           req.SessionID,
		"action":               req.Action,
		"note":                 req.Note,
		"selected_endpoints":   req.SelectedEndpoints,
		"selected_services":    req.SelectedServices,
		"allow_logs":           req.AllowLogs,
		"selected_log_sources": req.SelectedLogSources,
		"timestamp":            time.Now().Format(time.RFC3339),
	})
	if err != nil {
		log.Printf("[api-gateway] failed to publish session-consent: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[api-gateway] consent %s recorded for session %s", req.Action, req.SessionID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":               req.Action,
		"session_id":           req.SessionID,
		"selected_endpoints":   req.SelectedEndpoints,
		"selected_services":    req.SelectedServices,
		"allow_logs":           req.AllowLogs,
		"selected_log_sources": req.SelectedLogSources,
	})
}

// handleStopSession publishes a stop event so all services cancel work.
func handleStopSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID, err := parseStopSessionRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if sessionID == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	_, err = redisClient.Publish(ctx, "session-stop", map[string]interface{}{
		"session_id": sessionID,
		"timestamp":  time.Now().Format(time.RFC3339),
	})
	if err != nil {
		log.Printf("[api-gateway] failed to publish session-stop: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[api-gateway] stop requested for session %s", sessionID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped", "session_id": sessionID})
}

func handleListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionsList := collectSessions()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count":    len(sessionsList),
		"sessions": sessionsList,
	})
}

func handleSessionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "missing session parameter", http.StatusBadRequest)
		return
	}

	val, ok := sessions.Load(sessionID)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session": val.(*Session),
	})
}

// handleSSE streams Redis events to the browser via Server-Sent Events.
// BUG FIX: Uses per-stream lastID tracking so stream IDs don't collide.
// BUG FIX: Non-blocking reads so one empty stream doesn't freeze the loop.
func handleSSE(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "missing session parameter", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ctx := r.Context()

	// Stream names to fan out to the dashboard
	streams := []string{"recon-results", "session-state", "attack-results", "ml-predictions", "llm-classifications", "scoring-results", "service-metrics", "session-consent", "security-logs", "threat-intel"}

	// BUG FIX: Track lastID per stream — stream IDs are only comparable within the same stream
	lastIDs := make(map[string]string)
	for _, s := range streams {
		lastIDs[s] = "0"
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		anyMessages := false
		for _, stream := range streams {
			messages, err := redisClient.ReadStreamNonBlocking(ctx, stream, lastIDs[stream], 50)
			if err != nil {
				log.Printf("[sse] error reading %s: %v", stream, err)
				continue
			}

			for _, msg := range messages {
				// Filter events for this session
				if sid, ok := msg.Data["session_id"]; ok {
					if sid != sessionID {
						// Still update lastID so we don't re-read this msg
						lastIDs[stream] = msg.ID
						continue
					}
				}

				data, _ := json.Marshal(map[string]interface{}{
					"id":     msg.ID,
					"stream": msg.Stream,
					"data":   msg.Data,
				})
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
				lastIDs[stream] = msg.ID
				anyMessages = true
			}
		}

		// Only sleep if there were no messages (tight loop when active, slow when idle)
		if !anyMessages {
			time.Sleep(300 * time.Millisecond)
		}
	}
}

func parseCreateSessionRequest(r *http.Request) (*createSessionRequest, error) {
	req := &createSessionRequest{}
	if isJSONRequest(r) {
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			return nil, fmt.Errorf("invalid JSON body")
		}
		return req, nil
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("bad form data")
	}
	req.TargetURL = r.FormValue("target_url")
	req.Intensity = r.FormValue("intensity")
	req.Name = r.FormValue("participant_name")
	req.Organization = r.FormValue("organization")
	req.Address = r.FormValue("address")
	req.LogPaths = splitCSVFormValue(r.FormValue("log_paths"))
	req.AddressReused = r.FormValue("address_reused") == "true"
	req.ObserveTraffic = r.FormValue("observe_traffic") == "on"
	req.AllowLogIngestion = r.FormValue("allow_log_ingestion") == "on"
	req.AuthorizationConfirmed = r.FormValue("authorization_confirmed") == "on"
	req.ConsentSandbox = r.FormValue("consent_sandbox") == "on"
	req.ConsentFakeDB = r.FormValue("consent_fakedb") == "on"
	req.ConsentAuth = r.FormValue("consent_auth") == "on"
	req.ConsentLoad = r.FormValue("consent_load") == "on"
	req.ConsentResponsibility = r.FormValue("consent_responsibility") == "on"
	return req, nil
}

func splitCSVFormValue(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseConsentRequest(r *http.Request) (*consentRequest, error) {
	req := &consentRequest{}
	if isJSONRequest(r) {
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			return nil, fmt.Errorf("invalid JSON body")
		}
		return req, nil
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("bad form data")
	}

	req.SessionID = r.FormValue("session_id")
	req.Action = r.FormValue("action")
	req.Note = r.FormValue("note")
	req.AllowLogs = r.FormValue("allow_logs") == "true"
	if err := decodeJSONListField(r.FormValue("selected_endpoints"), &req.SelectedEndpoints); err != nil {
		return nil, fmt.Errorf("selected_endpoints must be valid JSON array")
	}
	if err := decodeJSONListField(r.FormValue("selected_services"), &req.SelectedServices); err != nil {
		return nil, fmt.Errorf("selected_services must be valid JSON array")
	}
	if err := decodeJSONListField(r.FormValue("selected_log_sources"), &req.SelectedLogSources); err != nil {
		return nil, fmt.Errorf("selected_log_sources must be valid JSON array")
	}
	return req, nil
}

func parseStopSessionRequest(r *http.Request) (string, error) {
	if isJSONRequest(r) {
		req := &stopSessionRequest{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			return "", fmt.Errorf("invalid JSON body")
		}
		return req.SessionID, nil
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID != "" {
		return sessionID, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("bad form data")
	}
	return r.FormValue("session_id"), nil
}

func decodeJSONListField(raw string, target *[]string) error {
	if raw == "" {
		return nil
	}
	return json.Unmarshal([]byte(raw), target)
}

func isJSONRequest(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Content-Type"), "application/json")
}

func wantsJSONResponse(r *http.Request) bool {
	if isJSONRequest(r) {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "application/json") || r.URL.Query().Get("format") == "json"
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func collectSessions() []*Session {
	sessionsList := make([]*Session, 0)
	sessions.Range(func(_, value interface{}) bool {
		session, ok := value.(*Session)
		if ok {
			sessionsList = append(sessionsList, session)
		}
		return true
	})
	sort.Slice(sessionsList, func(i, j int) bool {
		return sessionsList[i].CreatedAt.After(sessionsList[j].CreatedAt)
	})
	return sessionsList
}
