package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
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
	ID           string    `json:"id"`
	TargetURL    string    `json:"target_url"`
	Scope        string    `json:"scope"`
	Intensity    string    `json:"intensity"`
	Name         string    `json:"name"`
	Organization string    `json:"organization"`
	CreatedAt    time.Time `json:"created_at"`
	Phase        string    `json:"phase"`
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
	mux.HandleFunc("/api/session", handleCreateSession)
	mux.HandleFunc("/api/session/events", handleSSE)
	mux.HandleFunc("/api/session/stop", handleStopSession)
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

// handleCreateSession validates consent and starts an assessment.
func handleCreateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	// Validate all consent checkboxes
	consentFields := []string{"consent_sandbox", "consent_fakedb", "consent_auth", "consent_load", "consent_responsibility"}
	for _, field := range consentFields {
		if r.FormValue(field) != "on" {
			http.Error(w, fmt.Sprintf("consent field %s not checked", field), http.StatusBadRequest)
			return
		}
	}

	targetURL := r.FormValue("target_url")
	if targetURL == "" {
		http.Error(w, "target_url is required", http.StatusBadRequest)
		return
	}

	// Create session
	sessionID := fmt.Sprintf("session-%d", time.Now().UnixNano())
	session := &Session{
		ID:           sessionID,
		TargetURL:    targetURL,
		Scope:        r.FormValue("scope"),
		Intensity:    r.FormValue("intensity"),
		Name:         r.FormValue("participant_name"),
		Organization: r.FormValue("organization"),
		CreatedAt:    time.Now(),
		Phase:        "recon",
	}
	sessions.Store(sessionID, session)

	// Publish session start event to Redis
	ctx := context.Background()
	_, err := redisClient.Publish(ctx, "session-start", map[string]interface{}{
		"session_id": sessionID,
		"target_url": targetURL,
		"scope":      session.Scope,
		"intensity":  session.Intensity,
		"timestamp":  session.CreatedAt.Format(time.RFC3339),
	})
	if err != nil {
		log.Printf("[api-gateway] failed to publish session-start: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[api-gateway] session %s created for target %s", sessionID, targetURL)

	// Redirect to dashboard
	http.Redirect(w, r, fmt.Sprintf("/dashboard?session=%s", sessionID), http.StatusSeeOther)
}

// handleStopSession publishes a stop event so all services cancel work.
func handleStopSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		// Try form body
		if err := r.ParseForm(); err == nil {
			sessionID = r.FormValue("session_id")
		}
	}
	if sessionID == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	_, err := redisClient.Publish(ctx, "session-stop", map[string]interface{}{
		"session_id": sessionID,
		"timestamp":  time.Now().Format(time.RFC3339),
	})
	if err != nil {
		log.Printf("[api-gateway] failed to publish session-stop: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[api-gateway] stop requested for session %s", sessionID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped", "session_id": sessionID})
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
	streams := []string{"recon-results", "session-state", "attack-results", "ml-predictions", "llm-classifications", "scoring-results"}

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
