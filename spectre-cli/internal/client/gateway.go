package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type GatewayClient struct {
	baseURL string
	client  *http.Client
}

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

type CreateSessionRequest struct {
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

type CreateSessionResponse struct {
	Status       string  `json:"status"`
	Session      Session `json:"session"`
	DashboardURL string  `json:"dashboard_url"`
}

type ListSessionsResponse struct {
	Count    int       `json:"count"`
	Sessions []Session `json:"sessions"`
}

type SessionStatusResponse struct {
	Session Session `json:"session"`
}

type ConsentRequest struct {
	SessionID          string   `json:"session_id"`
	Action             string   `json:"action"`
	Note               string   `json:"note"`
	SelectedEndpoints  []string `json:"selected_endpoints"`
	SelectedServices   []string `json:"selected_services"`
	AllowLogs          bool     `json:"allow_logs"`
	SelectedLogSources []string `json:"selected_log_sources"`
}

type ConsentResponse struct {
	Status             string   `json:"status"`
	SessionID          string   `json:"session_id"`
	SelectedEndpoints  []string `json:"selected_endpoints"`
	SelectedServices   []string `json:"selected_services"`
	AllowLogs          bool     `json:"allow_logs"`
	SelectedLogSources []string `json:"selected_log_sources"`
}

type StopSessionResponse struct {
	Status    string `json:"status"`
	SessionID string `json:"session_id"`
}

func NewGatewayClient(baseURL string) *GatewayClient {
	return &GatewayClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *GatewayClient) Health() error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gateway health returned %s", resp.Status)
	}
	return nil
}

func (c *GatewayClient) CreateSession(body CreateSessionRequest) (*CreateSessionResponse, error) {
	var out CreateSessionResponse
	if err := c.doJSON(http.MethodPost, c.baseURL+"/api/session", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *GatewayClient) ListSessions() (*ListSessionsResponse, error) {
	var out ListSessionsResponse
	if err := c.doJSON(http.MethodGet, c.baseURL+"/api/sessions", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *GatewayClient) GetSession(sessionID string) (*SessionStatusResponse, error) {
	var out SessionStatusResponse
	target := c.baseURL + "/api/session/status?session=" + url.QueryEscape(sessionID)
	if err := c.doJSON(http.MethodGet, target, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *GatewayClient) SendConsent(body ConsentRequest) (*ConsentResponse, error) {
	var out ConsentResponse
	if err := c.doJSON(http.MethodPost, c.baseURL+"/api/session/consent", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *GatewayClient) StopSession(sessionID string) (*StopSessionResponse, error) {
	var out StopSessionResponse
	if err := c.doJSON(http.MethodPost, c.baseURL+"/api/session/stop", map[string]string{"session_id": sessionID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *GatewayClient) doJSON(method, target string, body interface{}, out interface{}) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s failed: %s", method, target, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
