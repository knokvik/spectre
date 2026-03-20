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

type IntelClient struct {
	baseURL string
	client  *http.Client
}

type IntelRequest struct {
	SessionID    string   `json:"session_id,omitempty"`
	TargetURL    string   `json:"target_url,omitempty"`
	FindingType  string   `json:"finding_type,omitempty"`
	AttackResult string   `json:"attack_result,omitempty"`
	CVEs         []string `json:"cves,omitempty"`
}

type CVEIntel struct {
	CVE               string   `json:"cve"`
	CVSSScore         float64  `json:"cvss_score"`
	CVSSSeverity      string   `json:"cvss_severity"`
	Description       string   `json:"description"`
	EPSS              float64  `json:"epss"`
	KEV               bool     `json:"kev"`
	ExploitReferences []string `json:"exploit_references"`
	Source            string   `json:"source"`
}

type IntelResponse struct {
	SessionID             string     `json:"session_id"`
	TargetURL             string     `json:"target_url"`
	FindingType           string     `json:"finding_type"`
	CVEs                  []string   `json:"cves"`
	IntelItems            []CVEIntel `json:"intel_items"`
	HighestEPSS           float64    `json:"highest_epss"`
	KEVCount              int        `json:"kev_count"`
	ExploitReferenceCount int        `json:"exploit_reference_count"`
	Priority              string     `json:"priority"`
	PriorityScore         float64    `json:"priority_score"`
	Rationale             string     `json:"rationale"`
	Timestamp             string     `json:"timestamp"`
}

func NewIntelClient(baseURL string) *IntelClient {
	return &IntelClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *IntelClient) Health() error {
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
		return fmt.Errorf("intel health returned %s", resp.Status)
	}
	return nil
}

func (c *IntelClient) GetCVE(cve string) (*IntelResponse, error) {
	var out IntelResponse
	target := c.baseURL + "/intel/cve/" + url.PathEscape(cve)
	if err := c.doJSON(http.MethodGet, target, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *IntelClient) Enrich(body IntelRequest) (*IntelResponse, error) {
	var out IntelResponse
	if err := c.doJSON(http.MethodPost, c.baseURL+"/intel", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *IntelClient) doJSON(method, target string, body interface{}, out interface{}) error {
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
	return json.NewDecoder(resp.Body).Decode(out)
}
