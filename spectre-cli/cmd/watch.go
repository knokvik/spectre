package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spectre/spectre-cli/internal/client"
	"github.com/spectre/spectre-cli/internal/config"
)

type sseEnvelope struct {
	ID     string                 `json:"id"`
	Stream string                 `json:"stream"`
	Data   map[string]interface{} `json:"data"`
}

type watchState struct {
	sessionID       string
	currentPhase    string
	eventCount      int
	portCount       int
	apis            map[string]consentEndpoint
	services        map[string]consentService
	lastMetrics     map[string]string
	consentHandled  bool
	completed       bool
	seenRiskSummary bool
}

type consentEndpoint struct {
	DiscoveredEndpoint string  `json:"discovered_endpoint"`
	Normalized         string  `json:"normalized"`
	Source             string  `json:"source"`
	Confidence         float64 `json:"confidence"`
	APIType            string  `json:"api_type"`
	ScopeType          string  `json:"scope_type"`
	Risk               string  `json:"risk"`
	Reason             string  `json:"reason"`
	Selectable         bool    `json:"selectable"`
	Recommended        bool    `json:"recommended"`
}

type consentService struct {
	Address     string  `json:"address"`
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	ServiceType string  `json:"service_type"`
	Relation    string  `json:"relation"`
	Confidence  float64 `json:"confidence"`
	Source      string  `json:"source"`
	Reason      string  `json:"reason"`
	Selectable  bool    `json:"selectable"`
	Recommended bool    `json:"recommended"`
	Internal    bool    `json:"internal"`
}

func runWatch(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: spectre watch <session_id>")
	}
	return watchSession(args[0], true, bufio.NewReader(os.Stdin))
}

func watchSession(sessionID string, interactive bool, reader *bufio.Reader) error {
	cfg := config.Load()
	target := cfg.GatewayURL + "/api/session/events?session=" + url.QueryEscape(sessionID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := (&http.Client{Timeout: 0}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("watch failed: %s", resp.Status)
	}

	state := &watchState{
		sessionID:    sessionID,
		currentPhase: "recon",
		apis:         make(map[string]consentEndpoint),
		services:     make(map[string]consentService),
		lastMetrics:  make(map[string]string),
	}

	fmt.Printf("Watching session %s\n", sessionID)
	fmt.Println(strings.Repeat("=", 72))

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		raw := strings.TrimPrefix(line, "data: ")
		var env sseEnvelope
		if err := json.Unmarshal([]byte(raw), &env); err != nil {
			continue
		}
		if err := handleWatchEvent(state, env, interactive, reader); err != nil {
			return err
		}
		if state.completed {
			fmt.Println(strings.Repeat("-", 72))
			fmt.Println("Assessment completed. Returning to CLI.")
			return nil
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func handleWatchEvent(state *watchState, env sseEnvelope, interactive bool, reader *bufio.Reader) error {
	state.eventCount++
	data := env.Data
	stream := env.Stream
	msg := asString(data["message"])
	step := asString(data["step"])

	switch stream {
	case "session-state":
		phase := asString(data["phase"])
		if phase != "" && phase != state.currentPhase {
			state.currentPhase = phase
			fmt.Printf("\n[phase] %s\n", strings.ToUpper(phase))
			if phase == "report" {
				state.completed = true
			}
		}
	case "recon-results":
		if port, ok := toInt(data["port"]); ok {
			state.portCount++
			fmt.Printf("[port] %d open\n", port)
		}
		if asString(data["type"]) == "backend-api" {
			endpoint := decodeEndpoint(data)
			key := endpoint.Normalized
			if key == "" {
				key = endpoint.DiscoveredEndpoint
			}
			state.apis[key] = endpoint
			fmt.Printf("[api] %s  type=%s  conf=%.2f\n", endpoint.DiscoveredEndpoint, endpoint.APIType, endpoint.Confidence)
			return nil
		}
		if asString(data["type"]) == "service-discovery" {
			service := decodeService(data)
			key := service.Address
			if key == "" {
				key = fmt.Sprintf("%s:%d", service.Host, service.Port)
			}
			state.services[key] = service
			fmt.Printf("[service] %s  kind=%s  relation=%s  conf=%.2f\n", key, service.ServiceType, service.Relation, service.Confidence)
			return nil
		}
		if asString(data["type"]) == "consent-required" && interactive && !state.consentHandled {
			state.consentHandled = true
			return handleConsentPrompt(state, data, reader)
		}
		if msg != "" {
			fmt.Printf("[recon/%s] %s\n", safeLabel(step, "event"), msg)
		}
	case "attack-results":
		severity := strings.ToUpper(asString(data["type"]))
		if severity == "" {
			severity = "INFO"
		}
		if msg != "" {
			fmt.Printf("[attack/%s] %s\n", severity, msg)
		}
	case "ml-predictions":
		if msg != "" {
			fmt.Printf("[ml] %s\n", msg)
		} else {
			printJSONLabel("ml", data)
		}
	case "llm-classifications":
		if msg != "" {
			fmt.Printf("[classify] %s\n", msg)
		} else {
			printJSONLabel("classify", data)
		}
	case "scoring-results":
		score := asFloat(data["risk_score"])
		level := asString(data["risk_level"])
		grade := asString(data["risk_grade"])
		summary := asString(data["summary"])
		fmt.Printf("[score] %.1f/10  level=%s  grade=%s\n", score, level, grade)
		if summary != "" {
			fmt.Printf("        %s\n", summary)
		}
		state.seenRiskSummary = true
	case "service-metrics":
		service := asString(data["service"])
		phase := asString(data["phase"])
		impact := asString(data["impact"])
		key := service + ":" + phase
		if state.lastMetrics[key] != impact {
			state.lastMetrics[key] = impact
			fmt.Printf("[metric] %s/%s %s\n", service, phase, impact)
		}
	case "security-logs":
		source := asString(data["source"])
		if source == "" {
			source = "security"
		}
		if msg == "" {
			msg = stringifyCompact(data)
		}
		fmt.Printf("[log/%s] %s\n", source, msg)
	case "session-consent":
		action := asString(data["action"])
		if action != "" {
			fmt.Printf("[consent] %s\n", strings.ToUpper(action))
		}
	case "threat-intel":
		priority := asString(data["priority"])
		if msg == "" {
			msg = asString(data["rationale"])
		}
		fmt.Printf("[intel] priority=%s %s\n", priority, msg)
	default:
		if msg != "" {
			fmt.Printf("[%s] %s\n", stream, msg)
		}
	}

	return nil
}

func handleConsentPrompt(state *watchState, data map[string]interface{}, reader *bufio.Reader) error {
	cfg := config.Load()
	gateway := client.NewGatewayClient(cfg.GatewayURL)

	fmt.Println()
	fmt.Println(strings.Repeat("=", 72))
	fmt.Println("Scope Review Required")
	fmt.Println(strings.Repeat("=", 72))
	message := asString(data["message"])
	if message == "" {
		message = "Additional infrastructure was detected and needs approval before deeper testing."
	}
	fmt.Println(message)

	detectedItems := toStringSlice(data["detected_items"])
	if len(detectedItems) > 0 {
		fmt.Println()
		fmt.Println("Detected items:")
		for _, item := range detectedItems {
			fmt.Printf("- %s\n", item)
		}
	}

	endpoints := decodeEndpoints(data["review_endpoints"])
	if len(endpoints) == 0 {
		endpoints = sortedEndpointValues(state.apis)
	}
	services := decodeServices(data["services"])
	if len(services) == 0 {
		services = sortedServiceValues(state.services)
	}
	logSources := toStringSlice(data["available_log_sources"])

	fmt.Println()
	if !printEndpointChoices(endpoints) {
		fmt.Println("No selectable backend endpoints were proposed.")
	}
	if !printServiceChoices(services) {
		fmt.Println("No selectable services were proposed.")
	}

	approve, err := promptYesNo(reader, "Approve deeper verification", true)
	if err != nil {
		return err
	}
	if !approve {
		_, err = gateway.SendConsent(client.ConsentRequest{
			SessionID: state.sessionID,
			Action:    "decline",
			Note:      "Declined from interactive CLI",
		})
		return err
	}

	selectedEndpoints, err := pickEndpoints(reader, endpoints)
	if err != nil {
		return err
	}
	selectedServices, err := pickServices(reader, services)
	if err != nil {
		return err
	}
	allowLogs := false
	selectedLogSources := []string(nil)
	if len(logSources) > 0 {
		allowLogs, err = promptYesNo(reader, "Allow log collection for approved services", false)
		if err != nil {
			return err
		}
		if allowLogs {
			selectedLogSources, err = pickLogSources(reader, logSources)
			if err != nil {
				return err
			}
		}
	}

	_, err = gateway.SendConsent(client.ConsentRequest{
		SessionID:          state.sessionID,
		Action:             "approve",
		Note:               "Approved from interactive CLI",
		SelectedEndpoints:  selectedEndpoints,
		SelectedServices:   selectedServices,
		AllowLogs:          allowLogs,
		SelectedLogSources: selectedLogSources,
	})
	if err == nil {
		fmt.Println("[consent] submitted")
	}
	return err
}

func printEndpointChoices(items []consentEndpoint) bool {
	selectable := 0
	if len(items) > 0 {
		fmt.Println()
		fmt.Println("Endpoints:")
	}
	for i, item := range items {
		marker := " "
		if item.Recommended {
			marker = "*"
		}
		scope := item.ScopeType
		if scope == "" {
			scope = "unknown"
		}
		if item.Selectable {
			selectable++
		}
		fmt.Printf("%d. [%s] %s  type=%s  scope=%s  selectable=%t\n", i+1, marker, item.DiscoveredEndpoint, item.APIType, scope, item.Selectable)
		if item.Reason != "" {
			fmt.Printf("    %s\n", item.Reason)
		}
	}
	return selectable > 0
}

func printServiceChoices(items []consentService) bool {
	selectable := 0
	if len(items) > 0 {
		fmt.Println()
		fmt.Println("Services:")
	}
	for i, item := range items {
		marker := " "
		if item.Recommended {
			marker = "*"
		}
		if item.Selectable {
			selectable++
		}
		fmt.Printf("%d. [%s] %s  kind=%s  relation=%s  selectable=%t\n", i+1, marker, item.Address, item.ServiceType, item.Relation, item.Selectable)
		if item.Reason != "" {
			fmt.Printf("    %s\n", item.Reason)
		}
	}
	return selectable > 0
}

func pickEndpoints(reader *bufio.Reader, items []consentEndpoint) ([]string, error) {
	defaults := make([]string, 0)
	for _, item := range items {
		if item.Selectable && item.Recommended {
			defaults = append(defaults, item.Normalized)
		}
	}
	useDefaults, err := promptYesNo(reader, "Use recommended endpoint selections", true)
	if err != nil {
		return nil, err
	}
	if useDefaults {
		return defaults, nil
	}
	raw, err := prompt(reader, "Enter endpoint numbers (comma separated, blank for none)", "")
	if err != nil {
		return nil, err
	}
	indices := parseIndexSelection(raw)
	selected := make([]string, 0, len(indices))
	for _, idx := range indices {
		if idx < 1 || idx > len(items) {
			continue
		}
		item := items[idx-1]
		if item.Selectable && item.Normalized != "" {
			selected = append(selected, item.Normalized)
		}
	}
	return selected, nil
}

func pickServices(reader *bufio.Reader, items []consentService) ([]string, error) {
	defaults := make([]string, 0)
	for _, item := range items {
		if item.Selectable && item.Recommended {
			defaults = append(defaults, item.Address)
		}
	}
	useDefaults, err := promptYesNo(reader, "Use recommended service selections", true)
	if err != nil {
		return nil, err
	}
	if useDefaults {
		return defaults, nil
	}
	raw, err := prompt(reader, "Enter service numbers (comma separated, blank for none)", "")
	if err != nil {
		return nil, err
	}
	indices := parseIndexSelection(raw)
	selected := make([]string, 0, len(indices))
	for _, idx := range indices {
		if idx < 1 || idx > len(items) {
			continue
		}
		item := items[idx-1]
		if item.Selectable && item.Address != "" {
			selected = append(selected, item.Address)
		}
	}
	return selected, nil
}

func pickLogSources(reader *bufio.Reader, items []string) ([]string, error) {
	fmt.Println()
	fmt.Println("Log sources:")
	for i, item := range items {
		fmt.Printf("%d. %s\n", i+1, item)
	}
	useAll, err := promptYesNo(reader, "Use all available log sources", true)
	if err != nil {
		return nil, err
	}
	if useAll {
		return items, nil
	}
	raw, err := prompt(reader, "Enter log source numbers (comma separated)", "")
	if err != nil {
		return nil, err
	}
	indices := parseIndexSelection(raw)
	selected := make([]string, 0, len(indices))
	for _, idx := range indices {
		if idx >= 1 && idx <= len(items) {
			selected = append(selected, items[idx-1])
		}
	}
	return selected, nil
}

func parseIndexSelection(raw string) []int {
	parts := splitCSV(raw)
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.Atoi(part)
		if err == nil {
			out = append(out, value)
		}
	}
	return out
}

func sortedEndpointValues(values map[string]consentEndpoint) []consentEndpoint {
	out := make([]consentEndpoint, 0, len(values))
	for _, item := range values {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Recommended == out[j].Recommended {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Recommended
	})
	return out
}

func sortedServiceValues(values map[string]consentService) []consentService {
	out := make([]consentService, 0, len(values))
	for _, item := range values {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Recommended == out[j].Recommended {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Recommended
	})
	return out
}

func decodeEndpoints(raw interface{}) []consentEndpoint {
	items := decodeSliceMaps(raw)
	out := make([]consentEndpoint, 0, len(items))
	for _, item := range items {
		out = append(out, decodeEndpoint(item))
	}
	return out
}

func decodeServices(raw interface{}) []consentService {
	items := decodeSliceMaps(raw)
	out := make([]consentService, 0, len(items))
	for _, item := range items {
		out = append(out, decodeService(item))
	}
	return out
}

func decodeSliceMaps(raw interface{}) []map[string]interface{} {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(list))
	for _, item := range list {
		if mapped, ok := item.(map[string]interface{}); ok {
			out = append(out, mapped)
		}
	}
	return out
}

func decodeEndpoint(data map[string]interface{}) consentEndpoint {
	return consentEndpoint{
		DiscoveredEndpoint: asString(data["discovered_endpoint"]),
		Normalized:         asString(data["normalized"]),
		Source:             asString(data["source"]),
		Confidence:         asFloat(data["confidence"]),
		APIType:            asString(data["api_type"]),
		ScopeType:          asString(data["scope_type"]),
		Risk:               asString(data["risk"]),
		Reason:             asString(data["reason"]),
		Selectable:         asBool(data["selectable"]),
		Recommended:        asBool(data["recommended"]),
	}
}

func decodeService(data map[string]interface{}) consentService {
	return consentService{
		Address:     asString(data["address"]),
		Host:        asString(data["host"]),
		Port:        int(asFloat(data["port"])),
		ServiceType: firstNonEmpty(asString(data["service_type"]), asString(data["type"])),
		Relation:    asString(data["relation"]),
		Confidence:  asFloat(data["confidence"]),
		Source:      asString(data["source"]),
		Reason:      asString(data["reason"]),
		Selectable:  asBool(data["selectable"]),
		Recommended: asBool(data["recommended"]),
		Internal:    asBool(data["internal"]),
	}
}

func asString(v interface{}) string {
	switch value := v.(type) {
	case string:
		return value
	default:
		return ""
	}
}

func asFloat(v interface{}) float64 {
	switch value := v.(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case json.Number:
		f, _ := value.Float64()
		return f
	default:
		return 0
	}
}

func asBool(v interface{}) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(value, "true")
	default:
		return false
	}
}

func toStringSlice(v interface{}) []string {
	list, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func toInt(v interface{}) (int, bool) {
	switch value := v.(type) {
	case int:
		return value, true
	case int64:
		return int(value), true
	case float64:
		return int(value), true
	case json.Number:
		i, err := value.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}

func safeLabel(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func printJSONLabel(label string, data map[string]interface{}) {
	fmt.Printf("[%s] %s\n", label, stringifyCompact(data))
}

func stringifyCompact(data map[string]interface{}) string {
	b, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(b)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
