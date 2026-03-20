package main

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type DiscoveredService struct {
	SessionID   string  `json:"session_id"`
	Event       string  `json:"event"`
	Address     string  `json:"address"`
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	Type        string  `json:"type"`
	Relation    string  `json:"relation"`
	Confidence  float64 `json:"confidence"`
	Source      string  `json:"source"`
	Reason      string  `json:"reason"`
	Selectable  bool    `json:"selectable"`
	Recommended bool    `json:"recommended"`
	Internal    bool    `json:"internal"`
}

func buildServiceInventory(targetURL string, result *ReconResult) []DiscoveredService {
	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	host := parsedTarget.Hostname()
	services := map[string]DiscoveredService{}
	entryAddress := fmt.Sprintf("%s:%d", host, normalizedPort(parsedTarget))
	services[entryAddress] = DiscoveredService{
		SessionID:   result.SessionID,
		Event:       "service_discovery",
		Address:     entryAddress,
		Host:        host,
		Port:        normalizedPort(parsedTarget),
		Type:        "frontend",
		Relation:    "entrypoint",
		Confidence:  0.99,
		Source:      "user-input",
		Reason:      "Primary user-provided entrypoint",
		Selectable:  true,
		Recommended: true,
		Internal:    true,
	}

	for address, serviceType := range result.Services {
		if address == "" {
			continue
		}
		serviceURL, err := url.Parse("http://" + address)
		if err != nil {
			continue
		}
		if _, exists := services[address]; exists {
			continue
		}
		internal := strings.EqualFold(serviceURL.Hostname(), host)
		relation := "linked_to_frontend"
		if !internal || serviceType == "external" {
			relation = "external_dependency"
		}
		services[address] = DiscoveredService{
			SessionID:   result.SessionID,
			Event:       "service_discovery",
			Address:     address,
			Host:        serviceURL.Hostname(),
			Port:        normalizedPort(serviceURL),
			Type:        serviceType,
			Relation:    relation,
			Confidence:  0.87,
			Source:      "behavior-observation",
			Reason:      "Observed via application behavior or approved logs",
			Selectable:  internal && serviceType != "external",
			Recommended: internal && serviceType != "external",
			Internal:    internal,
		}
	}

	for _, endpoint := range result.RASM.ReviewEndpoints {
		u, err := url.Parse(endpoint.DiscoveredEndpoint)
		if err != nil {
			continue
		}
		port := normalizedPort(u)
		address := fmt.Sprintf("%s:%d", u.Hostname(), port)
		if _, exists := services[address]; exists {
			continue
		}
		serviceType := "external"
		relation := "external_dependency"
		reason := endpoint.Reason
		internal := strings.EqualFold(host, u.Hostname())
		selectable := endpoint.Selectable && internal
		if internal {
			serviceType = "backend"
			relation = "linked_to_frontend"
			if endpoint.APIType == "graphql" {
				reason = "GraphQL service discovered behind the primary entrypoint"
			}
		}
		services[address] = DiscoveredService{
			SessionID:   result.SessionID,
			Event:       "service_discovery",
			Address:     address,
			Host:        u.Hostname(),
			Port:        port,
			Type:        serviceType,
			Relation:    relation,
			Confidence:  endpoint.Confidence,
			Source:      endpoint.Source,
			Reason:      reason,
			Selectable:  selectable,
			Recommended: endpoint.Recommended && selectable,
			Internal:    internal,
		}
	}

	out := make([]DiscoveredService, 0, len(services))
	for _, item := range services {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Recommended == out[j].Recommended {
			if out[i].Confidence == out[j].Confidence {
				return out[i].Address < out[j].Address
			}
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Recommended && !out[j].Recommended
	})
	return out
}

func classifyInternalService(sessionID, host string, port, targetPort int, banner string) DiscoveredService {
	serviceType := "internal-service"
	relation := "linked_to_frontend"
	reason := "Additional internal service detected on the same host"
	recommended := false
	confidence := 0.78
	lowerBanner := strings.ToLower(banner)

	switch {
	case port == targetPort:
		serviceType = "frontend"
		relation = "entrypoint"
		reason = "Primary user-provided entrypoint"
		recommended = true
		confidence = 0.98
	case isDatabasePort(port) || strings.Contains(lowerBanner, "redis") || strings.Contains(lowerBanner, "postgres") || strings.Contains(lowerBanner, "mongo") || strings.Contains(lowerBanner, "mysql"):
		serviceType = "database"
		relation = "data_store"
		reason = "Database or cache service exposed on the same host"
		confidence = 0.93
	case isWebPort(port):
		serviceType = "backend"
		relation = "linked_to_frontend"
		reason = "HTTP-capable service on the same host likely linked to the entrypoint"
		recommended = port != targetPort
		confidence = 0.9
	case strings.Contains(lowerBanner, "ssh"):
		serviceType = "ops"
		relation = "support_service"
		reason = "Operational or administration surface"
		confidence = 0.86
	}

	return DiscoveredService{
		SessionID:   sessionID,
		Event:       "service_discovery",
		Host:        host,
		Port:        port,
		Type:        serviceType,
		Relation:    relation,
		Confidence:  confidence,
		Source:      "port-scan",
		Reason:      reason,
		Selectable:  true,
		Recommended: recommended,
		Internal:    true,
	}
}

func publishDiscoveredService(ctx context.Context, service DiscoveredService) {
	payload := map[string]interface{}{
		"session_id":   service.SessionID,
		"event":        service.Event,
		"address":      service.Address,
		"host":         service.Host,
		"port":         service.Port,
		"type":         "service-discovery",
		"service_type": service.Type,
		"relation":     service.Relation,
		"confidence":   service.Confidence,
		"source":       service.Source,
		"reason":       service.Reason,
		"selectable":   service.Selectable,
		"recommended":  service.Recommended,
		"internal":     service.Internal,
	}
	_, _ = redisClient.Publish(ctx, "recon-results", payload)
}

func availableLogSources(services []DiscoveredService) []string {
	out := []string{"application", "system"}
	for _, service := range services {
		if service.Type == "database" {
			out = append(out, "database")
			break
		}
	}
	return out
}

func augmentConsentForServices(targetURL string, req *ConsentRequirement, services []DiscoveredService) {
	if req == nil || len(services) == 0 {
		return
	}

	added := false
	internalExtras := 0
	externalDeps := 0
	for _, service := range services {
		if service.Relation == "entrypoint" {
			continue
		}
		if service.Internal {
			internalExtras++
		} else {
			externalDeps++
		}

		label := fmt.Sprintf("%s (%s)", service.Address, service.Type)
		if !containsString(req.DetectedItems, label) {
			req.DetectedItems = append(req.DetectedItems, label)
			added = true
		}
	}

	if !added {
		return
	}

	req.Required = true
	if req.Reason == "" {
		req.Reason = "Detected multiple linked services beyond the primary entrypoint"
	}
	if req.Deployment == "" {
		req.Deployment = deploymentType(targetURL, "")
	}
	if req.Message == "" {
		req.Message = "Additional services were discovered around the primary target. Review which frontend, backend, database, and dependency surfaces SPECTRE is allowed to include before deeper testing continues."
	}
	if externalDeps > 0 {
		req.Message = "Additional internal services and external dependencies were discovered. Review scope carefully and approve only the services that belong to this project before deeper testing continues."
	} else if internalExtras > 0 {
		req.Message = "Additional same-host or same-project services were discovered. Confirm which linked services and logs SPECTRE is allowed to use before deeper testing continues."
	}
}

func normalizedPort(u *url.URL) int {
	if u == nil {
		return 0
	}
	if portText := u.Port(); portText != "" {
		port, err := strconv.Atoi(portText)
		if err == nil {
			return port
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

func isDatabasePort(port int) bool {
	switch port {
	case 3306, 5432, 6379, 27017, 1433, 1521, 11211:
		return true
	default:
		return false
	}
}

func containsString(items []string, candidate string) bool {
	for _, item := range items {
		if item == candidate {
			return true
		}
	}
	return false
}
