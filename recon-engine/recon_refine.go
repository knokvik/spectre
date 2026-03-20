package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func refineClassification(result *ReconResult) ClassificationResult {
	refined := result.Classification
	if refined.Confidence == 0 {
		refined.Confidence = 0.3
	}

	backendSignals := 0
	if len(result.RASM.DiscoveredEndpoints) > 0 {
		backendSignals += 2
	}
	for _, port := range result.OpenPorts {
		if !isWebPort(port) {
			backendSignals++
		}
	}
	for _, service := range result.Services {
		lower := strings.ToLower(service)
		if strings.Contains(lower, "mysql") || strings.Contains(lower, "postgres") || strings.Contains(lower, "redis") || strings.Contains(lower, "mongodb") || strings.Contains(lower, "ssh") || strings.Contains(lower, "http server") {
			backendSignals++
		}
	}

	if backendSignals == 0 {
		return refined
	}

	targetClass := refined.Class
	switch {
	case hasServiceKeyword(result.Services, "redis", "mongodb", "mysql", "postgres", "mariadb"):
		targetClass = "microservice-cluster"
	case len(result.RASM.DiscoveredEndpoints) > 0:
		targetClass = "full-backend"
	case backendSignals >= 2:
		targetClass = "full-backend"
	}

	if targetClass != refined.Class || refined.Confidence < 0.85 {
		refined.Class = targetClass
		refined.Confidence = minFloat(0.95, refined.Confidence+0.35)
		refined.Details = fmt.Sprintf("%s | Refined using open ports (%d), services (%d), backend endpoints (%d)", refined.Details, len(result.OpenPorts), len(result.Services), len(result.RASM.DiscoveredEndpoints))
	}

	return refined
}

func detectConsentRequirement(targetURL string, result *ReconResult) ConsentRequirement {
	req := ConsentRequirement{
		DetectedItems: []string{},
	}

	for _, port := range result.OpenPorts {
		if isWebPort(port) {
			continue
		}
		req.DetectedItems = append(req.DetectedItems, fmt.Sprintf("Port %d open", port))
	}
	for port, service := range result.Services {
		lower := strings.ToLower(service)
		if strings.Contains(lower, "mysql") || strings.Contains(lower, "postgres") || strings.Contains(lower, "redis") || strings.Contains(lower, "mongodb") || strings.Contains(lower, "ssh") {
			req.DetectedItems = append(req.DetectedItems, fmt.Sprintf("Service %s on %s", service, port))
		}
	}

	if len(req.DetectedItems) == 0 {
		return req
	}

	req.Required = true
	req.Reason = "Detected backend/server-side infrastructure beyond the web entrypoint"
	req.Deployment = deploymentType(targetURL, result.DNS.ResolvedIP)

	if req.Deployment == "hosted" {
		req.Message = "Additional hosted server-side infrastructure was detected. For security, run or mirror the backend locally before deep verification. Approve only if this infrastructure is part of the same project and in scope."
	} else {
		req.Message = "Additional local or same-project server-side infrastructure was detected. Confirm whether SPECTRE should use it for deeper verification before attacks proceed."
	}

	return req
}

func isWebPort(port int) bool {
	switch port {
	case 80, 81, 82, 83, 84, 85, 88, 443, 444, 591, 593, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000:
		return true
	default:
		return false
	}
}

func hasServiceKeyword(services map[string]string, keywords ...string) bool {
	for _, service := range services {
		lower := strings.ToLower(service)
		for _, keyword := range keywords {
			if strings.Contains(lower, keyword) {
				return true
			}
		}
	}
	return false
}

func deploymentType(targetURL, resolvedIP string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return "hosted"
	}
	host := parsed.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		return "local"
	}
	ip := net.ParseIP(host)
	if ip == nil && resolvedIP != "" && resolvedIP != "N/A" {
		ip = net.ParseIP(resolvedIP)
	}
	if ip != nil && isPrivateOrLoopback(ip) {
		return "local"
	}
	return "hosted"
}

func isPrivateOrLoopback(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	privateBlocks := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	for _, block := range privateBlocks {
		_, cidr, err := net.ParseCIDR(block)
		if err == nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
