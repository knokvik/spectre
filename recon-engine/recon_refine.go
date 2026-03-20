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
	for _, service := range result.Services {
		lower := strings.ToLower(service)
		if strings.Contains(lower, "backend") || strings.Contains(lower, "database") || strings.Contains(lower, "external") {
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
		refined.Details = fmt.Sprintf("%s | Refined using observed services (%d) and backend endpoints (%d)", refined.Details, len(result.Services), len(result.RASM.DiscoveredEndpoints))
	}

	return refined
}

func detectConsentRequirement(targetURL string, result *ReconResult) ConsentRequirement {
	req := ConsentRequirement{
		Required:      true,
		Reason:        "Review observed application scope before controlled testing continues",
		DetectedItems: []string{},
	}

	req.DetectedItems = append(req.DetectedItems, fmt.Sprintf("Frontend %s", targetURL))
	for address, service := range result.Services {
		req.DetectedItems = append(req.DetectedItems, fmt.Sprintf("Observed service %s (%s)", address, service))
	}
	for _, endpoint := range result.RASM.ReviewEndpoints {
		req.DetectedItems = append(req.DetectedItems, fmt.Sprintf("Observed endpoint %s", endpoint.Normalized))
	}

	req.Deployment = deploymentType(targetURL, result.DNS.ResolvedIP)

	if req.Deployment == "hosted" {
		req.Message = "Observed application behavior suggests internal and possibly external dependencies. If this application is hosted online, consider running a local version for deeper analysis and better log access. Approve only the services and endpoints that belong to this project."
	} else {
		req.Message = "Behavior-based discovery is complete. Review the observed services, endpoints, and optional logs, then approve only what SPECTRE may use for controlled testing."
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
