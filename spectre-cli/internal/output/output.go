package output

import (
	"fmt"
	"strings"

	"github.com/spectre/spectre-cli/internal/client"
)

type Check struct {
	Name   string
	Status string
	Detail string
}

func PrintSessions(sessions []client.Session) {
	if len(sessions) == 0 {
		fmt.Println("No sessions found.")
		return
	}
	for _, session := range sessions {
		fmt.Printf("%s  %s  %s  %s\n", session.ID, session.Phase, session.Intensity, session.TargetURL)
	}
}

func PrintIntel(resp *client.IntelResponse) {
	fmt.Printf("Priority: %s (%.2f)\n", resp.Priority, resp.PriorityScore)
	if resp.FindingType != "" {
		fmt.Printf("Finding: %s\n", resp.FindingType)
	}
	if resp.TargetURL != "" {
		fmt.Printf("Target: %s\n", resp.TargetURL)
	}
	if len(resp.CVEs) > 0 {
		fmt.Printf("CVEs: %s\n", strings.Join(resp.CVEs, ", "))
	}
	fmt.Printf("Rationale: %s\n", resp.Rationale)
	for _, item := range resp.IntelItems {
		fmt.Printf("- %s  CVSS %.1f  EPSS %.3f  KEV=%t  exploits=%d\n", item.CVE, item.CVSSScore, item.EPSS, item.KEV, len(item.ExploitReferences))
	}
}

func PrintChecks(checks []Check) {
	for _, check := range checks {
		fmt.Printf("%-14s %-5s %s\n", check.Name, strings.ToUpper(check.Status), check.Detail)
	}
}

func HasFailures(checks []Check) bool {
	for _, check := range checks {
		if check.Status == "fail" {
			return true
		}
	}
	return false
}
