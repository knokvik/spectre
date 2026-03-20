package cmd

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/spectre/spectre-cli/internal/client"
	"github.com/spectre/spectre-cli/internal/config"
	"github.com/spectre/spectre-cli/internal/output"
)

func runDoctor(_ []string) error {
	cfg := config.Load()
	checks := make([]output.Check, 0, 10)

	gateway := client.NewGatewayClient(cfg.GatewayURL)
	if err := gateway.Health(); err != nil {
		checks = append(checks, output.Check{Name: "api-gateway", Status: "fail", Detail: err.Error()})
	} else {
		checks = append(checks, output.Check{Name: "api-gateway", Status: "ok", Detail: cfg.GatewayURL})
	}

	intel := client.NewIntelClient(cfg.IntelURL)
	if err := intel.Health(); err != nil {
		checks = append(checks, output.Check{Name: "intel-service", Status: "fail", Detail: err.Error()})
	} else {
		checks = append(checks, output.Check{Name: "intel-service", Status: "ok", Detail: cfg.IntelURL})
	}

	conn, err := net.DialTimeout("tcp", cfg.RedisAddr, 2*time.Second)
	if err != nil {
		checks = append(checks, output.Check{Name: "redis", Status: "fail", Detail: err.Error()})
	} else {
		_ = conn.Close()
		checks = append(checks, output.Check{Name: "redis", Status: "ok", Detail: cfg.RedisAddr})
	}

	checkTool := func(name string, candidates ...string) {
		for _, candidate := range candidates {
			if path, err := exec.LookPath(candidate); err == nil {
				checks = append(checks, output.Check{Name: name, Status: "ok", Detail: path})
				return
			}
		}
		checks = append(checks, output.Check{Name: name, Status: "warn", Detail: "not found in PATH"})
	}

	checkTool("katana", "katana")
	checkTool("ParamSpider", "ParamSpider", "paramspider")
	checkTool("enumapis", "enumapis")
	checkTool("Arjun", "arjun", "Arjun")
	checkTool("nuclei", "nuclei")
	checkTool("sqlmap", "sqlmap")

	sploitscanPath := os.Getenv("SPLOITSCAN_PATH")
	if sploitscanPath == "" {
		checks = append(checks, output.Check{Name: "SploitScan", Status: "warn", Detail: "SPLOITSCAN_PATH not set"})
	} else {
		checks = append(checks, output.Check{Name: "SploitScan", Status: "ok", Detail: sploitscanPath})
	}

	output.PrintChecks(checks)
	if output.HasFailures(checks) {
		return fmt.Errorf("one or more core dependencies are unavailable")
	}
	return nil
}
