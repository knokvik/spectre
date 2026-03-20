package cmd

import (
	"fmt"
	"strings"
)

func Run(args []string) error {
	if len(args) == 0 {
		return runInteractiveHome()
	}

	switch strings.ToLower(args[0]) {
	case "scan":
		return runScan(args[1:])
	case "watch":
		return runWatch(args[1:])
	case "ui":
		return runUI(args[1:])
	case "session":
		return runSession(args[1:])
	case "intel":
		return runIntel(args[1:])
	case "report":
		return runReport(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage() {
	fmt.Println(`SPECTRE CLI

Usage:
  spectre scan <target>
  spectre watch <session_id>
  spectre ui
  spectre session list
  spectre session status <session_id>
  spectre session approve <session_id>
  spectre session decline <session_id>
  spectre session stop <session_id>
  spectre intel <cve> [<cve>...]
  spectre report <session_id>
  spectre doctor

Environment:
  SPECTRE_GATEWAY_URL   default: http://127.0.0.1:8080
  SPECTRE_INTEL_URL     default: http://127.0.0.1:5004
  REDIS_ADDR            default: 127.0.0.1:6379
  SPLOITSCAN_PATH       optional: path to SploitScan script, executable, or repo directory`)
}
