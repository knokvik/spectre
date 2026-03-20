package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/spectre/spectre-cli/internal/client"
	"github.com/spectre/spectre-cli/internal/config"
	"github.com/spectre/spectre-cli/internal/output"
)

func runSession(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: spectre session <list|status|approve|decline|stop>")
	}

	switch args[0] {
	case "list":
		return runSessionList(args[1:])
	case "status":
		return runSessionStatus(args[1:])
	case "approve":
		return runSessionConsent("approve", args[1:])
	case "decline":
		return runSessionConsent("decline", args[1:])
	case "stop":
		return runSessionStop(args[1:])
	default:
		return fmt.Errorf("unknown session subcommand %q", args[0])
	}
}

func runSessionList(args []string) error {
	fs := flag.NewFlagSet("session list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := config.Load()
	gateway := client.NewGatewayClient(cfg.GatewayURL)
	resp, err := gateway.ListSessions()
	if err != nil {
		return err
	}
	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}
	output.PrintSessions(resp.Sessions)
	return nil
}

func runSessionStatus(args []string) error {
	fs := flag.NewFlagSet("session status", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: spectre session status [flags] <session_id>")
	}

	cfg := config.Load()
	gateway := client.NewGatewayClient(cfg.GatewayURL)
	resp, err := gateway.GetSession(fs.Arg(0))
	if err != nil {
		return err
	}
	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}
	output.PrintSessions([]client.Session{resp.Session})
	return nil
}

func runSessionConsent(action string, args []string) error {
	fs := flag.NewFlagSet("session "+action, flag.ContinueOnError)
	note := fs.String("note", "", "consent note")
	endpoints := fs.String("endpoints", "", "comma-separated endpoints")
	services := fs.String("services", "", "comma-separated services")
	logSources := fs.String("log-sources", "", "comma-separated log sources")
	allowLogs := fs.Bool("allow-logs", false, "allow approved log collection")
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: spectre session %s [flags] <session_id>", action)
	}

	cfg := config.Load()
	gateway := client.NewGatewayClient(cfg.GatewayURL)
	resp, err := gateway.SendConsent(client.ConsentRequest{
		SessionID:          fs.Arg(0),
		Action:             action,
		Note:               *note,
		SelectedEndpoints:  splitCSV(*endpoints),
		SelectedServices:   splitCSV(*services),
		SelectedLogSources: splitCSV(*logSources),
		AllowLogs:          *allowLogs,
	})
	if err != nil {
		return err
	}
	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}
	fmt.Printf("Session %s %sd\n", resp.SessionID, resp.Status)
	return nil
}

func runSessionStop(args []string) error {
	fs := flag.NewFlagSet("session stop", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: spectre session stop <session_id>")
	}

	cfg := config.Load()
	gateway := client.NewGatewayClient(cfg.GatewayURL)
	resp, err := gateway.StopSession(fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Printf("Session %s %s\n", resp.SessionID, resp.Status)
	return nil
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
