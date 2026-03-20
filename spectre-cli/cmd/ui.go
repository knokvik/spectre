package cmd

import (
	"flag"
	"fmt"
	"os/exec"
	"runtime"

	"github.com/spectre/spectre-cli/internal/config"
)

func runUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	sessionID := fs.String("session", "", "open dashboard for an existing session")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := config.Load()
	target := cfg.RootURL()
	if *sessionID != "" {
		target = cfg.DashboardURL(*sessionID)
	}

	if err := openBrowser(target); err != nil {
		fmt.Printf("Dashboard URL: %s\n", target)
		return nil
	}
	fmt.Printf("Opened: %s\n", target)
	return nil
}

func openBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "linux":
		cmd = exec.Command("xdg-open", target)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", target)
	default:
		return fmt.Errorf("unsupported platform")
	}
	return cmd.Start()
}
