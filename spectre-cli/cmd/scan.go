package cmd

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/spectre/spectre-cli/internal/client"
	"github.com/spectre/spectre-cli/internal/config"
)

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	intensity := fs.String("intensity", "safe", "scan intensity")
	name := fs.String("name", "operator", "operator name")
	org := fs.String("org", "SPECTRE", "organization")
	address := fs.String("address", "", "address or contact note")
	logPaths := fs.String("log-paths", "", "comma-separated log file paths for optional ingestion")
	allowLogIngestion := fs.Bool("allow-log-ingestion", false, "allow ingestion from provided log paths")
	detach := fs.Bool("detach", false, "create the session and return without watching live output")
	interactive := fs.Bool("interactive", false, "prompt for missing values and run in guided mode")
	observeTraffic := fs.Bool("observe-traffic", true, "allow traffic observation for the provided target")
	confirmAuthorization := fs.Bool("confirm-authorization", true, "confirm authorization to scan the target")
	openUI := fs.Bool("open-ui", false, "open dashboard in browser after creating the session")
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *interactive {
		return runInteractiveScan(bufio.NewReader(os.Stdin))
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: spectre scan [flags] <target>")
	}

	cfg := config.Load()
	gateway := client.NewGatewayClient(cfg.GatewayURL)
	resp, err := gateway.CreateSession(client.CreateSessionRequest{
		TargetURL:              fs.Arg(0),
		Intensity:              *intensity,
		Name:                   *name,
		Organization:           *org,
		Address:                *address,
		LogPaths:               splitCSV(*logPaths),
		ObserveTraffic:         *observeTraffic,
		AllowLogIngestion:      *allowLogIngestion,
		AuthorizationConfirmed: *confirmAuthorization,
		ConsentSandbox:         true,
		ConsentFakeDB:          true,
		ConsentAuth:            true,
		ConsentLoad:            true,
		ConsentResponsibility:  true,
	})
	if err != nil {
		return err
	}

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}

	fmt.Printf("Session created: %s\n", resp.Session.ID)
	fmt.Printf("Target: %s\n", resp.Session.TargetURL)
	fmt.Printf("Dashboard: %s\n", resp.DashboardURL)
	if *openUI {
		if err := openBrowser(resp.DashboardURL); err != nil {
			fmt.Printf("Open browser manually: %s\n", resp.DashboardURL)
		}
	}
	if !*detach {
		fmt.Println()
		return watchSession(resp.Session.ID, true, bufio.NewReader(os.Stdin))
	}
	return nil
}
