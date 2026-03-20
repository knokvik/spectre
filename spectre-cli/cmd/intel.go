package cmd

import (
	"encoding/json"
	"flag"
	"os"

	"github.com/spectre/spectre-cli/internal/client"
	"github.com/spectre/spectre-cli/internal/config"
	"github.com/spectre/spectre-cli/internal/output"
)

func runIntel(args []string) error {
	fs := flag.NewFlagSet("intel", flag.ContinueOnError)
	sessionID := fs.String("session", "", "session id")
	targetURL := fs.String("target", "", "target URL")
	findingType := fs.String("finding", "", "finding type label")
	attackResult := fs.String("attack-result", "", "free-form attack result text to mine for CVEs")
	jsonOut := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := config.Load()
	intel := client.NewIntelClient(cfg.IntelURL)

	var (
		resp *client.IntelResponse
		err  error
	)
	if fs.NArg() == 1 && *sessionID == "" && *targetURL == "" && *findingType == "" && *attackResult == "" {
		resp, err = intel.GetCVE(fs.Arg(0))
	} else {
		req := client.IntelRequest{
			SessionID:    *sessionID,
			TargetURL:    *targetURL,
			FindingType:  *findingType,
			AttackResult: *attackResult,
			CVEs:         fs.Args(),
		}
		resp, err = intel.Enrich(req)
	}
	if err != nil {
		return err
	}

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}
	output.PrintIntel(resp)
	return nil
}
