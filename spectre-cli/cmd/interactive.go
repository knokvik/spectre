package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spectre/spectre-cli/internal/client"
	"github.com/spectre/spectre-cli/internal/config"
)

func runInteractiveHome() error {
	reader := bufio.NewReader(os.Stdin)
	for {
		printBanner()
		fmt.Println("1. New Scan")
		fmt.Println("2. Resume Session")
		fmt.Println("3. Threat Intel")
		fmt.Println("4. Doctor")
		fmt.Println("5. Open Web UI")
		fmt.Println("6. Help")
		fmt.Println("0. Exit")
		fmt.Println()

		choice, err := prompt(reader, "Select an option", "")
		if err != nil {
			return err
		}

		switch strings.TrimSpace(choice) {
		case "1":
			if err := runInteractiveScan(reader); err != nil {
				return err
			}
		case "2":
			if err := runResumeSession(reader); err != nil {
				return err
			}
		case "3":
			if err := runInteractiveIntel(reader); err != nil {
				return err
			}
		case "4":
			if err := runDoctor(nil); err != nil {
				fmt.Printf("\nDoctor finished with warnings: %v\n", err)
				_, _ = prompt(reader, "Press Enter to continue", "")
			}
		case "5":
			if err := runUI(nil); err != nil {
				return err
			}
			_, _ = prompt(reader, "Press Enter to continue", "")
		case "6":
			printUsage()
			_, _ = prompt(reader, "Press Enter to continue", "")
		case "0", "q", "quit", "exit":
			fmt.Println("Goodbye.")
			return nil
		default:
			fmt.Println("Unknown option.")
			_, _ = prompt(reader, "Press Enter to continue", "")
		}
	}
}

func runInteractiveScan(reader *bufio.Reader) error {
	fmt.Println()
	fmt.Println("Guided Scan")
	fmt.Println("-----------")

	target, err := prompt(reader, "Target URL", "")
	if err != nil {
		return err
	}
	if strings.TrimSpace(target) == "" {
		fmt.Println("Target is required.")
		_, _ = prompt(reader, "Press Enter to continue", "")
		return nil
	}

	intensity, err := promptChoice(reader, "Intensity", []string{"light", "standard", "thorough"}, "standard")
	if err != nil {
		return err
	}
	name, err := prompt(reader, "Operator name", "operator")
	if err != nil {
		return err
	}
	org, err := prompt(reader, "Organization", "SPECTRE")
	if err != nil {
		return err
	}
	address, err := prompt(reader, "Contact / address note", "")
	if err != nil {
		return err
	}
	logPathsRaw, err := prompt(reader, "Log file paths (comma separated, optional)", "")
	if err != nil {
		return err
	}
	allowLogs := false
	if strings.TrimSpace(logPathsRaw) != "" {
		allowLogs, err = promptYesNo(reader, "Allow log ingestion from those paths", true)
		if err != nil {
			return err
		}
	}
	observeTraffic, err := promptYesNo(reader, "Allow traffic observation for this target", true)
	if err != nil {
		return err
	}
	authorized, err := promptYesNo(reader, "Confirm you are authorized to scan this target", true)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Intensity: %s\n", intensity)
	fmt.Printf("Operator: %s\n", name)
	fmt.Printf("Organization: %s\n", org)
	if address != "" {
		fmt.Printf("Address/Note: %s\n", address)
	}
	if allowLogs {
		fmt.Printf("Log Paths: %s\n", strings.Join(splitCSV(logPathsRaw), ", "))
	}

	proceed, err := promptYesNo(reader, "Start assessment", true)
	if err != nil {
		return err
	}
	if !proceed {
		return nil
	}

	cfg := config.Load()
	gateway := client.NewGatewayClient(cfg.GatewayURL)
	resp, err := gateway.CreateSession(client.CreateSessionRequest{
		TargetURL:              target,
		Intensity:              intensity,
		Name:                   name,
		Organization:           org,
		Address:                address,
		LogPaths:               splitCSV(logPathsRaw),
		ObserveTraffic:         observeTraffic,
		AllowLogIngestion:      allowLogs,
		AuthorizationConfirmed: authorized,
		ConsentSandbox:         true,
		ConsentFakeDB:          true,
		ConsentAuth:            true,
		ConsentLoad:            true,
		ConsentResponsibility:  true,
	})
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("Session created: %s\n", resp.Session.ID)
	fmt.Printf("Dashboard: %s\n", resp.DashboardURL)
	fmt.Println()

	return watchSession(resp.Session.ID, true, reader)
}

func runResumeSession(reader *bufio.Reader) error {
	cfg := config.Load()
	gateway := client.NewGatewayClient(cfg.GatewayURL)
	resp, err := gateway.ListSessions()
	if err != nil {
		return err
	}
	if len(resp.Sessions) == 0 {
		fmt.Println("No sessions found.")
		_, _ = prompt(reader, "Press Enter to continue", "")
		return nil
	}

	fmt.Println()
	fmt.Println("Sessions")
	fmt.Println("--------")
	for i, session := range resp.Sessions {
		fmt.Printf("%d. %s  %s  %s\n", i+1, session.ID, strings.ToUpper(session.Phase), session.TargetURL)
	}
	fmt.Println()

	choice, err := prompt(reader, "Choose session number or enter session id", "")
	if err != nil {
		return err
	}
	sessionID := strings.TrimSpace(choice)
	if idx, convErr := strconv.Atoi(sessionID); convErr == nil && idx >= 1 && idx <= len(resp.Sessions) {
		sessionID = resp.Sessions[idx-1].ID
	}
	if sessionID == "" {
		return nil
	}
	return watchSession(sessionID, true, reader)
}

func runInteractiveIntel(reader *bufio.Reader) error {
	fmt.Println()
	fmt.Println("Threat Intel")
	fmt.Println("------------")
	query, err := prompt(reader, "Enter CVE IDs (comma separated) or raw text", "")
	if err != nil {
		return err
	}
	if strings.TrimSpace(query) == "" {
		return nil
	}

	parts := splitCSV(query)
	if len(parts) == 1 && strings.HasPrefix(strings.ToUpper(parts[0]), "CVE-") {
		return runIntel([]string{parts[0]})
	}
	return runIntel(append([]string{"--attack-result", query}, parts...))
}

func printBanner() {
	fmt.Print("\033[H\033[2J")
	fmt.Println(`███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗`)
	fmt.Println(`██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝`)
	fmt.Println(`███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  `)
	fmt.Println(`╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  `)
	fmt.Println(`███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗`)
	fmt.Println(`╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝`)
	fmt.Println("SPECTRE Interactive CLI")
	fmt.Println()
}

func prompt(reader *bufio.Reader, label, defaultValue string) (string, error) {
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", label, defaultValue)
	} else {
		fmt.Printf("%s: ", label)
	}
	value, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

func promptChoice(reader *bufio.Reader, label string, options []string, defaultValue string) (string, error) {
	fmt.Printf("%s (%s)\n", label, strings.Join(options, "/"))
	for {
		value, err := prompt(reader, label, defaultValue)
		if err != nil {
			return "", err
		}
		for _, option := range options {
			if strings.EqualFold(value, option) {
				return strings.ToLower(option), nil
			}
		}
		fmt.Println("Choose one of:", strings.Join(options, ", "))
	}
}

func promptYesNo(reader *bufio.Reader, label string, defaultYes bool) (bool, error) {
	defaultValue := "y/N"
	if defaultYes {
		defaultValue = "Y/n"
	}
	value, err := prompt(reader, label, defaultValue)
	if err != nil {
		return false, err
	}
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" || trimmed == "y/n" || trimmed == "y" || trimmed == "yes" || trimmed == "default" || trimmed == "default yes" || trimmed == "default no" {
		return defaultYes, nil
	}
	if trimmed == "n" || trimmed == "no" {
		return false, nil
	}
	return defaultYes, nil
}
