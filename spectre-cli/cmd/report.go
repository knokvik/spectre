package cmd

import "fmt"

func runReport(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: spectre report <session_id>")
	}
	fmt.Printf("Report generation is not wired yet for session %s.\n", args[0])
	fmt.Println("Next planned step: persist session artifacts and expose a report endpoint from the gateway.")
	return nil
}
