package main

import (
	"fmt"
	"os"

	"github.com/spectre/spectre-cli/cmd"
)

func main() {
	if err := cmd.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "spectre: %v\n", err)
		os.Exit(1)
	}
}
