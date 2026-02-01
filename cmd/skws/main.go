package main

import (
	"fmt"
	"os"

	"github.com/swiss-knife-for-web-security/skws/cmd/skws/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
