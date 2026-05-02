package main

import (
	"fmt"
	"os"

	"github.com/TyrusRC/swiss-knife-for-web-security/cmd/skws/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
