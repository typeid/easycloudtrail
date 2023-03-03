package main

import (
	"os"

	"srep-cloudtrail/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
