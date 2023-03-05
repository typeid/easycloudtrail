package main

import (
	"os"

	"easycloudtrail/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
