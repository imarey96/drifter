package main

import (
	"os"

	"github.com/imarey96/drifter/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
