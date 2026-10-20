package main

import (
	"os"

	"reconflow/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr)) }
