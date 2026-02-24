package main

import (
	"os"

	"github.com/easyenclave/easyenclave/v2/internal/eectl/root"
)

func main() {
	os.Exit(root.Run(os.Args[1:], os.Stdout, os.Stderr))
}
