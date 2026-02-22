package main

import (
	"os"

	"github.com/samirkhoja/agent-proxy/internal/app"
)

func main() {
	os.Exit(app.Run(os.Args[1:]))
}
