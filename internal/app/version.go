package app

import (
	"fmt"
	"os"
	"strings"
)

// Version is set at build time via:
// go build -ldflags "-X agentproxy/internal/app.Version=vX.Y.Z" ./cmd/agentproxy
var Version = "dev"

func runVersion(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: agentproxy version")
		return 1
	}
	fmt.Println(formatVersion())
	return 0
}

func formatVersion() string {
	v := strings.TrimSpace(Version)
	if v == "" {
		v = "dev"
	}
	return fmt.Sprintf("agentproxy version %s", v)
}
