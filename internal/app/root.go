package app

import (
	"fmt"
	"os"
)

const defaultRetention = "7d"
const maxTailEventLineBytes = 16 << 20

func Run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 1
	}

	switch args[0] {
	case "setup-ca":
		return runSetupCA(args[1:])
	case "ca":
		return runCA(args[1:])
	case "run":
		return runProxy(args[1:])
	case "events":
		return runEvents(args[1:])
	case "rules":
		return runRules(args[1:])
	case "report":
		return runReport(args[1:])
	case "version", "-v", "--version":
		return runVersion(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
		printUsage()
		return 1
	}
}
