package app

import (
	"fmt"
	"os"
	"path/filepath"
)

func printUsage() {
	prog := filepath.Base(os.Args[0])
	fmt.Printf(`%s monitors outbound LLM API requests via a local proxy.

Usage:
  %s setup-ca [--dir DIR] [--name NAME] [--overwrite]
  %s ca rotate [--dir DIR] [--name NAME]
  %s ca revoke [--dir DIR]
  %s ca status [--dir DIR]
  %s run [--listen ADDR] [--dir DIR] [--rules FILE] [--block] [--autoblock-high-risk] [--tail] [--retention 7d]
  %s events tail [--dir DIR] [--limit N] [--follow]
  %s events prune [--dir DIR] [--older-than 7d]
  %s rules add-regex [--dir DIR|--file FILE] --name NAME --regex REGEX [--risk low|medium|high] [--block] [--replace]
  %s rules list [--dir DIR|--file FILE]
  %s report [--dir DIR] [--since 24h]
  %s version

Examples:
  %s setup-ca
  %s ca rotate
  %s rules add-regex --name customer_id --regex "CUST-[0-9]{6}" --risk high --block
  %s run --listen 127.0.0.1:8787 --block --autoblock-high-risk --tail --retention 7d
  %s version
  %s events prune --older-than 7d
`, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog)
}
