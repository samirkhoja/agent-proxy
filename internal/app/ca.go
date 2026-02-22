package app

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/proxy"
	"github.com/samirkhoja/agent-proxy/internal/util"
)

func runSetupCA(args []string) int {
	fs := flag.NewFlagSet("setup-ca", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", util.DefaultDataDir(), "agentproxy data directory")
	name := fs.String("name", "agentproxy Local CA", "certificate authority common name")
	overwrite := fs.Bool("overwrite", false, "overwrite existing CA cert/key if present")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if err := util.EnsureDir(*dir); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create data directory: %v\n", err)
		return 1
	}

	ca, err := proxy.SetupCA(*dir, *name, *overwrite)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup-ca failed: %v\n", err)
		return 1
	}

	fmt.Println("CA ready")
	fmt.Printf("  cert: %s\n", ca.CertPath)
	fmt.Printf("  key: %s\n", ca.KeyPath)
	fmt.Printf("  sha256: %s\n", ca.CertSHA256)
	fmt.Println()
	fmt.Println("Trust this CA in your OS/app trust store to enable HTTPS payload inspection.")
	return 0
}

func runCA(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentproxy ca [rotate|revoke|status] [flags]")
		return 1
	}
	switch args[0] {
	case "rotate":
		return runCARotate(args[1:])
	case "revoke":
		return runCARevoke(args[1:])
	case "status":
		return runCAStatus(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown ca command: %s\n", args[0])
		return 1
	}
}

func runCARotate(args []string) int {
	fs := flag.NewFlagSet("ca rotate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", util.DefaultDataDir(), "agentproxy data directory")
	name := fs.String("name", "agentproxy Local CA", "certificate authority common name")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if err := util.EnsureDir(*dir); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create data directory: %v\n", err)
		return 1
	}

	result, err := proxy.RotateCA(*dir, *name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ca rotate failed: %v\n", err)
		return 1
	}

	fmt.Println("CA rotated")
	if result.ArchivedCertPath != "" {
		fmt.Printf("  archived old cert: %s\n", result.ArchivedCertPath)
	}
	if result.ArchivedKeyPath != "" {
		fmt.Printf("  archived old key: %s\n", result.ArchivedKeyPath)
	}
	fmt.Printf("  new cert: %s\n", result.NewCA.CertPath)
	fmt.Printf("  new key: %s\n", result.NewCA.KeyPath)
	fmt.Printf("  new sha256: %s\n", result.NewCA.CertSHA256)
	fmt.Println("Update your trust store to trust the new cert and remove the old one.")
	return 0
}

func runCARevoke(args []string) int {
	fs := flag.NewFlagSet("ca revoke", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", util.DefaultDataDir(), "agentproxy data directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	result, err := proxy.RevokeCA(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ca revoke failed: %v\n", err)
		return 1
	}
	fmt.Println("CA revoked")
	if result.RevokedCertPath != "" {
		fmt.Printf("  revoked cert moved to: %s\n", result.RevokedCertPath)
	}
	if result.RevokedKeyPath != "" {
		fmt.Printf("  revoked key moved to: %s\n", result.RevokedKeyPath)
	}
	fmt.Println("Remove the cert from your OS/app trust store to fully disable trust.")
	return 0
}

func runCAStatus(args []string) int {
	fs := flag.NewFlagSet("ca status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", util.DefaultDataDir(), "agentproxy data directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ca, err := proxy.LoadCA(util.CACertPath(*dir), util.CAKeyPath(*dir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "no active CA: %v\n", err)
		return 1
	}

	keyInfo, err := os.Stat(ca.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stat key failed: %v\n", err)
		return 1
	}
	fmt.Println("CA status")
	fmt.Printf("  cert: %s\n", ca.CertPath)
	fmt.Printf("  key: %s\n", ca.KeyPath)
	fmt.Printf("  sha256: %s\n", ca.CertSHA256)
	fmt.Printf("  key mode: %04o\n", keyInfo.Mode().Perm())
	fmt.Printf("  expires: %s\n", ca.Cert.NotAfter.UTC().Format(time.RFC3339))
	return 0
}
