package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/config"
	"github.com/samirkhoja/agent-proxy/internal/model"
	"github.com/samirkhoja/agent-proxy/internal/proxy"
	"github.com/samirkhoja/agent-proxy/internal/store"
	"github.com/samirkhoja/agent-proxy/internal/util"
)

func runProxy(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", "127.0.0.1:8787", "proxy listen address (loopback only)")
	dir := fs.String("dir", util.DefaultDataDir(), "agentproxy data directory")
	rulesPath := fs.String("rules", "", "path to rules.json")
	block := fs.Bool("block", false, "block sensitive requests")
	autoBlockHighRisk := fs.Bool("autoblock-high-risk", false, "automatically block high-risk findings")
	tail := fs.Bool("tail", true, "print events live while proxy is running (set --tail=false to disable)")
	retention := fs.String("retention", defaultRetention, "event retention window, e.g. 24h, 7d, 0(disable prune)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if util.IsElevated() {
		fmt.Fprintln(os.Stderr, "refusing to run proxy as root; start agentproxy as an unprivileged user")
		return 1
	}
	if err := validateLoopbackListen(*listen); err != nil {
		fmt.Fprintf(os.Stderr, "invalid --listen: %v\n", err)
		return 1
	}

	if err := util.EnsureDir(*dir); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create data directory: %v\n", err)
		return 1
	}

	effectiveRulesPath := strings.TrimSpace(*rulesPath)
	if effectiveRulesPath == "" {
		defaultRulesPath := util.RulesPath(*dir)
		if _, err := os.Stat(defaultRulesPath); err == nil {
			effectiveRulesPath = defaultRulesPath
		}
	}

	rules, err := config.LoadRules(effectiveRulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load rules: %v\n", err)
		return 1
	}

	retentionDur, err := parseSince(*retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --retention: %v\n", err)
		return 1
	}
	if retentionDur > 0 {
		_, removed, err := store.PruneOlderThan(util.EventsPath(*dir), time.Now().Add(-retentionDur))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed pruning old events: %v\n", err)
			return 1
		}
		if removed > 0 {
			fmt.Printf("pruned %d old events (older than %s)\n", removed, retentionDur)
		}
	}

	var outMu sync.Mutex
	var eventSink func(model.Event)
	if *tail {
		eventSink = func(e model.Event) {
			outMu.Lock()
			defer outMu.Unlock()
			printEventLine(e)
		}
	}

	srv, err := proxy.NewServer(proxy.Options{
		Listen:            *listen,
		DataDir:           *dir,
		Rules:             rules,
		BlockOnSensitive:  *block,
		AutoBlockHighRisk: *autoBlockHighRisk,
		AsyncEventWrite:   true,
		EventSink:         eventSink,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create proxy server: %v\n", err)
		if strings.Contains(err.Error(), "load ca") {
			fmt.Fprintf(os.Stderr, "run `agentproxy setup-ca --dir %s` first\n", *dir)
		}
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Println(formatVersion())
	fmt.Println("startup:")
	fmt.Printf("  listen: %s\n", *listen)
	fmt.Printf("  events: %s\n", util.EventsPath(*dir))
	if effectiveRulesPath != "" {
		fmt.Printf("  rules: %s\n", effectiveRulesPath)
	}
	fmt.Printf("  retention: %s\n", *retention)
	fmt.Printf("  autoblock-high-risk: %t\n", *autoBlockHighRisk)
	fmt.Printf("  tail: %t\n", *tail)
	fmt.Printf("  proxy endpoint: http://%s\n", *listen)

	err = srv.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "proxy exited with error: %v\n", err)
		return 1
	}
	return 0
}

func parseSince(input string) (time.Duration, error) {
	if input == "0" {
		return 0, nil
	}
	if strings.HasSuffix(input, "d") {
		days := strings.TrimSuffix(input, "d")
		v, err := strconv.ParseFloat(days, 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(v * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(input)
}

func validateLoopbackListen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" {
		return errors.New("host cannot be empty; use 127.0.0.1 or localhost")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("host %q is not loopback", host)
	}
	return nil
}
