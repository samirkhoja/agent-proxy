package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/model"
	"github.com/samirkhoja/agent-proxy/internal/store"
	"github.com/samirkhoja/agent-proxy/internal/util"
)

func runEvents(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentproxy events [tail|prune] [flags]")
		return 1
	}
	switch args[0] {
	case "tail":
		return runEventsTail(args[1:])
	case "prune":
		return runEventsPrune(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown events command: %s\n", args[0])
		return 1
	}
}

func runEventsTail(args []string) int {
	fs := flag.NewFlagSet("events tail", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", util.DefaultDataDir(), "agentproxy data directory")
	limit := fs.Int("limit", 20, "number of recent events to print")
	follow := fs.Bool("follow", false, "keep printing as new events arrive")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := util.EventsPath(*dir)
	events, err := store.ReadAll(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed reading events: %v\n", err)
		return 1
	}
	start := 0
	if *limit > 0 && len(events) > *limit {
		start = len(events) - *limit
	}
	for _, e := range events[start:] {
		printEventLine(e)
	}

	if !*follow {
		return 0
	}
	return followEvents(path)
}

func runEventsPrune(args []string) int {
	fs := flag.NewFlagSet("events prune", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", util.DefaultDataDir(), "agentproxy data directory")
	olderThan := fs.String("older-than", defaultRetention, "remove events older than this duration")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dur, err := parseSince(*olderThan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --older-than: %v\n", err)
		return 1
	}
	if dur <= 0 {
		fmt.Fprintln(os.Stderr, "--older-than must be > 0")
		return 1
	}

	kept, removed, err := store.PruneOlderThan(util.EventsPath(*dir), time.Now().Add(-dur))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed pruning events: %v\n", err)
		return 1
	}
	fmt.Printf("events prune: removed=%d kept=%d\n", removed, kept)
	return 0
}

func followEvents(path string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var offset int64
	if st, err := os.Stat(path); err == nil {
		offset = st.Size()
	}

	for {
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(1 * time.Second):
			st, err := os.Stat(path)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				fmt.Fprintf(os.Stderr, "tail stat error: %v\n", err)
				continue
			}
			if st.Size() < offset {
				// File shrank (rotation/truncate), so restart from beginning.
				offset = 0
			}
			if st.Size() == offset {
				continue
			}
			f, err := os.Open(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "tail open error: %v\n", err)
				continue
			}
			_, _ = f.Seek(offset, 0)
			s := bufio.NewScanner(f)
			s.Buffer(make([]byte, 64*1024), maxTailEventLineBytes)
			for s.Scan() {
				line := strings.TrimSpace(s.Text())
				if line == "" {
					continue
				}
				var e model.Event
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					continue
				}
				printEventLine(e)
			}
			if err := s.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "tail scan error: %v\n", err)
			}
			offset, _ = f.Seek(0, 2)
			_ = f.Close()
		}
	}
}
