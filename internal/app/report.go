package app

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/model"
	"github.com/samirkhoja/agent-proxy/internal/store"
	"github.com/samirkhoja/agent-proxy/internal/util"
)

func runReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", util.DefaultDataDir(), "agentproxy data directory")
	since := fs.String("since", "24h", "lookback duration (e.g. 1h, 24h, 7d)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	dur, err := parseSince(*since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --since: %v\n", err)
		return 1
	}

	events, err := store.ReadAll(util.EventsPath(*dir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed reading events: %v\n", err)
		return 1
	}

	cutoff := time.Now().Add(-dur)
	providerCounts := map[string]int{}
	findingCounts := map[string]int{}
	total := 0
	sensitive := 0
	blocked := 0

	for _, e := range events {
		if e.Timestamp.Before(cutoff) {
			continue
		}
		total++
		providerCounts[e.Provider]++
		if e.Sensitive {
			sensitive++
		}
		if e.Action == model.ActionBlock {
			blocked++
		}
		for _, f := range e.Findings {
			findingCounts[f.Name] += f.Count
		}
	}

	fmt.Println("report:")
	fmt.Printf("  window: %s\n", dur)
	fmt.Printf("  total: %d\n", total)
	fmt.Printf("  sensitive: %d\n", sensitive)
	fmt.Printf("  blocked: %d\n", blocked)
	fmt.Println()
	fmt.Println("providers:")
	printSortedMap(providerCounts)
	fmt.Println()
	fmt.Println("findings:")
	printSortedMap(findingCounts)
	return 0
}

func printSortedMap(m map[string]int) {
	if len(m) == 0 {
		fmt.Println("  (none)")
		return
	}
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k: k, v: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v == pairs[j].v {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v > pairs[j].v
	})
	for _, p := range pairs {
		fmt.Printf("  %s: %d\n", p.k, p.v)
	}
}
