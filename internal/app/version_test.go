package app

import "testing"

func TestFormatVersion(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })

	Version = "v1.2.3"
	if got := formatVersion(); got != "agentproxy version v1.2.3" {
		t.Fatalf("formatVersion()=%q", got)
	}
}

func TestFormatVersionDefaultsToDev(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })

	Version = "   "
	if got := formatVersion(); got != "agentproxy version dev" {
		t.Fatalf("formatVersion()=%q", got)
	}
}
