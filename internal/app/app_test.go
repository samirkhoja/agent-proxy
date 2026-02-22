package app

import "testing"

func TestParseSince(t *testing.T) {
	cases := map[string]string{
		"1h": "1h0m0s",
		"2d": "48h0m0s",
		"0":  "0s",
	}
	for in, want := range cases {
		d, err := parseSince(in)
		if err != nil {
			t.Fatalf("parseSince(%q) error: %v", in, err)
		}
		if d.String() != want {
			t.Fatalf("parseSince(%q)=%s want %s", in, d.String(), want)
		}
	}
}

func TestValidateLoopbackListen(t *testing.T) {
	if err := validateLoopbackListen("127.0.0.1:8787"); err != nil {
		t.Fatalf("expected loopback address to pass: %v", err)
	}
	if err := validateLoopbackListen("localhost:8787"); err != nil {
		t.Fatalf("expected localhost address to pass: %v", err)
	}
	if err := validateLoopbackListen("0.0.0.0:8787"); err == nil {
		t.Fatalf("expected wildcard address to fail")
	}
}
