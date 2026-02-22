package util

import (
	"os"
	"path/filepath"
)

func DefaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".agentproxy"
	}
	return filepath.Join(home, ".agentproxy")
}

func EnsureDir(path string) error {
	return os.MkdirAll(path, 0o755)
}

func CACertPath(dir string) string {
	return filepath.Join(dir, "ca_cert.pem")
}

func CAKeyPath(dir string) string {
	return filepath.Join(dir, "ca_key.pem")
}

func RevokedCADir(dir string) string {
	return filepath.Join(dir, "revoked")
}

func EventsPath(dir string) string {
	return filepath.Join(dir, "events.jsonl")
}

func RulesPath(dir string) string {
	return filepath.Join(dir, "rules.json")
}
