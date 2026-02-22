//go:build !windows

package util

import "os"

func IsElevated() bool {
	return os.Geteuid() == 0
}
