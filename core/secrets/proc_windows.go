//go:build windows

package secrets

import "os"

// processAlive reports whether a process with the given pid currently exists.
// On Windows os.FindProcess opens the process handle and fails when the process
// is gone, which is a good-enough liveness signal for run cleanup.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = proc.Release()
	return true
}
