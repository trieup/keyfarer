//go:build !windows

package secrets

import (
	"errors"
	"os"
	"syscall"
)

// processAlive reports whether a process with the given pid currently exists.
// Signal 0 performs the standard existence check without delivering a signal;
// EPERM means the process exists but is owned by another user.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
