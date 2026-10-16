//go:build !windows

package probe

import "syscall"

var (
	errnoRefused     = []syscall.Errno{syscall.ECONNREFUSED}
	errnoUnreachable = []syscall.Errno{syscall.ENETUNREACH, syscall.EHOSTUNREACH}
	errnoReset       = []syscall.Errno{syscall.ECONNRESET, syscall.EPIPE}
	errnoTimedOut    = []syscall.Errno{syscall.ETIMEDOUT}
)
