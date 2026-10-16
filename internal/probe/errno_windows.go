//go:build windows

package probe

import "syscall"

// Windows reports socket errors as WSA codes; Go's syscall.ECONNREFUSED and
// friends are invented values there and never match.
var (
	errnoRefused     = []syscall.Errno{10061, 1225}                     // WSAECONNREFUSED, ERROR_CONNECTION_REFUSED
	errnoUnreachable = []syscall.Errno{10050, 10051, 10065, 1231, 1232} // WSAENETDOWN, WSAENETUNREACH, WSAEHOSTUNREACH, ERROR_NETWORK_UNREACHABLE, ERROR_HOST_UNREACHABLE
	errnoReset       = []syscall.Errno{10054, 10053, 64, 1236}          // WSAECONNRESET, WSAECONNABORTED, ERROR_NETNAME_DELETED, ERROR_CONNECTION_ABORTED
	errnoTimedOut    = []syscall.Errno{10060, 121}                      // WSAETIMEDOUT, ERROR_SEM_TIMEOUT
)
