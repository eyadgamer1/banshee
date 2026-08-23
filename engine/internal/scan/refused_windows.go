//go:build windows

package scan

import "syscall"

// WSAECONNREFUSED — Windows reports an actively-refused connect with this errno.
const syscallRefused = syscall.Errno(10061)
