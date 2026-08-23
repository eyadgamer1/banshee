//go:build !windows

package scan

import "syscall"

const syscallRefused = syscall.ECONNREFUSED
