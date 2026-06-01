//go:build stealth

package dlog

import "io"

func Println(a ...any)                             {}
func Printf(format string, a ...any)               {}
func Fprintf(_ io.Writer, _ string, _ ...any)      {}
