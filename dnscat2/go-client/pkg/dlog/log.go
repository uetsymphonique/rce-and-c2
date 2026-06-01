//go:build !stealth

package dlog

import (
	"fmt"
	"io"
)

func Println(a ...any)                             { fmt.Println(a...) }
func Printf(format string, a ...any)               { fmt.Printf(format, a...) }
func Fprintf(w io.Writer, format string, a ...any) { fmt.Fprintf(w, format, a...) }
