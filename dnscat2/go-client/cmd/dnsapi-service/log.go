//go:build windows && !stealth

package main

import "os"

func logError(msg string) {
	name := DefaultServiceName
	if name == "" {
		name = "svc"
	}
	f, err := os.OpenFile(name+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(msg + "\n")
}
