//go:build !windows

package main

import (
	"os"
	"strings"
)

// getSystemDNS reads the first nameserver from /etc/resolv.conf.
func getSystemDNS() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			if parts := strings.Fields(line); len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}
