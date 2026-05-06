//go:build windows

package main

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// getSystemDNS reads DNS servers from the Windows registry.
// It enumerates all TCP/IP interface GUIDs and returns the first
// non-empty DNS server found, preferring static NameServer over DhcpNameServer.
func getSystemDNS() string {
	const ifacesKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`

	root, err := registry.OpenKey(registry.LOCAL_MACHINE, ifacesKey, registry.READ)
	if err != nil {
		return ""
	}
	defer root.Close()

	guids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return ""
	}

	for _, guid := range guids {
		ikey, err := registry.OpenKey(root, guid, registry.READ)
		if err != nil {
			continue
		}

		for _, valName := range []string{"NameServer", "DhcpNameServer"} {
			val, _, err := ikey.GetStringValue(valName)
			if err != nil || val == "" {
				continue
			}
			// Values may be comma- or space-separated (e.g. "10.12.10.10 8.8.8.8")
			for _, srv := range strings.FieldsFunc(val, func(r rune) bool {
				return r == ',' || r == ' '
			}) {
				srv = strings.TrimSpace(srv)
				if srv != "" && srv != "0.0.0.0" {
					ikey.Close()
					return srv
				}
			}
		}
		ikey.Close()
	}
	return ""
}
