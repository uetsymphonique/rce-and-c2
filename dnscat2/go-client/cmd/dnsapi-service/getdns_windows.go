//go:build windows

package main

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// getSystemDNS reads DNS servers from the Windows registry and returns the
// most appropriate one for C2 DNS tunnelling.
//
// Selection order (highest priority first):
//  1. Static NameServer entries across all interfaces (non-DHCP)
//  2. DHCP-assigned DhcpNameServer entries across all interfaces
//
// Within each tier, servers are de-duplicated and returned in the order they
// appear across interfaces. The first candidate is returned so that a static
// DNS on any interface always beats a DHCP-assigned one, regardless of which
// interface's registry key happens to be enumerated first.
func getSystemDNS() string {
	candidates := collectDNSServers()
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// collectDNSServers returns all DNS server addresses found in the registry,
// static entries first (pass 1), then DHCP-assigned (pass 2).
// Duplicates are suppressed; "0.0.0.0" entries are skipped.
func collectDNSServers() []string {
	const ifacesKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`

	root, err := registry.OpenKey(registry.LOCAL_MACHINE, ifacesKey, registry.READ)
	if err != nil {
		return nil
	}
	defer root.Close()

	guids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	split := func(val string) []string {
		var out []string
		for _, srv := range strings.FieldsFunc(val, func(r rune) bool {
			return r == ',' || r == ' '
		}) {
			srv = strings.TrimSpace(srv)
			if srv != "" && srv != "0.0.0.0" {
				out = append(out, srv)
			}
		}
		return out
	}

	seen := make(map[string]bool)
	var result []string

	appendUniq := func(servers []string) {
		for _, s := range servers {
			if !seen[s] {
				seen[s] = true
				result = append(result, s)
			}
		}
	}

	// Pass 1: static NameServer across all interfaces
	for _, guid := range guids {
		ikey, err := registry.OpenKey(root, guid, registry.READ)
		if err != nil {
			continue
		}
		val, _, err := ikey.GetStringValue("NameServer")
		ikey.Close()
		if err == nil && val != "" {
			appendUniq(split(val))
		}
	}

	// Pass 2: DHCP-assigned DNS across all interfaces
	for _, guid := range guids {
		ikey, err := registry.OpenKey(root, guid, registry.READ)
		if err != nil {
			continue
		}
		val, _, err := ikey.GetStringValue("DhcpNameServer")
		ikey.Close()
		if err == nil && val != "" {
			appendUniq(split(val))
		}
	}

	return result
}
