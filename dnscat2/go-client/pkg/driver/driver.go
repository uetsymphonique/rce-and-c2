// Package driver implements the dnscat2 driver interface and implementations.
package driver

// Type represents the type of driver
type Type int

const (
	TypeConsole Type = iota
	TypeExec
	TypeCommand
	TypePing
)

// Driver interface defines the common interface for all drivers
type Driver interface {
	// DataReceived is called when data is received from the session
	DataReceived(data []byte)

	// GetOutgoing returns data to be sent, returns nil when driver is done
	GetOutgoing(maxLength int) []byte

	// Close closes the driver
	Close()

	// IsClosed returns true if driver is shut down
	IsClosed() bool
}
