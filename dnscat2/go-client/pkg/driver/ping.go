package driver

import (
	"fmt"
	"math/rand"
	"os"
)

const PingLength = 16

// PingDriver implements a ping driver for testing server connectivity
type PingDriver struct {
	data       []byte
	isShutdown bool
	alreadySent bool
}

// NewPingDriver creates a new ping driver with random data
func NewPingDriver() *PingDriver {
	data := make([]byte, PingLength)
	for i := 0; i < PingLength; i++ {
		data[i] = byte(rand.Intn(26) + 'a')
	}

	return &PingDriver{
		data: data,
	}
}

// DataReceived handles ping response
func (d *PingDriver) DataReceived(data []byte) {
	if string(data) == string(d.data) {
		fmt.Println("Ping response received! This seems like a valid dnscat2 server.")
		os.Exit(0)
	} else {
		fmt.Println("Ping response received, but it didn't contain the right data!")
		fmt.Printf("Expected: %s\n", string(d.data))
		fmt.Printf("Received: %s\n", string(data))
		fmt.Println()
		fmt.Println("The only reason this can happen is if something is messing with")
		fmt.Println("your DNS traffic.")
	}
}

// GetOutgoing returns ping data (only once)
func (d *PingDriver) GetOutgoing(maxLength int) []byte {
	if d.alreadySent {
		return []byte{}
	}
	d.alreadySent = true

	if PingLength > maxLength && maxLength > 0 {
		fmt.Println("Sorry, the ping packet is too long to respect the protocol's length restrictions :(")
		os.Exit(1)
	}

	result := make([]byte, PingLength)
	copy(result, d.data)
	return result
}

// Close closes the driver
func (d *PingDriver) Close() {
	d.isShutdown = true
}

// IsClosed returns true if driver is shut down
func (d *PingDriver) IsClosed() bool {
	return d.isShutdown
}


