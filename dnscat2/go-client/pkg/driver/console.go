package driver

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sync"
)

// ConsoleDriver implements a console driver that reads from stdin and writes to stdout
type ConsoleDriver struct {
	outgoingData []byte
	mu           sync.Mutex
	isShutdown   bool
	stdinDone    chan struct{}
}

// NewConsoleDriver creates a new console driver
func NewConsoleDriver() *ConsoleDriver {
	d := &ConsoleDriver{
		stdinDone: make(chan struct{}),
	}

	// Start reading from stdin in a goroutine
	go d.readStdin()

	return d
}

func (d *ConsoleDriver) readStdin() {
	defer close(d.stdinDone)

	reader := bufio.NewReader(os.Stdin)
	buf := make([]byte, 4096)

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			d.mu.Lock()
			d.outgoingData = append(d.outgoingData, buf[:n]...)
			d.mu.Unlock()
		}

		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			}
			d.mu.Lock()
			d.isShutdown = true
			d.mu.Unlock()
			return
		}
	}
}

// DataReceived writes received data to stdout
func (d *ConsoleDriver) DataReceived(data []byte) {
	os.Stdout.Write(data)
}

// GetOutgoing returns data waiting to be sent
func (d *ConsoleDriver) GetOutgoing(maxLength int) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()

	// If shutdown and no data, return nil to signal session should close
	if d.isShutdown && len(d.outgoingData) == 0 {
		return nil
	}

	if len(d.outgoingData) == 0 {
		return []byte{}
	}

	// Calculate how much to send
	sendLen := len(d.outgoingData)
	if maxLength > 0 && sendLen > maxLength {
		sendLen = maxLength
	}

	result := make([]byte, sendLen)
	copy(result, d.outgoingData[:sendLen])
	d.outgoingData = d.outgoingData[sendLen:]

	return result
}

// Close closes the driver
func (d *ConsoleDriver) Close() {
	d.mu.Lock()
	d.isShutdown = true
	d.mu.Unlock()
}

// IsClosed returns true if driver is shut down
func (d *ConsoleDriver) IsClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isShutdown
}


