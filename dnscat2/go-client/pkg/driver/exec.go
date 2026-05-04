package driver

import (
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// ExecDriver implements a driver that executes a process
type ExecDriver struct {
	cmd          *exec.Cmd
	stdin        io.WriteCloser
	outgoingData []byte
	mu           sync.Mutex
	isShutdown   bool
	process      string
}

// isShellCommand checks if the command is an interactive shell
func isShellCommand(process string) bool {
	p := strings.ToLower(strings.TrimSpace(process))
	if runtime.GOOS == "windows" {
		return p == "cmd" || p == "cmd.exe" || p == "powershell" || p == "powershell.exe"
	}
	return p == "sh" || p == "/bin/sh" || p == "bash" || p == "/bin/bash" || 
		p == "zsh" || p == "/bin/zsh" || p == "/usr/bin/bash" || p == "/usr/bin/zsh"
}

// NewExecDriver creates a new exec driver
func NewExecDriver(process string) (*ExecDriver, error) {
	d := &ExecDriver{
		process: process,
	}

	// For shell commands, run directly without wrapper
	// For other commands, wrap in shell to handle pipes, redirects, etc.
	if isShellCommand(process) {
		// Interactive shell - run directly
		if runtime.GOOS == "windows" {
			d.cmd = exec.Command(process)
		} else {
			d.cmd = exec.Command(process)
		}
	} else {
		// Command string - wrap in shell
		if runtime.GOOS == "windows" {
			d.cmd = exec.Command("cmd.exe", "/c", process)
		} else {
			d.cmd = exec.Command("/bin/sh", "-c", process)
		}
	}

	// Get stdin pipe
	stdin, err := d.cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	d.stdin = stdin

	// Get stdout pipe
	stdout, err := d.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	// Get stderr pipe (merge with stdout)
	d.cmd.Stderr = d.cmd.Stdout

	// Start the process
	if err := d.cmd.Start(); err != nil {
		return nil, err
	}

	// Read stdout in goroutine
	go d.readOutput(stdout)

	// Wait for process in goroutine
	go func() {
		d.cmd.Wait()
		d.mu.Lock()
		d.isShutdown = true
		d.mu.Unlock()
	}()

	return d, nil
}

func (d *ExecDriver) readOutput(r io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			d.mu.Lock()
			d.outgoingData = append(d.outgoingData, buf[:n]...)
			d.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// DataReceived writes data to the process stdin
func (d *ExecDriver) DataReceived(data []byte) {
	if d.stdin != nil {
		d.stdin.Write(data)
	}
}

// GetOutgoing returns data from process stdout
func (d *ExecDriver) GetOutgoing(maxLength int) []byte {
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

// Close closes the driver and terminates the process
func (d *ExecDriver) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.isShutdown {
		return
	}

	d.isShutdown = true

	if d.stdin != nil {
		d.stdin.Close()
	}

	if d.cmd != nil && d.cmd.Process != nil {
		d.cmd.Process.Kill()
	}
}

// IsClosed returns true if driver is shut down
func (d *ExecDriver) IsClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isShutdown
}
