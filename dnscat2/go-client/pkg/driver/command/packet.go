// Package command implements the dnscat2 command protocol.
package command

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// PacketType represents command packet types
type PacketType uint16

const (
	CommandPing     PacketType = 0x0000
	CommandShell    PacketType = 0x0001
	CommandExec     PacketType = 0x0002
	CommandDownload PacketType = 0x0003
	CommandUpload   PacketType = 0x0004
	CommandShutdown PacketType = 0x0005
	CommandDelay    PacketType = 0x0006

	TunnelConnect PacketType = 0x1000
	TunnelData    PacketType = 0x1001
	TunnelClose   PacketType = 0x1002

	CommandError PacketType = 0xFFFF
)

// TunnelStatus constants
const (
	TunnelStatusFail uint16 = 0x8000
)

// Packet represents a command protocol packet
type Packet struct {
	RequestID uint16
	CommandID PacketType
	IsRequest bool

	// Request bodies
	PingRequest           *PingRequest
	ShellRequest          *ShellRequest
	ExecRequest           *ExecRequest
	DownloadRequest       *DownloadRequest
	UploadRequest         *UploadRequest
	ShutdownRequest       *ShutdownRequest
	DelayRequest          *DelayRequest
	TunnelConnectRequest  *TunnelConnectRequest
	TunnelDataRequest     *TunnelDataRequest
	TunnelCloseRequest    *TunnelCloseRequest
	ErrorRequest          *ErrorRequest

	// Response bodies
	PingResponse           *PingResponse
	ShellResponse          *ShellResponse
	ExecResponse           *ExecResponse
	DownloadResponse       *DownloadResponse
	UploadResponse         *UploadResponse
	ShutdownResponse       *ShutdownResponse
	DelayResponse          *DelayResponse
	TunnelConnectResponse  *TunnelConnectResponse
	ErrorResponse          *ErrorResponse
}

// Request types
type PingRequest struct {
	Data string
}

type ShellRequest struct {
	Name string
}

type ExecRequest struct {
	Name    string
	Command string
}

type DownloadRequest struct {
	Filename string
}

type UploadRequest struct {
	Filename string
	Data     []byte
}

type ShutdownRequest struct{}

type DelayRequest struct {
	Delay uint32
}

type TunnelConnectRequest struct {
	Options uint32
	Host    string
	Port    uint16
}

type TunnelDataRequest struct {
	TunnelID uint32
	Data     []byte
}

type TunnelCloseRequest struct {
	TunnelID uint32
	Reason   string
}

type ErrorRequest struct {
	Status uint16
	Reason string
}

// Response types
type PingResponse struct {
	Data string
}

type ShellResponse struct {
	SessionID uint16
}

type ExecResponse struct {
	SessionID uint16
}

type DownloadResponse struct {
	Data []byte
}

type UploadResponse struct{}

type ShutdownResponse struct{}

type DelayResponse struct{}

type TunnelConnectResponse struct {
	Status   uint16
	TunnelID uint32
}

type ErrorResponse struct {
	Status uint16
	Reason string
}

// ReadPacket reads a command packet from a buffer
func ReadPacket(buf *bytes.Buffer) (*Packet, error) {
	if buf.Len() < 4 {
		return nil, nil // Not enough data yet
	}

	// Peek at length
	lengthBytes := buf.Bytes()[:4]
	length := binary.BigEndian.Uint32(lengthBytes)

	// Check for overflow
	if length+4 < length {
		return nil, errors.New("overflow in command packet")
	}

	// Check if we have enough data
	if uint32(buf.Len()) < length+4 {
		return nil, nil // Not enough data yet
	}

	// Consume length
	buf.Next(4)

	// Read packet data
	data := make([]byte, length)
	buf.Read(data)

	return parsePacket(data)
}

func parsePacket(data []byte) (*Packet, error) {
	if len(data) < 4 {
		return nil, errors.New("packet too short")
	}

	buf := bytes.NewReader(data)
	p := &Packet{}

	var packedID uint16
	binary.Read(buf, binary.BigEndian, &packedID)

	p.RequestID = packedID & 0x7FFF
	p.IsRequest = (packedID & 0x8000) == 0

	var cmdID uint16
	binary.Read(buf, binary.BigEndian, &cmdID)
	p.CommandID = PacketType(cmdID)

	switch p.CommandID {
	case CommandPing:
		if p.IsRequest {
			str, _ := readNTString(buf)
			p.PingRequest = &PingRequest{Data: str}
		} else {
			str, _ := readNTString(buf)
			p.PingResponse = &PingResponse{Data: str}
		}

	case CommandShell:
		if p.IsRequest {
			str, _ := readNTString(buf)
			p.ShellRequest = &ShellRequest{Name: str}
		} else {
			var sessionID uint16
			binary.Read(buf, binary.BigEndian, &sessionID)
			p.ShellResponse = &ShellResponse{SessionID: sessionID}
		}

	case CommandExec:
		if p.IsRequest {
			name, _ := readNTString(buf)
			command, _ := readNTString(buf)
			p.ExecRequest = &ExecRequest{Name: name, Command: command}
		} else {
			var sessionID uint16
			binary.Read(buf, binary.BigEndian, &sessionID)
			p.ExecResponse = &ExecResponse{SessionID: sessionID}
		}

	case CommandDownload:
		if p.IsRequest {
			filename, _ := readNTString(buf)
			p.DownloadRequest = &DownloadRequest{Filename: filename}
		} else {
			data := make([]byte, buf.Len())
			buf.Read(data)
			p.DownloadResponse = &DownloadResponse{Data: data}
		}

	case CommandUpload:
		if p.IsRequest {
			filename, _ := readNTString(buf)
			data := make([]byte, buf.Len())
			buf.Read(data)
			p.UploadRequest = &UploadRequest{Filename: filename, Data: data}
		} else {
			p.UploadResponse = &UploadResponse{}
		}

	case CommandShutdown:
		if p.IsRequest {
			p.ShutdownRequest = &ShutdownRequest{}
		} else {
			p.ShutdownResponse = &ShutdownResponse{}
		}

	case CommandDelay:
		if p.IsRequest {
			var delay uint32
			binary.Read(buf, binary.BigEndian, &delay)
			p.DelayRequest = &DelayRequest{Delay: delay}
		} else {
			p.DelayResponse = &DelayResponse{}
		}

	case TunnelConnect:
		if p.IsRequest {
			var options uint32
			binary.Read(buf, binary.BigEndian, &options)
			host, _ := readNTString(buf)
			var port uint16
			binary.Read(buf, binary.BigEndian, &port)
			p.TunnelConnectRequest = &TunnelConnectRequest{
				Options: options,
				Host:    host,
				Port:    port,
			}
		} else {
			var tunnelID uint32
			binary.Read(buf, binary.BigEndian, &tunnelID)
			p.TunnelConnectResponse = &TunnelConnectResponse{TunnelID: tunnelID}
		}

	case TunnelData:
		if p.IsRequest {
			var tunnelID uint32
			binary.Read(buf, binary.BigEndian, &tunnelID)
			data := make([]byte, buf.Len())
			buf.Read(data)
			p.TunnelDataRequest = &TunnelDataRequest{
				TunnelID: tunnelID,
				Data:     data,
			}
		}

	case TunnelClose:
		if p.IsRequest {
			var tunnelID uint32
			binary.Read(buf, binary.BigEndian, &tunnelID)
			reason, _ := readNTString(buf)
			p.TunnelCloseRequest = &TunnelCloseRequest{
				TunnelID: tunnelID,
				Reason:   reason,
			}
		}

	case CommandError:
		var status uint16
		binary.Read(buf, binary.BigEndian, &status)
		reason, _ := readNTString(buf)
		if p.IsRequest {
			p.ErrorRequest = &ErrorRequest{Status: status, Reason: reason}
		} else {
			p.ErrorResponse = &ErrorResponse{Status: status, Reason: reason}
		}

	default:
		return nil, fmt.Errorf("unknown command_id: 0x%04x", p.CommandID)
	}

	return p, nil
}

// ToBytes serializes the packet to bytes
func (p *Packet) ToBytes() []byte {
	buf := new(bytes.Buffer)

	packedID := p.RequestID & 0x7FFF
	if !p.IsRequest {
		packedID |= 0x8000
	}
	binary.Write(buf, binary.BigEndian, packedID)
	binary.Write(buf, binary.BigEndian, uint16(p.CommandID))

	switch p.CommandID {
	case CommandPing:
		if p.IsRequest && p.PingRequest != nil {
			writeNTString(buf, p.PingRequest.Data)
		} else if !p.IsRequest && p.PingResponse != nil {
			writeNTString(buf, p.PingResponse.Data)
		}

	case CommandShell:
		if p.IsRequest && p.ShellRequest != nil {
			writeNTString(buf, p.ShellRequest.Name)
		} else if !p.IsRequest && p.ShellResponse != nil {
			binary.Write(buf, binary.BigEndian, p.ShellResponse.SessionID)
		}

	case CommandExec:
		if p.IsRequest && p.ExecRequest != nil {
			writeNTString(buf, p.ExecRequest.Name)
			writeNTString(buf, p.ExecRequest.Command)
		} else if !p.IsRequest && p.ExecResponse != nil {
			binary.Write(buf, binary.BigEndian, p.ExecResponse.SessionID)
		}

	case CommandDownload:
		if p.IsRequest && p.DownloadRequest != nil {
			writeNTString(buf, p.DownloadRequest.Filename)
		} else if !p.IsRequest && p.DownloadResponse != nil {
			buf.Write(p.DownloadResponse.Data)
		}

	case CommandUpload:
		if p.IsRequest && p.UploadRequest != nil {
			writeNTString(buf, p.UploadRequest.Filename)
			buf.Write(p.UploadRequest.Data)
		}

	case CommandShutdown:
		// No body

	case CommandDelay:
		if p.IsRequest && p.DelayRequest != nil {
			binary.Write(buf, binary.BigEndian, p.DelayRequest.Delay)
		}

	case TunnelConnect:
		if p.IsRequest && p.TunnelConnectRequest != nil {
			binary.Write(buf, binary.BigEndian, p.TunnelConnectRequest.Options)
			writeNTString(buf, p.TunnelConnectRequest.Host)
			binary.Write(buf, binary.BigEndian, p.TunnelConnectRequest.Port)
		} else if !p.IsRequest && p.TunnelConnectResponse != nil {
			binary.Write(buf, binary.BigEndian, p.TunnelConnectResponse.TunnelID)
		}

	case TunnelData:
		if p.IsRequest && p.TunnelDataRequest != nil {
			binary.Write(buf, binary.BigEndian, p.TunnelDataRequest.TunnelID)
			buf.Write(p.TunnelDataRequest.Data)
		}

	case TunnelClose:
		if p.IsRequest && p.TunnelCloseRequest != nil {
			binary.Write(buf, binary.BigEndian, p.TunnelCloseRequest.TunnelID)
			writeNTString(buf, p.TunnelCloseRequest.Reason)
		}

	case CommandError:
		if p.IsRequest && p.ErrorRequest != nil {
			binary.Write(buf, binary.BigEndian, p.ErrorRequest.Status)
			writeNTString(buf, p.ErrorRequest.Reason)
		} else if !p.IsRequest && p.ErrorResponse != nil {
			binary.Write(buf, binary.BigEndian, p.ErrorResponse.Status)
			writeNTString(buf, p.ErrorResponse.Reason)
		}
	}

	// Prepend length
	data := buf.Bytes()
	result := new(bytes.Buffer)
	binary.Write(result, binary.BigEndian, uint32(len(data)))
	result.Write(data)

	return result.Bytes()
}

// Helper functions
func readNTString(r *bytes.Reader) (string, error) {
	var result []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return string(result), err
		}
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return string(result), nil
}

func writeNTString(buf *bytes.Buffer, s string) {
	buf.WriteString(s)
	buf.WriteByte(0)
}

// Factory functions for creating response packets

func CreatePingResponse(requestID uint16, data string) *Packet {
	return &Packet{
		RequestID:    requestID,
		CommandID:    CommandPing,
		IsRequest:    false,
		PingResponse: &PingResponse{Data: data},
	}
}

func CreateShellResponse(requestID uint16, sessionID uint16) *Packet {
	return &Packet{
		RequestID:     requestID,
		CommandID:     CommandShell,
		IsRequest:     false,
		ShellResponse: &ShellResponse{SessionID: sessionID},
	}
}

func CreateExecResponse(requestID uint16, sessionID uint16) *Packet {
	return &Packet{
		RequestID:    requestID,
		CommandID:    CommandExec,
		IsRequest:    false,
		ExecResponse: &ExecResponse{SessionID: sessionID},
	}
}

func CreateDownloadResponse(requestID uint16, data []byte) *Packet {
	return &Packet{
		RequestID:        requestID,
		CommandID:        CommandDownload,
		IsRequest:        false,
		DownloadResponse: &DownloadResponse{Data: data},
	}
}

func CreateUploadResponse(requestID uint16) *Packet {
	return &Packet{
		RequestID:      requestID,
		CommandID:      CommandUpload,
		IsRequest:      false,
		UploadResponse: &UploadResponse{},
	}
}

func CreateShutdownResponse(requestID uint16) *Packet {
	return &Packet{
		RequestID:        requestID,
		CommandID:        CommandShutdown,
		IsRequest:        false,
		ShutdownResponse: &ShutdownResponse{},
	}
}

func CreateDelayResponse(requestID uint16) *Packet {
	return &Packet{
		RequestID:     requestID,
		CommandID:     CommandDelay,
		IsRequest:     false,
		DelayResponse: &DelayResponse{},
	}
}

func CreateTunnelConnectResponse(requestID uint16, tunnelID uint32) *Packet {
	return &Packet{
		RequestID: requestID,
		CommandID: TunnelConnect,
		IsRequest: false,
		TunnelConnectResponse: &TunnelConnectResponse{
			TunnelID: tunnelID,
		},
	}
}

func CreateTunnelDataRequest(requestID uint16, tunnelID uint32, data []byte) *Packet {
	return &Packet{
		RequestID: requestID,
		CommandID: TunnelData,
		IsRequest: true,
		TunnelDataRequest: &TunnelDataRequest{
			TunnelID: tunnelID,
			Data:     data,
		},
	}
}

func CreateTunnelCloseRequest(requestID uint16, tunnelID uint32, reason string) *Packet {
	return &Packet{
		RequestID: requestID,
		CommandID: TunnelClose,
		IsRequest: true,
		TunnelCloseRequest: &TunnelCloseRequest{
			TunnelID: tunnelID,
			Reason:   reason,
		},
	}
}

func CreateErrorResponse(requestID uint16, status uint16, reason string) *Packet {
	return &Packet{
		RequestID:     requestID,
		CommandID:     CommandError,
		IsRequest:     false,
		ErrorResponse: &ErrorResponse{Status: status, Reason: reason},
	}
}

// String returns a string representation
func (p *Packet) String() string {
	reqType := "request"
	if !p.IsRequest {
		reqType = "response"
	}

	switch p.CommandID {
	case CommandPing:
		if p.IsRequest {
			return fmt.Sprintf("COMMAND_PING [%s] :: request_id: 0x%04x :: data: %s",
				reqType, p.RequestID, p.PingRequest.Data)
		}
		return fmt.Sprintf("COMMAND_PING [%s] :: request_id: 0x%04x :: data: %s",
			reqType, p.RequestID, p.PingResponse.Data)

	case CommandShell:
		if p.IsRequest {
			return fmt.Sprintf("COMMAND_SHELL [%s] :: request_id: 0x%04x :: name: %s",
				reqType, p.RequestID, p.ShellRequest.Name)
		}
		return fmt.Sprintf("COMMAND_SHELL [%s] :: request_id: 0x%04x :: session_id: 0x%04x",
			reqType, p.RequestID, p.ShellResponse.SessionID)

	case CommandExec:
		if p.IsRequest {
			return fmt.Sprintf("COMMAND_EXEC [%s] :: request_id: 0x%04x :: name: %s :: command: %s",
				reqType, p.RequestID, p.ExecRequest.Name, p.ExecRequest.Command)
		}
		return fmt.Sprintf("COMMAND_EXEC [%s] :: request_id: 0x%04x :: session_id: 0x%04x",
			reqType, p.RequestID, p.ExecResponse.SessionID)

	case CommandDownload:
		if p.IsRequest {
			return fmt.Sprintf("COMMAND_DOWNLOAD [%s] :: request_id: 0x%04x :: filename: %s",
				reqType, p.RequestID, p.DownloadRequest.Filename)
		}
		return fmt.Sprintf("COMMAND_DOWNLOAD [%s] :: request_id: 0x%04x :: data: 0x%x bytes",
			reqType, p.RequestID, len(p.DownloadResponse.Data))

	case CommandUpload:
		if p.IsRequest {
			return fmt.Sprintf("COMMAND_UPLOAD [%s] :: request_id: 0x%04x :: filename: %s :: data: 0x%x bytes",
				reqType, p.RequestID, p.UploadRequest.Filename, len(p.UploadRequest.Data))
		}
		return fmt.Sprintf("COMMAND_UPLOAD [%s] :: request_id: 0x%04x", reqType, p.RequestID)

	case CommandShutdown:
		return fmt.Sprintf("COMMAND_SHUTDOWN [%s] :: request_id: 0x%04x", reqType, p.RequestID)

	case CommandDelay:
		if p.IsRequest {
			return fmt.Sprintf("COMMAND_DELAY [%s] :: request_id: 0x%04x :: delay: %d",
				reqType, p.RequestID, p.DelayRequest.Delay)
		}
		return fmt.Sprintf("COMMAND_DELAY [%s] :: request_id: 0x%04x", reqType, p.RequestID)

	case TunnelConnect:
		if p.IsRequest {
			return fmt.Sprintf("TUNNEL_CONNECT [%s] :: request_id: 0x%04x :: host: %s :: port: %d",
				reqType, p.RequestID, p.TunnelConnectRequest.Host, p.TunnelConnectRequest.Port)
		}
		return fmt.Sprintf("TUNNEL_CONNECT [%s] :: request_id: 0x%04x :: tunnel_id: %d",
			reqType, p.RequestID, p.TunnelConnectResponse.TunnelID)

	case TunnelData:
		if p.IsRequest {
			return fmt.Sprintf("TUNNEL_DATA [%s] :: request_id: 0x%04x :: tunnel_id: %d :: data: %d bytes",
				reqType, p.RequestID, p.TunnelDataRequest.TunnelID, len(p.TunnelDataRequest.Data))
		}
		return fmt.Sprintf("TUNNEL_DATA [%s] :: request_id: 0x%04x", reqType, p.RequestID)

	case TunnelClose:
		if p.IsRequest {
			return fmt.Sprintf("TUNNEL_CLOSE [%s] :: request_id: 0x%04x :: tunnel_id: %d :: reason: %s",
				reqType, p.RequestID, p.TunnelCloseRequest.TunnelID, p.TunnelCloseRequest.Reason)
		}
		return fmt.Sprintf("TUNNEL_CLOSE [%s] :: request_id: 0x%04x", reqType, p.RequestID)

	case CommandError:
		if p.IsRequest {
			return fmt.Sprintf("COMMAND_ERROR [%s] :: request_id: 0x%04x :: status: 0x%04x :: reason: %s",
				reqType, p.RequestID, p.ErrorRequest.Status, p.ErrorRequest.Reason)
		}
		return fmt.Sprintf("COMMAND_ERROR [%s] :: request_id: 0x%04x :: status: 0x%04x :: reason: %s",
			reqType, p.RequestID, p.ErrorResponse.Status, p.ErrorResponse.Reason)

	default:
		return fmt.Sprintf("Unknown command: 0x%04x", p.CommandID)
	}
}


