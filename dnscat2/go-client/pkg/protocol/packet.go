// Package protocol implements the dnscat2 protocol packet handling.
package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
)

const (
	MaxPacketSize = 1024
)

// PacketType represents the type of dnscat packet
type PacketType uint8

const (
	PacketTypeSYN  PacketType = 0x00
	PacketTypeMSG  PacketType = 0x01
	PacketTypeFIN  PacketType = 0x02
	PacketTypeENC  PacketType = 0x03
	PacketTypePING PacketType = 0xFF
)

// String returns the string representation of packet type
func (t PacketType) String() string {
	switch t {
	case PacketTypeSYN:
		return "SYN"
	case PacketTypeMSG:
		return "MSG"
	case PacketTypeFIN:
		return "FIN"
	case PacketTypeENC:
		return "ENC"
	case PacketTypePING:
		return "PING"
	default:
		return "Unknown"
	}
}

// EncSubtype represents encryption packet subtype
type EncSubtype uint16

const (
	EncSubtypeInit EncSubtype = 0x00
	EncSubtypeAuth EncSubtype = 0x01
)

// Options for SYN packets
type Options uint16

const (
	OptName    Options = 0x0001
	OptCommand Options = 0x0020
)

// SYNPacket represents a SYN packet body
type SYNPacket struct {
	Seq     uint16
	Options Options
	Name    string
}

// MSGPacket represents a MSG packet body
type MSGPacket struct {
	Seq  uint16
	Ack  uint16
	Data []byte
}

// FINPacket represents a FIN packet body
type FINPacket struct {
	Reason string
}

// PINGPacket represents a PING packet body
type PINGPacket struct {
	Data string
}

// ENCPacket represents an encryption packet body
type ENCPacket struct {
	Subtype       EncSubtype
	Flags         uint16
	PublicKey     [64]byte
	Authenticator [32]byte
}

// Packet represents a dnscat2 protocol packet
type Packet struct {
	PacketID   uint16
	PacketType PacketType
	SessionID  uint16

	// Body - only one will be set based on PacketType
	SYN  *SYNPacket
	MSG  *MSGPacket
	FIN  *FINPacket
	PING *PINGPacket
	ENC  *ENCPacket
}

// Parse parses a packet from raw bytes
func Parse(data []byte, options Options) (*Packet, error) {
	if len(data) < 5 {
		return nil, errors.New("packet too short")
	}

	if len(data) > MaxPacketSize {
		return nil, fmt.Errorf("packet too long: %d bytes", len(data))
	}

	buf := bytes.NewReader(data)
	p := &Packet{}

	if err := binary.Read(buf, binary.BigEndian, &p.PacketID); err != nil {
		return nil, err
	}

	var pType uint8
	if err := binary.Read(buf, binary.BigEndian, &pType); err != nil {
		return nil, err
	}
	p.PacketType = PacketType(pType)

	if err := binary.Read(buf, binary.BigEndian, &p.SessionID); err != nil {
		return nil, err
	}

	switch p.PacketType {
	case PacketTypeSYN:
		syn := &SYNPacket{}
		if err := binary.Read(buf, binary.BigEndian, &syn.Seq); err != nil {
			return nil, err
		}
		var opts uint16
		if err := binary.Read(buf, binary.BigEndian, &opts); err != nil {
			return nil, err
		}
		syn.Options = Options(opts)

		if syn.Options&OptName != 0 {
			name, err := readNTString(buf)
			if err != nil {
				return nil, err
			}
			syn.Name = name
		}
		p.SYN = syn

	case PacketTypeMSG:
		msg := &MSGPacket{}
		if err := binary.Read(buf, binary.BigEndian, &msg.Seq); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.BigEndian, &msg.Ack); err != nil {
			return nil, err
		}
		// Read remaining data (if any) - avoid calling Read on exhausted reader with empty slice
		remaining := buf.Len()
		if remaining > 0 {
			msg.Data = make([]byte, remaining)
			if _, err := buf.Read(msg.Data); err != nil {
				return nil, err
			}
		} else {
			msg.Data = []byte{}
		}
		p.MSG = msg

	case PacketTypeFIN:
		reason, err := readNTString(buf)
		if err != nil {
			return nil, err
		}
		p.FIN = &FINPacket{Reason: reason}

	case PacketTypePING:
		data, err := readNTString(buf)
		if err != nil {
			return nil, err
		}
		p.PING = &PINGPacket{Data: data}

	case PacketTypeENC:
		enc := &ENCPacket{}
		if err := binary.Read(buf, binary.BigEndian, &enc.Subtype); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.BigEndian, &enc.Flags); err != nil {
			return nil, err
		}

		switch enc.Subtype {
		case EncSubtypeInit:
			if _, err := buf.Read(enc.PublicKey[:]); err != nil {
				return nil, err
			}
		case EncSubtypeAuth:
			if _, err := buf.Read(enc.Authenticator[:]); err != nil {
				return nil, err
			}
		}
		p.ENC = enc

	default:
		return nil, fmt.Errorf("unknown message type: 0x%02x", p.PacketType)
	}

	return p, nil
}

// PeekSessionID extracts session ID from raw packet data without full parsing
func PeekSessionID(data []byte) (uint16, error) {
	if len(data) < 5 {
		return 0, errors.New("packet too short")
	}
	return binary.BigEndian.Uint16(data[3:5]), nil
}

// ToBytes serializes the packet to bytes
func (p *Packet) ToBytes(options Options) ([]byte, error) {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, p.PacketID)
	binary.Write(buf, binary.BigEndian, uint8(p.PacketType))
	binary.Write(buf, binary.BigEndian, p.SessionID)

	switch p.PacketType {
	case PacketTypeSYN:
		if p.SYN == nil {
			return nil, errors.New("SYN packet body is nil")
		}
		binary.Write(buf, binary.BigEndian, p.SYN.Seq)
		binary.Write(buf, binary.BigEndian, uint16(p.SYN.Options))
		if p.SYN.Options&OptName != 0 {
			writeNTString(buf, p.SYN.Name)
		}

	case PacketTypeMSG:
		if p.MSG == nil {
			return nil, errors.New("MSG packet body is nil")
		}
		binary.Write(buf, binary.BigEndian, p.MSG.Seq)
		binary.Write(buf, binary.BigEndian, p.MSG.Ack)
		buf.Write(p.MSG.Data)

	case PacketTypeFIN:
		if p.FIN == nil {
			return nil, errors.New("FIN packet body is nil")
		}
		writeNTString(buf, p.FIN.Reason)

	case PacketTypePING:
		if p.PING == nil {
			return nil, errors.New("PING packet body is nil")
		}
		writeNTString(buf, p.PING.Data)

	case PacketTypeENC:
		if p.ENC == nil {
			return nil, errors.New("ENC packet body is nil")
		}
		binary.Write(buf, binary.BigEndian, p.ENC.Subtype)
		binary.Write(buf, binary.BigEndian, p.ENC.Flags)

		switch p.ENC.Subtype {
		case EncSubtypeInit:
			buf.Write(p.ENC.PublicKey[:])
		case EncSubtypeAuth:
			buf.Write(p.ENC.Authenticator[:])
		}

	default:
		return nil, fmt.Errorf("unknown message type: %d", p.PacketType)
	}

	return buf.Bytes(), nil
}

// CreateSYN creates a new SYN packet
func CreateSYN(sessionID, seq uint16, options Options) *Packet {
	return &Packet{
		PacketID:   uint16(rand.Intn(0xFFFF)),
		PacketType: PacketTypeSYN,
		SessionID:  sessionID,
		SYN: &SYNPacket{
			Seq:     seq,
			Options: options,
		},
	}
}

// CreateMSG creates a new MSG packet
func CreateMSG(sessionID, seq, ack uint16, data []byte) *Packet {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	return &Packet{
		PacketID:   uint16(rand.Intn(0xFFFF)),
		PacketType: PacketTypeMSG,
		SessionID:  sessionID,
		MSG: &MSGPacket{
			Seq:  seq,
			Ack:  ack,
			Data: dataCopy,
		},
	}
}

// CreateFIN creates a new FIN packet
func CreateFIN(sessionID uint16, reason string) *Packet {
	return &Packet{
		PacketID:   uint16(rand.Intn(0xFFFF)),
		PacketType: PacketTypeFIN,
		SessionID:  sessionID,
		FIN: &FINPacket{
			Reason: reason,
		},
	}
}

// CreatePING creates a new PING packet
func CreatePING(sessionID uint16, data string) *Packet {
	return &Packet{
		PacketID:   uint16(rand.Intn(0xFFFF)),
		PacketType: PacketTypePING,
		SessionID:  sessionID,
		PING: &PINGPacket{
			Data: data,
		},
	}
}

// CreateENC creates a new encryption packet
func CreateENC(sessionID uint16, flags uint16) *Packet {
	return &Packet{
		PacketID:   uint16(rand.Intn(0xFFFF)),
		PacketType: PacketTypeENC,
		SessionID:  sessionID,
		ENC: &ENCPacket{
			Flags: flags,
		},
	}
}

// SetName sets the name option on a SYN packet
func (p *Packet) SetName(name string) {
	if p.SYN != nil {
		p.SYN.Options |= OptName
		p.SYN.Name = name
	}
}

// SetIsCommand sets the command option on a SYN packet
func (p *Packet) SetIsCommand() {
	if p.SYN != nil {
		p.SYN.Options |= OptCommand
	}
}

// SetEncInit sets up the ENC packet for key init
func (p *Packet) SetEncInit(publicKey []byte) {
	if p.ENC != nil {
		p.ENC.Subtype = EncSubtypeInit
		copy(p.ENC.PublicKey[:], publicKey)
	}
}

// SetEncAuth sets up the ENC packet for authentication
func (p *Packet) SetEncAuth(authenticator []byte) {
	if p.ENC != nil {
		p.ENC.Subtype = EncSubtypeAuth
		copy(p.ENC.Authenticator[:], authenticator)
	}
}

// GetMSGSize returns the size of an empty MSG packet
func GetMSGSize(options Options) int {
	p := CreateMSG(0, 0, 0, nil)
	data, _ := p.ToBytes(options)
	return len(data)
}

// GetPINGSize returns the size of an empty PING packet
func GetPINGSize() int {
	p := CreatePING(0, "")
	data, _ := p.ToBytes(0)
	return len(data)
}

// String returns a string representation of the packet
func (p *Packet) String() string {
	switch p.PacketType {
	case PacketTypeSYN:
		return fmt.Sprintf("Type = SYN :: [0x%04x] session = 0x%04x, seq = 0x%04x, options = 0x%04x",
			p.PacketID, p.SessionID, p.SYN.Seq, p.SYN.Options)
	case PacketTypeMSG:
		return fmt.Sprintf("Type = MSG :: [0x%04x] session = 0x%04x, seq = 0x%04x, ack = 0x%04x, data = 0x%x bytes",
			p.PacketID, p.SessionID, p.MSG.Seq, p.MSG.Ack, len(p.MSG.Data))
	case PacketTypeFIN:
		return fmt.Sprintf("Type = FIN :: [0x%04x] session = 0x%04x :: %s",
			p.PacketID, p.SessionID, p.FIN.Reason)
	case PacketTypePING:
		return fmt.Sprintf("Type = PING :: [0x%04x] data = %s",
			p.PacketID, p.PING.Data)
	case PacketTypeENC:
		return fmt.Sprintf("Type = ENC :: [0x%04x] session = 0x%04x",
			p.PacketID, p.SessionID)
	default:
		return "Unknown packet type"
	}
}

// Helper functions for null-terminated strings
func readNTString(r *bytes.Reader) (string, error) {
	var result []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
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


