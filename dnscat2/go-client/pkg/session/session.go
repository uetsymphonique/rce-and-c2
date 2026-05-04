// Package session implements dnscat2 session management.
package session

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	"dnscat2/pkg/crypto"
	"dnscat2/pkg/driver"
	"dnscat2/pkg/protocol"
)

// State represents session state
type State int

const (
	StateBeforeInit State = iota
	StateBeforeAuth
	StateNew
	StateEstablished
)

// String returns the string representation of session state
func (s State) String() string {
	switch s {
	case StateBeforeInit:
		return "BEFORE_INIT"
	case StateBeforeAuth:
		return "BEFORE_AUTH"
	case StateNew:
		return "NEW"
	case StateEstablished:
		return "ESTABLISHED"
	default:
		return "Unknown"
	}
}

// Global settings
var (
	PacketTrace            = false
	PacketDelay            = 1000 * time.Millisecond
	TransmitInstantOnData  = true
	DoEncryption           = true
	PresharedSecret        = ""
)

// Session represents a dnscat2 session
type Session struct {
	ID       uint16
	State    State
	TheirSeq uint16
	MySeq    uint16
	Name     string
	Options  protocol.Options

	IsCommand bool
	IsPing    bool

	Driver         driver.Driver
	OutgoingBuffer []byte // Sliding window buffer - data stays until ACKed

	Encryptor    *crypto.Encryptor
	NewEncryptor *crypto.Encryptor

	LastTransmit         time.Time
	MissedTransmissions  int
	isShutdown           bool

	mu sync.Mutex
}

// New creates a new session
func New(name string) (*Session, error) {
	s := &Session{
		ID:             uint16(rand.Intn(0xFFFF)),
		MySeq:          uint16(rand.Intn(0xFFFF)),
		OutgoingBuffer: make([]byte, 0),
	}

	if DoEncryption {
		s.State = StateBeforeInit
		enc, err := crypto.NewEncryptor(PresharedSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}
		s.Encryptor = enc
	} else {
		s.State = StateNew
	}

	if name != "" {
		hostname, _ := os.Hostname()
		s.Name = fmt.Sprintf("%s (%s)", name, hostname)
	}

	return s, nil
}

// NewConsoleSession creates a session with console driver
func NewConsoleSession(name string) (*Session, error) {
	s, err := New(name)
	if err != nil {
		return nil, err
	}
	s.Driver = driver.NewConsoleDriver()
	return s, nil
}

// NewExecSession creates a session with exec driver
func NewExecSession(name, process string) (*Session, error) {
	s, err := New(name)
	if err != nil {
		return nil, err
	}
	d, err := driver.NewExecDriver(process)
	if err != nil {
		return nil, err
	}
	s.Driver = d
	return s, nil
}

// NewPingSession creates a session with ping driver
func NewPingSession(name string) (*Session, error) {
	s, err := New(name)
	if err != nil {
		return nil, err
	}
	s.Driver = driver.NewPingDriver()
	s.IsPing = true
	return s, nil
}

// shouldEncrypt returns true if we should encrypt
func (s *Session) shouldEncrypt() bool {
	return DoEncryption && s.State != StateBeforeInit
}

// canTransmitYet returns true if enough time has passed since last transmit
func (s *Session) canTransmitYet() bool {
	return time.Since(s.LastTransmit) > PacketDelay
}

// pollDriverForData reads data from driver into outgoing buffer
func (s *Session) pollDriverForData() {
	data := s.Driver.GetOutgoing(-1)

	if data == nil {
		// Driver is done
		if len(s.OutgoingBuffer) == 0 {
			s.Kill()
		}
	} else if len(data) > 0 {
		s.OutgoingBuffer = append(s.OutgoingBuffer, data...)
	}
}

// GetOutgoing returns the next packet to send
func (s *Session) GetOutgoing(maxLength int) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pollDriverForData()

	if !s.canTransmitYet() {
		return nil
	}

	// Reserve space for encryption header if needed
	if s.shouldEncrypt() {
		maxLength -= 8
		if maxLength <= 0 {
			fmt.Println("There isn't enough room in this protocol to encrypt packets!")
			os.Exit(1)
		}
	}

	var pkt *protocol.Packet

	if s.IsPing {
		// Handle ping specially - read WITHOUT consuming (data stays until ACKed)
		dataLen := min(len(s.OutgoingBuffer), maxLength-protocol.GetPINGSize())
		data := make([]byte, dataLen)
		copy(data, s.OutgoingBuffer[:dataLen])
		pkt = protocol.CreatePING(s.ID, string(data))
	} else {
		switch s.State {
		case StateBeforeInit:
			pkt = protocol.CreateENC(s.ID, 0)
			pkt.SetEncInit(s.Encryptor.GetMyPublicKey())

		case StateBeforeAuth:
			pkt = protocol.CreateENC(s.ID, 0)
			pkt.SetEncAuth(s.Encryptor.GetMyAuthenticator())

		case StateNew:
			pkt = protocol.CreateSYN(s.ID, s.MySeq, 0)
			if s.IsCommand {
				pkt.SetIsCommand()
			}
			if s.Name != "" {
				pkt.SetName(s.Name)
			}

		case StateEstablished:
			// Check if we need to renegotiate
			if s.shouldEncrypt() && s.Encryptor.ShouldRenegotiate() {
				if s.NewEncryptor != nil {
					fmt.Println("The server didn't respond to our re-negotiation request! Waiting...")
					return nil
				}
				fmt.Println("Wow, this session is old! Time to re-negotiate encryption keys!")
				enc, err := crypto.NewEncryptor(PresharedSecret)
				if err != nil {
					fmt.Printf("Failed to create new encryptor: %v\n", err)
					return nil
				}
				s.NewEncryptor = enc
				pkt = protocol.CreateENC(s.ID, 0)
				pkt.SetEncInit(s.NewEncryptor.GetMyPublicKey())
			} else {
				// Normal MSG packet - read WITHOUT consuming (data stays until ACKed)
				dataLen := min(len(s.OutgoingBuffer), maxLength-protocol.GetMSGSize(s.Options))
				data := make([]byte, dataLen)
				copy(data, s.OutgoingBuffer[:dataLen])

				if len(data) == 0 && s.isShutdown {
					pkt = protocol.CreateFIN(s.ID, "Stream closed")
				} else {
					pkt = protocol.CreateMSG(s.ID, s.MySeq, s.TheirSeq, data)
				}
			}
		}
	}

	if pkt == nil {
		return nil
	}

	if PacketTrace {
		fmt.Printf("OUTGOING: %s\n", pkt.String())
	}

	packetBytes, err := pkt.ToBytes(s.Options)
	if err != nil {
		fmt.Printf("Error serializing packet: %v\n", err)
		return nil
	}

	// Encrypt if needed
	if s.shouldEncrypt() {
		packetBytes = s.Encryptor.Encrypt(packetBytes)
		packetBytes = s.Encryptor.Sign(packetBytes)
	}

	s.LastTransmit = time.Now()
	s.MissedTransmissions++

	return packetBytes
}

// DataIncoming processes incoming packet data
func (s *Session) DataIncoming(data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pollDriverForData()

	packetData := make([]byte, len(data))
	copy(packetData, data)

	if PacketTrace {
		fmt.Printf("RECV RAW (%d bytes): %x\n", len(packetData), packetData)
	}

	// Decrypt if needed
	if s.shouldEncrypt() {
		var ok bool
		packetData, ok = s.Encryptor.CheckSignature(packetData)
		if !ok {
			if PacketTrace {
				fmt.Printf("Signature check failed for %d bytes\n", len(data))
			}
			return false
		}

		var err error
		packetData, _, err = s.Encryptor.Decrypt(packetData)
		if err != nil {
			if PacketTrace {
				fmt.Printf("Decryption error: %v\n", err)
			}
			return false
		}

		if PacketTrace {
			fmt.Printf("DECRYPTED (%d bytes): %x\n", len(packetData), packetData)
		}
	}

	pkt, err := protocol.Parse(packetData, s.Options)
	if err != nil {
		if PacketTrace {
			fmt.Printf("Parse error: %v (data len=%d, data=%x)\n", err, len(packetData), packetData)
		}
		return false
	}

	if PacketTrace {
		fmt.Printf("INCOMING: %s\n", pkt.String())
	}

	if s.IsPing && pkt.PacketType == protocol.PacketTypePING {
		s.Driver.DataReceived([]byte(pkt.PING.Data))
		return true
	}

	sendRightAway := false

	switch pkt.PacketType {
	case protocol.PacketTypeSYN:
		sendRightAway = s.handleSYN(pkt)
	case protocol.PacketTypeMSG:
		sendRightAway = s.handleMSG(pkt)
	case protocol.PacketTypeFIN:
		sendRightAway = s.handleFIN(pkt)
	case protocol.PacketTypeENC:
		sendRightAway = s.handleENC(pkt)
	default:
		fmt.Printf("Received illegal packet type: %s\n", pkt.PacketType)
	}

	return sendRightAway
}

func (s *Session) handleSYN(pkt *protocol.Packet) bool {
	switch s.State {
	case StateNew:
		s.TheirSeq = pkt.SYN.Seq
		s.Options = pkt.SYN.Options
		s.MissedTransmissions = 0
		s.State = StateEstablished
		fmt.Println("Session established!")
		return true
	default:
		fmt.Printf("Received SYN in state %s; ignoring!\n", s.State)
		return false
	}
}

func (s *Session) handleMSG(pkt *protocol.Packet) bool {
	if s.State != StateEstablished {
		fmt.Printf("Received MSG in state %s; ignoring!\n", s.State)
		return false
	}

	sendRightAway := false

	if pkt.MSG.Seq == s.TheirSeq {
		// Calculate bytes acknowledged (with wraparound handling)
		bytesAcked := (pkt.MSG.Ack - s.MySeq) & 0xFFFF

		if int(bytesAcked) <= len(s.OutgoingBuffer) {
			s.MissedTransmissions = 0

			if bytesAcked > 0 && TransmitInstantOnData {
				s.LastTransmit = time.Time{}
				sendRightAway = true
			}

			// Update their sequence number
			s.TheirSeq = (s.TheirSeq + uint16(len(pkt.MSG.Data))) & 0xFFFF

			// CONSUME acknowledged data from the buffer (key fix!)
			if bytesAcked > 0 {
				s.OutgoingBuffer = s.OutgoingBuffer[bytesAcked:]
				s.MySeq = (s.MySeq + bytesAcked) & 0xFFFF
			}

			// Pass data to driver
			if len(pkt.MSG.Data) > 0 {
				s.Driver.DataReceived(pkt.MSG.Data)
				s.LastTransmit = time.Time{} // Allow immediate response
			}
		} else {
			fmt.Printf("Bad ACK received (%d bytes acked; %d bytes in buffer)\n",
				bytesAcked, len(s.OutgoingBuffer))
		}
	} else {
		fmt.Printf("Bad SEQ received (Expected %d, received %d)\n",
			s.TheirSeq, pkt.MSG.Seq)
	}

	return sendRightAway
}

func (s *Session) handleFIN(pkt *protocol.Packet) bool {
	fmt.Printf("Received FIN: (reason: '%s') - closing session\n", pkt.FIN.Reason)
	s.LastTransmit = time.Time{}
	s.MissedTransmissions = 0
	s.Kill()
	return true
}

func (s *Session) handleENC(pkt *protocol.Packet) bool {
	switch s.State {
	case StateBeforeInit:
		if pkt.ENC.Subtype != protocol.EncSubtypeInit {
			fmt.Printf("Received unexpected encryption packet subtype: 0x%04x\n", pkt.ENC.Subtype)
			os.Exit(1)
		}

		if err := s.Encryptor.SetTheirPublicKey(pkt.ENC.PublicKey[:]); err != nil {
			fmt.Printf("Failed to calculate shared secret: %v\n", err)
			os.Exit(1)
		}

		s.Encryptor.Print()

		if PresharedSecret != "" {
			s.State = StateBeforeAuth
		} else {
			s.State = StateNew
			fmt.Println()
			fmt.Println("Encrypted session established! For added security, please verify the server also displays this string:")
			fmt.Println()
			fmt.Println(s.Encryptor.PrintSAS())
			fmt.Println()
		}
		return true

	case StateBeforeAuth:
		if pkt.ENC.Subtype != protocol.EncSubtypeAuth {
			fmt.Printf("Received unexpected encryption packet subtype: 0x%04x\n", pkt.ENC.Subtype)
			os.Exit(1)
		}

		if !bytes.Equal(pkt.ENC.Authenticator[:], s.Encryptor.GetTheirAuthenticator()) {
			fmt.Println("Their authenticator was wrong! That likely means something weird is happening on the network...")
			os.Exit(1)
		}

		fmt.Println()
		fmt.Println("** Peer verified with pre-shared secret!")
		fmt.Println()

		s.State = StateNew
		return true

	case StateEstablished:
		// Re-negotiation
		if s.NewEncryptor == nil {
			fmt.Println("Received unexpected renegotiation from the server!")
			os.Exit(1)
		}

		if err := s.NewEncryptor.SetTheirPublicKey(pkt.ENC.PublicKey[:]); err != nil {
			fmt.Printf("Failed to calculate shared secret for renegotiation: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Server responded to re-negotiation request! Switching to new keys!")
		s.Encryptor = s.NewEncryptor
		s.NewEncryptor = nil
		s.Encryptor.Print()
		return true

	default:
		fmt.Printf("Received ENC packet in state %s; error!\n", s.State)
		os.Exit(1)
		return false
	}
}

// Kill marks the session for shutdown
func (s *Session) Kill() {
	if s.isShutdown {
		fmt.Printf("Tried to kill a session that's already dead: %d\n", s.ID)
		return
	}
	s.isShutdown = true
	s.Driver.Close()
}

// IsShutdown returns true if session is shut down
func (s *Session) IsShutdown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isShutdown
}

// Destroy cleans up the session
func (s *Session) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isShutdown {
		s.isShutdown = true
		s.Driver.Close()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

