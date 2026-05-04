package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"strings"
)

// DNS header flags
const (
	FlagQR     = 0x8000 // Query/Response
	FlagAA     = 0x0400 // Authoritative Answer
	FlagTC     = 0x0200 // Truncation
	FlagRD     = 0x0100 // Recursion Desired
	FlagRA     = 0x0080 // Recursion Available
)

// DNSQuestion represents a DNS question
type DNSQuestion struct {
	Name  string
	Type  DNSType
	Class uint16
}

// DNSAnswer represents a DNS answer
type DNSAnswer struct {
	Name  string
	Type  DNSType
	Class uint16
	TTL   uint32
	Data  []byte
}

// DNSResponse represents a parsed DNS response
type DNSResponse struct {
	ID        uint16
	Flags     uint16
	RCode     uint16
	Questions []DNSQuestion
	Answers   []DNSAnswer
}

// BuildDNSQuery builds a DNS query packet
func BuildDNSQuery(name string, qtype DNSType) []byte {
	buf := new(bytes.Buffer)

	// Transaction ID
	binary.Write(buf, binary.BigEndian, uint16(rand.Intn(0xFFFF)))

	// Flags: standard query with recursion desired
	binary.Write(buf, binary.BigEndian, uint16(FlagRD))

	// Question count
	binary.Write(buf, binary.BigEndian, uint16(1))

	// Answer, Authority, Additional counts
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, uint16(0))

	// Question section
	encodeDNSName(buf, name)
	binary.Write(buf, binary.BigEndian, uint16(qtype))
	binary.Write(buf, binary.BigEndian, uint16(1)) // IN class

	return buf.Bytes()
}

// encodeDNSName encodes a domain name in DNS wire format
func encodeDNSName(buf *bytes.Buffer, name string) {
	parts := strings.Split(name, ".")
	for _, part := range parts {
		if len(part) > 0 {
			buf.WriteByte(byte(len(part)))
			buf.WriteString(part)
		}
	}
	buf.WriteByte(0) // Terminator
}

// ParseDNSResponse parses a DNS response packet
func ParseDNSResponse(data []byte) (*DNSResponse, error) {
	if len(data) < 12 {
		return nil, errors.New("DNS response too short")
	}

	r := &DNSResponse{
		ID:    binary.BigEndian.Uint16(data[0:2]),
		Flags: binary.BigEndian.Uint16(data[2:4]),
		RCode: binary.BigEndian.Uint16(data[2:4]) & 0x000F,
	}

	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])

	offset := 12

	// Parse questions
	for i := uint16(0); i < qdCount; i++ {
		q := DNSQuestion{}
		var err error
		q.Name, offset, err = decodeDNSName(data, offset)
		if err != nil {
			return nil, err
		}

		if offset+4 > len(data) {
			return nil, errors.New("DNS response truncated in question")
		}

		q.Type = DNSType(binary.BigEndian.Uint16(data[offset : offset+2]))
		q.Class = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		r.Questions = append(r.Questions, q)
	}

	// Parse answers
	for i := uint16(0); i < anCount; i++ {
		a := DNSAnswer{}
		var err error
		a.Name, offset, err = decodeDNSName(data, offset)
		if err != nil {
			return nil, err
		}

		if offset+10 > len(data) {
			return nil, errors.New("DNS response truncated in answer header")
		}

		a.Type = DNSType(binary.BigEndian.Uint16(data[offset : offset+2]))
		a.Class = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		a.TTL = binary.BigEndian.Uint32(data[offset+4 : offset+8])
		rdLength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLength) > len(data) {
			return nil, errors.New("DNS response truncated in answer data")
		}

		// Parse answer data based on type
		switch a.Type {
		case TypeA:
			if rdLength >= 4 {
				a.Data = make([]byte, 4)
				copy(a.Data, data[offset:offset+4])
			}

		case TypeAAAA:
			if rdLength >= 16 {
				a.Data = make([]byte, 16)
				copy(a.Data, data[offset:offset+16])
			}

		case TypeCNAME, TypeMX:
			// Decode the name
			var name string
			var err error
			if a.Type == TypeMX {
				// MX has preference first
				if rdLength >= 2 {
					name, _, err = decodeDNSName(data, offset+2)
				}
			} else {
				name, _, err = decodeDNSName(data, offset)
			}
			if err == nil {
				a.Data = []byte(name)
			}

		case TypeTXT:
			// TXT records have length prefix
			if rdLength >= 1 {
				txtLen := int(data[offset])
				if offset+1+txtLen <= len(data) {
					a.Data = make([]byte, txtLen)
					copy(a.Data, data[offset+1:offset+1+txtLen])
				}
			}

		default:
			a.Data = make([]byte, rdLength)
			copy(a.Data, data[offset:offset+int(rdLength)])
		}

		offset += int(rdLength)
		r.Answers = append(r.Answers, a)
	}

	return r, nil
}

// decodeDNSName decodes a DNS name from wire format
func decodeDNSName(data []byte, offset int) (string, int, error) {
	var parts []string
	jumped := false
	jumpOffset := 0

	for {
		if offset >= len(data) {
			return "", 0, errors.New("DNS name extends beyond packet")
		}

		length := int(data[offset])

		if length == 0 {
			if !jumped {
				offset++
			}
			break
		}

		// Check for compression pointer
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, errors.New("DNS compression pointer truncated")
			}
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if !jumped {
				jumpOffset = offset + 2
				jumped = true
			}
			offset = pointer
			continue
		}

		offset++
		if offset+length > len(data) {
			return "", 0, errors.New("DNS name label extends beyond packet")
		}

		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}

	finalOffset := offset
	if jumped {
		finalOffset = jumpOffset
	}

	return strings.Join(parts, "."), finalOffset, nil
}


