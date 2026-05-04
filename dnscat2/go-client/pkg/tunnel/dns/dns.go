// Package dns implements the DNS tunnel driver.
package dns

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"dnscat2/pkg/controller"
)

const (
	MaxFieldLength = 62
	MaxDNSLength   = 255
	WildcardPrefix = "dnscat"
)

// DNSType represents DNS record types
type DNSType uint16

const (
	TypeA     DNSType = 1
	TypeCNAME DNSType = 5
	TypeMX    DNSType = 15
	TypeTXT   DNSType = 16
	TypeAAAA  DNSType = 28
)

// Driver implements the DNS tunnel driver
type Driver struct {
	Domain    string
	DNSServer string
	DNSPort   uint16
	Types     []DNSType
	conn      *net.UDPConn
}

// NewDriver creates a new DNS tunnel driver
func NewDriver(domain, host string, port uint16, types string, server string) (*Driver, error) {
	d := &Driver{
		Domain:    domain,
		DNSServer: server,
		DNSPort:   port,
	}

	// Parse DNS types
	if types == "ANY" {
		types = "TXT,CNAME,MX"
	}

	for _, t := range strings.Split(types, ",") {
		t = strings.TrimSpace(strings.ToUpper(t))
		switch t {
		case "TXT", "TEXT":
			d.Types = append(d.Types, TypeTXT)
		case "MX":
			d.Types = append(d.Types, TypeMX)
		case "CNAME":
			d.Types = append(d.Types, TypeCNAME)
		case "A":
			d.Types = append(d.Types, TypeA)
		case "AAAA":
			d.Types = append(d.Types, TypeAAAA)
		}
	}

	if len(d.Types) == 0 {
		return nil, fmt.Errorf("no valid DNS types specified")
	}

	// Create UDP socket
	laddr, err := net.ResolveUDPAddr("udp", host+":0")
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	d.conn = conn

	return d, nil
}

// MaxDNSCatLength returns the maximum payload length for DNS queries
func (d *Driver) MaxDNSCatLength() int {
	domainLen := len(d.Domain)
	if d.Domain == "" {
		domainLen = len(WildcardPrefix)
	}
	return (MaxDNSLength / 2) - domainLen - 1 - ((MaxDNSLength / MaxFieldLength) + 1)
}

// getType returns a random DNS type to use
func (d *Driver) getType() DNSType {
	return d.Types[rand.Intn(len(d.Types))]
}

// encodeDNSName encodes data as DNS name with hex encoding
func (d *Driver) encodeDNSName(data []byte) string {
	var result strings.Builder

	// Add wildcard prefix if no domain
	if d.Domain == "" {
		result.WriteString(WildcardPrefix)
		result.WriteByte('.')
	}

	encoded := hex.EncodeToString(data)
	sectionLen := 0

	for i := 0; i < len(encoded); i++ {
		result.WriteByte(encoded[i])
		sectionLen++

		// Add period if needed
		if i+1 != len(encoded) && sectionLen+1 >= MaxFieldLength {
			result.WriteByte('.')
			sectionLen = 0
		}
	}

	// Add domain suffix if set
	if d.Domain != "" {
		result.WriteByte('.')
		result.WriteString(d.Domain)
	}

	return result.String()
}

// decodeDNSResponse decodes DNS response data
func (d *Driver) decodeDNSResponse(response *DNSResponse) ([]byte, error) {
	if len(response.Answers) == 0 {
		return nil, fmt.Errorf("no answers in response")
	}

	answer := response.Answers[0]

	switch answer.Type {
	case TypeTXT:
		// TXT record - hex decode the text
		return d.decodeHex(answer.Data)

	case TypeCNAME, TypeMX:
		// CNAME/MX - remove domain and hex decode
		name := string(answer.Data)
		name = d.removeDomain(name)
		if name == "" {
			return nil, fmt.Errorf("empty response after removing domain")
		}
		return d.decodeHex([]byte(name))

	case TypeA:
		// A records - sort by first byte, extract payload
		sort.Slice(response.Answers, func(i, j int) bool {
			return response.Answers[i].Data[0] < response.Answers[j].Data[0]
		})

		var buf []byte
		for _, a := range response.Answers {
			if len(a.Data) >= 4 {
				buf = append(buf, a.Data[1:4]...)
			}
		}

		if len(buf) < 1 {
			return nil, fmt.Errorf("A record response too short")
		}

		length := int(buf[0])
		if length > len(buf)-1 {
			return nil, fmt.Errorf("A record length mismatch")
		}

		return buf[1 : length+1], nil

	case TypeAAAA:
		// AAAA records - similar to A but 15 bytes per record
		sort.Slice(response.Answers, func(i, j int) bool {
			return response.Answers[i].Data[0] < response.Answers[j].Data[0]
		})

		var buf []byte
		for _, a := range response.Answers {
			if len(a.Data) >= 16 {
				buf = append(buf, a.Data[1:16]...)
			}
		}

		if len(buf) < 1 {
			return nil, fmt.Errorf("AAAA record response too short")
		}

		length := int(buf[0])
		if length > len(buf)-1 {
			return nil, fmt.Errorf("AAAA record length mismatch")
		}

		return buf[1 : length+1], nil

	default:
		return nil, fmt.Errorf("unknown DNS type: %d", answer.Type)
	}
}

// removeDomain removes the domain suffix from a name
func (d *Driver) removeDomain(name string) string {
	if d.Domain != "" {
		if !strings.HasSuffix(name, d.Domain) {
			return ""
		}
		if name == d.Domain {
			return ""
		}
		return strings.TrimSuffix(name, "."+d.Domain)
	} else {
		if !strings.HasPrefix(name, WildcardPrefix) {
			return ""
		}
		return strings.TrimPrefix(name, WildcardPrefix+".")
	}
}

// decodeHex decodes hex string, ignoring periods
func (d *Driver) decodeHex(data []byte) ([]byte, error) {
	// Remove periods
	clean := strings.ReplaceAll(string(data), ".", "")
	return hex.DecodeString(clean)
}

// doSend sends outgoing data
func (d *Driver) doSend() {
	data, hasActiveSessions := controller.GetOutgoing(d.MaxDNSCatLength())
	if !hasActiveSessions {
		fmt.Println("There are no active sessions left! Goodbye!")
		os.Exit(0)
	}

	if data == nil || len(data) == 0 {
		return
	}

	name := d.encodeDNSName(data)
	dnsType := d.getType()

	query := BuildDNSQuery(name, dnsType)

	addr := fmt.Sprintf("%s:%d", d.DNSServer, d.DNSPort)
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Printf("DNS: failed to resolve %s: %v\n", addr, err)
		return
	}

	_, err = d.conn.WriteToUDP(query, raddr)
	if err != nil {
		fmt.Printf("DNS: send error: %v\n", err)
	}
}

// Run starts the DNS driver main loop
func (d *Driver) Run() {
	// Initial send
	d.doSend()

	// Set up receive buffer
	buf := make([]byte, 4096)

	for {
		// Set timeout for receiving
		d.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

		n, _, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout - send next packet and continue
				controller.Heartbeat()
				d.doSend()
				continue
			}
			fmt.Printf("DNS: receive error: %v\n", err)
			continue
		}

		// Parse DNS response
		response, err := ParseDNSResponse(buf[:n])
		if err != nil {
			fmt.Printf("DNS: parse error: %v\n", err)
			continue
		}

		// Check for errors
		if response.RCode != 0 {
			switch response.RCode {
			case 1:
				fmt.Println("DNS: RCODE_FORMAT_ERROR")
			case 2:
				fmt.Println("DNS: RCODE_SERVER_FAILURE")
			case 3:
				fmt.Println("DNS: RCODE_NAME_ERROR")
			case 4:
				fmt.Println("DNS: RCODE_NOT_IMPLEMENTED")
			case 5:
				fmt.Println("DNS: RCODE_REFUSED")
			default:
				fmt.Printf("DNS: Unknown error code (0x%04x)\n", response.RCode)
			}
			continue
		}

		if len(response.Answers) == 0 {
			fmt.Println("DNS didn't return an answer")
			continue
		}

		// Decode response
		data, err := d.decodeDNSResponse(response)
		if err != nil {
			// Only log if debug is enabled
			continue
		}

		if len(data) > 0 {
			if controller.DataIncoming(data) {
				d.doSend()
			}
		} else {
			// Empty response from server (just ACK, no data) - still call doSend for retransmit
			d.doSend()
		}
	}
}

// Close closes the driver
func (d *Driver) Close() {
	if d.conn != nil {
		d.conn.Close()
	}
}

