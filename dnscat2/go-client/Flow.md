# dnscat2 Go Client — Flow

**Entry:** `cmd/dnsapi-service/main.go` (service path) · `cmd/dnscat-dnsapi/main.go` (standalone; skips #2–4)  ·  **Artifact summary:** DNS C2 implant tunneling Salsa20-encrypted sessions via DnsQuery_W through Dnscache; service variant reads config from registry and runs as a managed Windows service

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1 | implant decodes "dnscat" prefix string via XOR at package init | — [no-artifact] → #8 | — | `pkg/tunnel/dnsapi init()`; literal absent from .rdata; XOR-encoded byte array |
| 2 | implant queries SCM to detect service execution context `(svc)` | — [no-artifact] → #3 | — | `svc.IsWindowsService()`; branches: service path (registry config) vs interactive (CLI flags) |
| 3 | implant reads C2 config from service registry key `(svc)` | config values [registry] → #5,#7,#8 | — | `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\`; Domain, DnsTypes, Secret, ExecCommand |
| 4 | implant registers service control handler and signals Running to SCM `(svc)` | — [no-artifact] → #5 | — | `svc.Run()`; Stop/Shutdown commands call `controller.Destroy()` to unblock the DNS loop |
| 5 | implant reads system DNS resolver from Tcpip interfaces registry | DNS server IP [registry] → #8 | — | `HKLM\...\Tcpip\Parameters\Interfaces\<GUID>\{NameServer,DhcpNameServer}`; static first, DHCP second; skipped when DnsServer already set in config |
| 6 | implant loads dnsapi.dll via lazy system DLL reference | — [no-artifact] → #8 | — | `windows.NewLazySystemDLL("dnsapi.dll")`; no static import entry; loaded on first DnsQuery_W call |
| 7 | implant spawns child process for shell or command execution | child process [process] → #12 | — | `exec.Command()` or `cmd.exe /c <cmd>`; stdin/stdout piped; created before DNS loop starts |
| 8 | implant sends ECDH ENC_INIT DNS query via DnsQuery_W | DNS query [network] → #9 | — | P-256 public key hex-encoded in question name with ≤20-char labels; Dnscache/svchost.exe owns UDP/53 socket |
| 9 | implant sends ECDH ENC_AUTH DNS query via DnsQuery_W | DNS query [network] → #10 | — | SHA3-256 authenticator verifying pre-shared secret; skipped when no secret configured |
| 10 | implant sends SYN DNS query to open C2 session | DNS query [network] → #11 | — | Session ID + ISN in question name; IsCommand flag marks command-protocol sessions |
| 11 | implant sends MSG DNS queries carrying encrypted C2 data | DNS queries [network] → #12 | — | Salsa20-encrypted; adaptive jitter 1–3 s active / 5–30 s idle; TXT/CNAME/MX/A/AAAA record types |
| 12 | implant relays received C2 commands to child process stdin | stdin writes [process] → terminal | — | `ExecDriver.DataReceived()` writes decrypted MSG data to child stdin; child stdout buffered back into outgoing MSG |
| 13 | implant writes error message to log file on disk `(svc, non-stealth build)` | log file [file] → terminal | — | `<servicename>.log` appended on error; no-op when compiled with `-tags stealth` |
