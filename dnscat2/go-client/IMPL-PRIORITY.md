# Evasion Implementation Priority (no server changes)

Full analysis: `EVASION.md`

## Pass 1 — Build flags (~1h)
- **(H)** `garble -literals -tiny build -trimpath -ldflags="-s -w -buildid="` — kill YARA / string signatures
- **(I)** Add `//go:build stealth` tag; replace `fmt.Print*` with no-op wrapper — kill stdout leak

## Pass 2 — Default config (~30 min)
- **(B + F)** Change default `--dns-type` to `A,CNAME`; pair with `crl.ms-cert.net` masquerade — kill MX anomaly

## Pass 3 — Code changes (~2h)
- **(D + E)** Jitter `Run()` loop: `delay = 1000 + rand(0..2000)` ms; elongate idle interval to 5-30s when buffer empty — kill timing fingerprint
- **(C)** Cap label length at ~20 chars in `encodeDNSName()`, split into more labels; keep hex — kill entropy rule; no server change needed

## Pass 4 — Deployment
- **(K)** Service name `Certificate Status Update Service`, file `certupdater.exe` in `System32` — kill persistence baseline signal
- **(L)** Drop `--exec` at launch; use command channel for shell — kill `dnscat2.exe → cmd.exe` parent-child

## Deferred
- **(A)** DNS Client API (`DnsQuery_W`) — biggest behavioral win (kill non-DnsCache UDP/53), ~200 LoC transport rewrite; prioritize if EDR hits on that rule
- **(M)** Reflective load — already `[ALT] Step 1B` in Phase 1; deployment decision, not a go-client code change
