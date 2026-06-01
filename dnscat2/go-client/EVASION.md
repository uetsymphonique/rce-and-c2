# dnscat2 Go Client — Đánh giá & Hướng evade

Tài liệu này tổng hợp các bề mặt bị lộ (detection surface) hiện tại của `dnscat2/go-client` và các hướng đề xuất để evade — ưu tiên những hướng làm cho traffic và binary trông **tự nhiên** thay vì obfuscate brute-force.

> Phạm vi: phân tích trên code base hiện có tại `./` (CLI `cmd/dnscat`, service `cmd/dnscat-service`, transport `pkg/tunnel/dns`, protocol/session `pkg/session`, `pkg/protocol`, `pkg/crypto`).

---

## 1. Bề mặt bị lộ hiện tại

| Lớp | Tell-tale | Vị trí trong code |
|---|---|---|
| **Network — chữ ký nội dung** | Subdomain là **hex thuần** `[0-9a-f]`, labels dài tới 62 ký tự, FQDN gần chạm 255 byte | `pkg/tunnel/dns/dns.go` — `encodeDNSName()` |
| **Network — wildcard prefix** | Khi không có domain → prefix literal `"dnscat"` | `pkg/tunnel/dns/dns.go` — `WildcardPrefix` |
| **Network — record type mix** | Random TXT/CNAME/MX trong cùng một session — không client thật nào hành xử như vậy | `pkg/tunnel/dns/dns.go` — `getType()` |
| **Network — beacon rhythm** | Fixed `1000ms` delay + `50ms` read deadline → heartbeat liên tục dù không có data | `pkg/tunnel/dns/dns.go` `Run()`, `pkg/session/session.go` `PacketDelay` |
| **Network — process-to-port-53 anomaly** | `net.ListenUDP` raw → traffic xuất phát trực tiếp từ PID payload, không đi qua Windows DNS Client (`svchost.exe -k NetworkService`) | `pkg/tunnel/dns/dns.go` — `NewDriver()` |
| **Network — handshake fingerprint** | `ENC INIT` đầu phiên có cấu trúc ECDH P-256 (X‖Y) cố định 64 byte, packet đầu kích thước/format đoán được | `pkg/crypto/encryptor.go`, `pkg/session/session.go` state machine |
| **Binary — Go runtime** | ~3.3 MB, gopclntab, build-id, runtime symbols → trivial cho YARA/EDR phát hiện "Go binary" | mặc định Go toolchain |
| **Binary — string literals** | `"dnscat2"`, `"dnscat"`, banner `** WARNING!`, `"Creating a command session!"`, `"DNS: RCODE_..."`, error strings — nhúng nguyên văn | `cmd/dnscat/main.go`, `pkg/tunnel/dns/dns.go` |
| **Process — child lineage** | `--exec=cmd.exe` ⇒ `dnscat2.exe → cmd.exe` (parent-child rất kêu) | `pkg/driver/exec.go` |
| **Stdout leak** | `os.Exit(0)` print `"There are no active sessions left! Goodbye!"`; `DNS: RCODE_*` errors; warning banner | `pkg/tunnel/dns/dns.go`, `cmd/dnscat/main.go` |

---

## 2. Hướng evade — sắp xếp theo "độ tự nhiên"

### 2.1. Lớp Network — quan trọng nhất, dễ ngụy trang tự nhiên

#### (A) Đi qua Windows DNS Client thay vì raw UDP — đòn lớn nhất

Thay `net.ListenUDP` + `BuildDNSQuery` bằng `DnsQuery_W` / `DnsQueryEx` (`windnsapi.dll`), hoặc gọi resolver qua `net.Resolver{PreferGo: false}` để Go gọi xuống `getaddrinfo` → DNS Client service.

- Hiệu quả: traffic UDP/53 xuất phát từ **`svchost.exe` (Dnscache service)**, không phải PID payload. EDR rule "non-DNS-Client process talking to :53" mất tác dụng.
- Bonus: resolver cache làm pattern bớt đều; query đi qua conditional forwarder của DC một cách hoàn toàn hợp lệ.
- Trade-off: phải bỏ A/AAAA mode raw-byte (DnsQuery trả về parsed records), nhưng vẫn giữ được TXT/CNAME/MX.

Đây là cách C2 framework "tự nhiên nhất" nhìn từ host telemetry — về sau khi telemetry rule "process X mở socket UDP/53" trở thành signature thông dụng, đây là cách duy nhất bypass được.

#### (B) Bỏ MX khỏi default, ưu tiên A + CNAME

MX query từ một workstation domain-joined là **bất thường rõ rệt** — chỉ mail client / Exchange query MX. Default `TXT,CNAME,MX` (đang để trong `BUILD.md` và `cmd/dnscat/main.go`) nên đổi thành `A,CNAME` hoặc `CNAME` thuần.

- Quan trọng: **không random giữa MX và TXT trong cùng phiên**. Pick một type cố định cho mỗi session, hoặc dùng A/CNAME cho upstream và TXT chỉ cho downstream data lớn.
- Trade-off: A record chỉ 3 byte payload/answer → throughput giảm. Với C2 mức KB/phút vẫn OK; kết hợp với (D) jitter và (E) burst.

#### (C) Subdomain encoding "trông như CDN"

Hex thuần (`[0-9a-f]`) rất dễ flag bởi entropy + charset rule. Thay bằng:

- **base32 lowercase** (`a-z2-7`) → giống `*.cloudfront.net`, `*.akamaiedge.net` hash subdomains
- **base36** với separator `-` mỗi 8 ký tự → giống Azure Front Door / `r2.dev`

Quan trọng hơn: **shorten label**. Đang max 62 ký tự (`MaxFieldLength`); real CDN subdomain thường 10-24 ký tự. Cap label ở ~20 ký tự, split thành nhiều label cấp 2-3. Trade-off: số query nhiều hơn cho cùng lượng data → kết hợp với (D)/(E).

#### (D) Beacon jitter + working-hours gate

- Bỏ fixed `1000ms`; đổi sang phân phối ngẫu nhiên: `delay = base + rand(0, 2*base)` hoặc log-normal jitter.
- Thêm option `--active-hours=8-18` chỉ beacon trong giờ làm việc local. Off-hours: idle hoàn toàn hoặc chỉ 1 query / 5-15 phút.
- Heartbeat hiện tại 50ms read deadline + retransmit liên tục → rất "máy móc". Sửa vòng `Run()` để khi `OutgoingBuffer` rỗng, kéo dài interval lên 5-30s (jitter).

#### (E) Burst pattern thay vì stream đều

Real-world DNS C2 (Cobalt Strike DNS beacon, Saitama) dùng pattern: idle dài → burst ngắn khi có command/response → quay lại idle. Code hiện có `OutgoingBuffer`-driven send, nhưng cần kết hợp idle timer dài và bỏ heartbeat khi không có data thực sự cần gửi.

#### (F) Domain masquerade phải match record type

`crl.ms-cert.net` đang dùng (mô phỏng Microsoft CRL) — **CRL traffic thực tế không bao giờ query TXT/MX**, chỉ A/AAAA. Nếu giữ vỏ bọc này thì `--dns-type=A,CNAME` mới nhất quán.

Bảng pairing đề xuất:

| Vỏ bọc | Record type phù hợp | Ghi chú |
|---|---|---|
| `crl.*`, `ocsp.*` | A, CNAME | Phù hợp Microsoft cert revocation flow |
| `*.windowsupdate.com`, `*.azureedge.net` | A, CNAME | High-volume update traffic, ít ai để ý |
| `*.spf.*`, `_dmarc.*`, `_acme-challenge.*` | TXT | TXT acceptable nhưng query volume thấp → suspicious nếu bursty |
| `*.telemetry.*`, `*.events.data.microsoft.com` | A, CNAME (chính là MS telemetry pattern) | Match cực tốt với "dnscat-service" persistence |

#### (G) Giảm fingerprint handshake

ENC INIT (ECDH pubkey X‖Y, 64 byte) trong vài packet đầu tạo signature ổn định. Hai cách:

- Pre-shared key + pre-derived session keys (cần sửa server) → bỏ ENC handshake on-wire, vào thẳng MSG.
- Đệm dummy queries trước handshake để ENC packets lẫn vào noise.

---

### 2.2. Lớp Binary — chống YARA / static analysis

#### (H) `-trimpath` + xoá build-id + garble

```bash
go build -trimpath -ldflags="-s -w -buildid=" \
  -o payload.exe ./cmd/dnscat/

# hoặc mạnh hơn với garble:
garble -literals -tiny build -trimpath \
  -ldflags="-s -w -buildid=" -o payload.exe ./cmd/dnscat/
```

- `-literals` của [garble](https://github.com/burrowers/garble) obfuscate **toàn bộ string literals** (bao gồm `"dnscat2"`, `"DNS: RCODE_..."` v.v.) → vô hiệu hoá strings-based signature.
- `-tiny` xoá metadata reflection còn lại của Go runtime, đồng thời rút gọn panic info.
- `-trimpath` xoá đường dẫn build local trong gopclntab.

#### (I) Strip toàn bộ print path trong "stealth build"

Tạo build tag `//go:build stealth` và compile-out tất cả `fmt.Println`/`fmt.Printf` ở:

- `cmd/dnscat/main.go` — banner WARNING, "Creating a ... session!", driver info print
- `pkg/tunnel/dns/dns.go` — "DNS: RCODE_*", "DNS didn't return an answer", "There are no active sessions left! Goodbye!"
- `pkg/session/session.go` — packet trace log

Cách làm: thay `fmt.Println(...)` bằng wrapper `debugLog(...)` mặc định no-op trong release build. Trong stealth build, `os.Exit(0)` cũng nên đổi sang silent exit (đang in `"Goodbye!"`).

#### (J) Cân nhắc giảm runtime footprint

Viết lại transport layer (chỉ DNS tunnel + protocol packet, không cần session/crypto/driver phức tạp khi đã có server cooperated) bằng **C/Rust** để bỏ Go runtime 3MB → 100-300KB. Không bắt buộc cho test lab, nhưng nếu mục tiêu là binary "trông tự nhiên" như standalone Windows service utility (`certupdater.exe` ~ 200KB) thì 3MB Go binary là một anomaly tự nó.

Mức trung gian: vẫn dùng Go nhưng compile stripped + UPX → ~1MB.

---

### 2.3. Lớp Process / Runtime — chống behavioral telemetry

#### (K) Dùng Windows Service variant với tên & description tự nhiên

`cmd/dnscat-service/` đã hỗ trợ service mode. Tận dụng:

- Parent process trở thành `services.exe` (rất tự nhiên cho outbound DNS).
- Service display name + description giả Microsoft:
  - `Certificate Status Update Service` — "Maintains the certificate revocation list cache for client applications. Disabling this service may prevent applications from validating certificates."
  - `Windows Diagnostics Tracking` — match với telemetry domain masquerade.
- File on disk: `C:\Windows\System32\certupdater.exe` hoặc `C:\Program Files\Common Files\Microsoft Shared\CrlMaint\crlmaint.exe`.
- Service config in registry không nhất thiết phải đặt dưới `HKLM\...\Services\dnscat2\Parameters` — đổi key sang `Services\CertSvcMaint\Parameters` để khớp với tên service mới.

#### (L) Tránh `--exec=cmd.exe` direct spawn

Hiện tại `dnscat2.exe → cmd.exe` là parent-child rất nổi. Hai hướng:

- **Bỏ exec channel, chỉ giữ command session.** Command session đã hỗ trợ shell/exec/upload/download/tunnel qua server → không cần spawn shell từ lúc khởi động. Ưu điểm: dnscat2 process không có child process gì cho tới khi server chủ động yêu cầu shell.
- **PPID spoof khi spawn cmd.exe** — sử dụng `UpdateProcThreadAttribute` với `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` để cmd.exe có vẻ là con của `explorer.exe` / `svchost.exe`.

#### (M) Reflective load để bỏ binary on-disk

Plan đã có `[ALT] Step 1B: T1620 reflective load` cho IIS path. Áp dụng tương tự cho host khác — bypass file-based detection hoàn toàn, kết hợp với (K) làm persistence (service entry trỏ vào loader giả Microsoft).

---

### 2.4. Lớp Operator / Usage — không sửa code, vẫn evade tốt hơn

#### (N) Không chạy ping mode trong production

`--ping` rất noisy về protocol (PING packet rỗng, không có data nghiệp vụ). Chỉ test connectivity 1 lần rồi tắt.

#### (O) Tách kênh "command" và kênh "shell" thành 2 binary build khác nhau

Một binary chỉ command session (no exec, no upload/download) → footprint nhỏ, ít behavior. Khi cần shell mới drop binary thứ hai qua command channel. Giảm "surface" của payload chính.

#### (P) Domain rotation

Compile nhiều biến thể với `DefaultDomain` khác nhau (`crl.ms-cert.net`, `ocsp.ms-cert.net`, `tm.ms-cert.net`). Khi server bị flag, swap binary mới qua command channel thay vì sửa cùng một file.

---

## 3. Recommended stack — kết hợp impact + tự nhiên

Nếu chỉ chọn 5 thay đổi cho **một build "natural-looking"**:

1. **(A)** Switch sang Windows DNS Client API — single biggest behavioral win.
2. **(B) + (F)** Default `--dns-type=A,CNAME` với domain `crl.ms-cert.net` (hoặc telemetry domain) — type và vỏ bọc khớp nhau.
3. **(C)** Đổi encoding sang base32 lowercase, label ≤ 24 ký tự — match CDN subdomain shape.
4. **(D)** Jittered beacon (`delay = 1000 + rand(0..2000)` ms) + idle interval 30s khi buffer rỗng.
5. **(H) + (I)** `garble -literals -tiny` + stealth build tag bỏ tất cả `fmt.Print*`.

Stack này không cần sửa server, không phá compatibility, không cần thêm dependency lớn, và mỗi thay đổi đều có lý do "tự nhiên" (DNS Client là cách Windows app vẫn dùng, A/CNAME là pattern CRL/CDN, base32 là pattern subdomain hash phổ biến, jitter là cách mọi app retry-ed sau khi gặp lỗi DNS).

Nếu muốn đi xa hơn (lab scenario nhắm tới EDR cao cấp):

6. **(K)** Service variant với name `Certificate Status Update Service`, file `certupdater.exe` trong `System32`.
7. **(L)** Bỏ `--exec` direct spawn, chỉ tạo shell qua command channel khi cần.
8. **(M)** Reflective load để bỏ on-disk artifact.

---

## 4. Trade-off & lưu ý

| Hướng | Cost | Risk khi áp dụng |
|---|---|---|
| (A) DnsQuery API | Sửa transport layer (~200 LoC), bỏ A/AAAA raw mode | Mất khả năng dùng A/AAAA cho raw byte transport |
| (B) Drop MX | Update default | Không có |
| (C) Encoding mới | Sửa cả client + server (Ruby `dnscat2.rb`) | **Phá compatibility với upstream server** — cần fork server hoặc cấu hình encoding qua flag |
| (D)/(E) Jitter | Sửa `Run()` loop | Latency tăng → ảnh hưởng interactive shell experience |
| (G) Pre-shared key | Sửa cả server | Phá compatibility |
| (H) garble | Thêm build tool | Đôi khi break reflection-based code; test kỹ |
| (I) Strip prints | Sửa code, build tag | Khó debug — chỉ áp dụng cho release |
| (J) Rewrite C/Rust | Effort lớn | Mất các ưu điểm Go (cross-platform, single binary) |
| (K) Service masquerade | Mostly operator-side | Tên service nên check không trùng service có thật trên lab |
| (L) Drop `--exec` | Bỏ build flag | Mất khả năng auto-shell khi binary chạy không có server |
| (M) Reflective load | Cần loader riêng | Đã có trong plan ở `[ALT] Step 1B` |

---

## 5. Mapping tới detection control điển hình

| Detection control | Hướng evade chính |
|---|---|
| YARA signature trên Go binary / "dnscat" string | (H), (I) |
| EDR rule "process X opens UDP/53" | (A) |
| DNS analytics: high-entropy subdomain | (C) |
| DNS analytics: query volume per host per minute | (D), (E) |
| DNS analytics: anomalous record type (MX from workstation) | (B), (F) |
| Process telemetry: dnscat2.exe → cmd.exe | (L), (M) |
| File-based AV scan | (M) |
| Persistence baseline (suspicious service name) | (K) |
| Beacon timing analysis (FFT / autocorrelation) | (D), (E) |
| TLS/handshake JA3-equivalent on DNS | (G) |

---

## 6. Phân tích server dependency

Đánh giá dựa trên hai file server chính:
- `../server/tunnel_drivers/driver_dns.rb` — DNS transport, parse query name, encode response
- `../server/controller/encryptor.rb` + `controller/session.rb` — session state machine, ECDH, PSK

Có ba điểm hardcode quan trọng phía server cần nắm trước khi triển khai bất kỳ hướng nào:

```ruby
# driver_dns.rb:171 — hard-block mọi ký tự ngoài hex và dấu chấm
if(name !~ /^[a-fA-F0-9.]*$/)
  return nil
end

# driver_dns.rb:177 — decode query name bằng hex
name = [name].pack("H*")

# driver_dns.rb:32-49 — encode response bằng hex cho TXT/CNAME/MX
name.unpack("H*").pop  # TXT
name.unpack("H*").pop.chars.each_slice(63)...  # CNAME, MX
```

### Nhóm 1 — Không cần sửa server

Tất cả hướng sau đây hoàn toàn **client-side hoặc deployment-side**. Server nhận DNS packet đúng protocol như cũ, không cần sửa bất kỳ dòng nào trong codebase Ruby.

| Hướng | Lý do không cần sửa server |
|---|---|
| **(A)** DNS Client API | Server chỉ thấy UDP packet DNS y hệt — không phân biệt client gửi bằng raw socket hay qua `DnsQuery_W`. |
| **(B)** Drop MX, dùng A + CNAME | `RECORD_TYPES` hash trong `driver_dns.rb` đã có đủ A, CNAME, TXT. A record dùng encoding binary riêng (`requires_hex: false`), không liên quan hex. CNAME đã có sẵn. |
| **(D)** Beacon jitter + working-hours gate | Timing logic nằm hoàn toàn ở client. Server không quan tâm tần suất nhận query. |
| **(E)** Burst pattern | Tương tự (D) — server passive, xử lý khi có query đến. |
| **(F)** Domain masquerade | Chỉ là giá trị `--dns domain=...` ở server startup. Không cần đổi code. |
| **(G-dummy)** Dummy queries trước handshake | Server trả `nil` cho query không nhận ra (line 167: `if name.nil? return nil`) và drop gracefully — không crash, không ảnh hưởng real session. Server log thêm dòng "Unable to handle request" nhưng không cần sửa. |
| **(H)** garble + trimpath + build-id | Build-time only. Binary đến server có protocol packet giống hệt. |
| **(I)** Strip print path / stealth build tag | Client code change. Server không bao giờ thấy stdout client. |
| **(J)** Rewrite transport C/Rust | Nếu giữ protocol compatibility (hex encoding, same packet format, same A/CNAME/TXT record logic) thì server không cần sửa. |
| **(K)** Service masquerade | Deployment/operator side. |
| **(L)** Drop `--exec`, chỉ command session | Server command-session driver đã hoạt động không cần exec phía client khi startup. |
| **(M)** Reflective load | Deployment side. Protocol không đổi. |
| **(N)** Không dùng ping mode | Operator usage. |
| **(O)** Split binary command/shell | Operator/build. |
| **(P)** Domain rotation | Client `ldflags` config. Server cần `--dns domain=...` mới nhưng đó là config lúc chạy, không phải code change. |

**Ghi chú cho (C) label length shortening:** Nếu chỉ rút ngắn label từ 62 xuống 20 ký tự **nhưng vẫn giữ hex**, server không cần sửa — `name.gsub(/\./, '')` strip hết dấu chấm trước khi decode, không quan tâm số label hay độ dài từng label.

---

### Nhóm 2 — Thay đổi nhỏ phía server

Các hướng này **hoạt động được mà không sửa** (không crash, không phá session), nhưng cần sửa nhỏ để đạt hiệu quả đầy đủ.

#### (G-dummy) Dummy queries với response hợp lệ

**Không sửa:** Server drop dummy query, log "Unable to handle request", client vẫn hoạt động bình thường.

**Nếu muốn hoàn hảo hơn:** Thêm ~10 dòng Ruby vào `driver_dns.rb` để trả lời dummy query bằng response tự nhiên (NXDOMAIN hoặc một IP placeholder) thay vì im lặng. Im lặng (không reply) với một DNS query là bất thường trong chính DNS traffic — resolver thật luôn trả lời gì đó, dù là NXDOMAIN.

```ruby
# Thêm vào phần handle unrecognized queries trong driver_dns.rb
# Trả NXDOMAIN thay vì không reply
response.rcode = DNSer::Packet::RCODE_NAME_ERROR
```

Scope sửa: ~10 dòng trong `handle_dns_request` hoặc `packet_to_bytes` fallback.

---

### Nhóm 3 — Thay đổi lớn phía server

Các hướng này **phá compatibility** hoặc đòi hỏi sửa core logic của server Ruby — không thể dùng upstream `dnscat2.rb` mà không fork.

#### (C) Đổi encoding sang base32 / base36

**Điểm chặn trong server:**

```ruby
# driver_dns.rb:171 — regex chỉ cho phép [a-fA-F0-9.]
if(name !~ /^[a-fA-F0-9.]*$/)
  return nil  # ← Query bị drop, session không bao giờ được thiết lập
end

# driver_dns.rb:177 — pack("H*") chỉ decode hex
name = [name].pack("H*")  # ← base32 input → garbage hoặc exception
```

**Cần sửa server:**
1. `packet_to_bytes`: bỏ hex-only regex, thêm base32 decode (hoặc thêm `?encoding=` negotiation)
2. Response encoders trong `RECORD_TYPES` cho TXT/CNAME/MX: đổi `name.unpack("H*")` sang base32 encode tương ứng
3. Test toàn bộ A/AAAA path (hiện dùng raw binary, không bị ảnh hưởng nếu chỉ đổi query encoding)

Scope sửa: ~30-50 dòng trong `driver_dns.rb`, cần test hồi quy toàn bộ record types.

#### (G-keys) Pre-derived session keys — bỏ ECDH handshake on-wire

**Điểm chặn trong server:**

Server session state machine (`controller/session.rb`) bắt đầu ở trạng thái `BEFORE_ENC_REQUEST`, chờ `ENC_INIT` packet chứa ECDH pubkey trước khi xử lý bất kỳ `SYN` hay `MSG` nào. Nếu client bỏ qua ENC INIT và gửi thẳng `SYN`, server sẽ reject vì state machine không match.

**Cần sửa server:**
1. `controller/session.rb`: thêm state `BEFORE_SYN_PRESHARED` — khi có PSK và cả hai bên đã agree trên pre-derived keys, skip toàn bộ ECDH state transitions
2. `controller/encryptor.rb`: thêm constructor mode không dùng ECDH — nhận pre-derived key pair thay vì tự tạo ECDH
3. `controller/packet.rb`: đảm bảo server không strict-require ENC packet khi PSK đủ để derive keys

Scope sửa: ~80-120 dòng trên 3 file, ảnh hưởng security model của toàn bộ protocol — cần review kỹ.

---

### Tổng hợp

| Approach | Server dependency | Ghi chú |
|---|---|---|
| (A) DNS Client API | Không | Transparent với server |
| (B) Drop MX | Không | Server đã support A, CNAME, TXT |
| (C) Label length rút ngắn (giữ hex) | Không | Server strip dots, không quan tâm label count |
| (C) Đổi charset sang base32/base36 | **Lớn** | Regex + pack/unpack trong `driver_dns.rb` |
| (D) Jitter | Không | Client timing |
| (E) Burst pattern | Không | Client timing |
| (F) Domain masquerade | Không | Server config lúc chạy |
| (G) Dummy queries | Không (hoạt động) / Nhỏ (hoàn hảo) | Server drop gracefully; thêm ~10 dòng để trả NXDOMAIN |
| (G) Pre-derived session keys | **Lớn** | Session state machine + encryptor |
| (H) garble + build flags | Không | Build-time |
| (I) Strip prints | Không | Client-only |
| (J) Rewrite C/Rust (protocol-compatible) | Không | Giữ hex encoding + packet format |
| (K) Service masquerade | Không | Deployment |
| (L) Drop `--exec` spawn | Không | Server không bị ảnh hưởng |
| (M) Reflective load | Không | Deployment |
| (N/O/P) Operator practices | Không | Usage/config |

---

## 8. Tham chiếu

- Code flow tổng quan: `../../../Emulation_Plan/further-reading/dnscat2.md`
- Build options hiện tại: `./BUILD.md`
- Plan integration: `../../../Emulation_Plan/iis-apppool-escalation-path/Phase 1.md` (dnscat2 C2 trên IIS01)
- Plan integration: `../../../Emulation_Plan/toneshell-path/Phase 1.md` (so sánh với Toneshell TCP C2)
- `garble` obfuscator: https://github.com/burrowers/garble
