# TONESHELL v2 — Phase A Injection: Brainstorm & Approach Comparison

**Mục tiêu:** Chọn hoặc cải tiến injection chain cho Phase A của TONESHELL v2 để tối ưu stealth. Kết quả cuối: Dropper (wsdapi.dll → EssosUpdate.exe) đưa shellcode/beacon chạy được trong process mới.

**Hiện trạng (đã build + verified):**
- `CreateProcessW(CREATE_SUSPENDED, waitfor.exe)` + 5 direct syscalls (Alloc/Write/Protect/APC/Resume) qua Halos Gate
- Beacon TCP lên C2 thành công

---

## Tiêu chí đánh giá stealth (từ cao → thấp ảnh hưởng)

| # | Tín hiệu detection | Tại sao mạnh |
|---|---|---|
| S1 | `CREATE_SUSPENDED` + cross-process memory ops | Pattern kinh điển — EDR kernel callback `PsSetCreateProcessNotifyRoutine` bắt process mới tạo, userland hook bắt memory ops sau đó |
| S2 | Cross-process memory writes (alloc/write/protect) | `VirtualAllocEx` + `WriteProcessMemory` vào process khác → rất ít phần mềm hợp lệ làm việc này |
| S3 | Thread/APC tạo trong remote process | `QueueUserAPC` / `CreateRemoteThread` vào process khác |
| S4 | Memory artifact: unbacked executable (Private RX) | Shellcode trong vùng nhớ không map từ file → scan memory thấy code không có file backing |
| S5 | Process tree: `EssosUpdate.exe → waitfor.exe` | Process cha-con không tự nhiên — `wsddebug_host.exe` (EssosUpdate) không spawn `waitfor.exe` trong operation bình thường |
| S6 | File-on-disk artifact | File tạm, payload ghi ra disk, mismatch giữa file và memory |

---

## Danh sách các hướng đã đánh giá

### Nhóm A — Injection vào process mới (giữ nguyên pattern spawn + inject)

| # | Hướng | Mô tả ngắn | Tín hiệu giảm được | Effort | Stealth gain |
|---|---|---|---|---|---|
| A1 | **Early Bird APC + direct syscalls** _(hiện tại)_ | `CreateProcessW(SUSPENDED)` + 5 syscalls bypass userland hook | Không — đây là baseline | Đã làm xong | Baseline |
| A2 | Module Stomping | Load DLL hợp lệ vào target → ghi đè `.text` → code nằm trong vùng backed memory | S4 (backed RX) | Trung bình | Thấp |
| A3 | Process Hollowing | `NtUnmapViewOfSection` → map PE thay thế → target trông như `waitfor.exe` nhưng code đã bị thay | S4 (backed RX), S5 (process trông như binary sạch) | Trung bình | Thấp — `NtUnmapViewOfSection` thêm tín hiệu S2 mới cực mạnh |
| A4 | PPID Spoofing | Set `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` để `waitfor.exe` có cha là `explorer.exe` | S5 (process tree) | Thấp (nhưng `NtCreateUserProcess` đã fail) | Rất thấp — chỉ cosmetic |

### Nhóm B — Injection vào process đang chạy (bỏ `CREATE_SUSPENDED`)

| # | Hướng | Mô tả ngắn | Tín hiệu giảm được | Effort | Stealth gain |
|---|---|---|---|---|---|
| B1 | Target existing process | `OpenProcess` → alloc/write/protect/APC vào process đang chạy (vd `explorer.exe`, `dllhost.exe`) | S1 (không process mới) | Trung bình | Trung bình — vẫn S2+S3 |
| B2 | PoolParty | Chèn work item vào thread pool của target → worker thread có sẵn thực thi shellcode | S3 (không tạo thread mới) | Cao (cần hiểu TP internals) | Trung bình — vẫn S2 |
| B3 | Dirty Vanity (fork) | Clone process đang chạy → memory space y hệt → set RIP → resume | S1 (không CREATE_SUSPENDED), S2 (không WriteProcessMemory) | Cao (cần parse PEB/TEB, xử lý fork edge case) | Cao |

### Nhóm C — Injection qua section object (bỏ `CREATE_SUSPENDED` + cross-process memory)

| # | Hướng | Mô tả ngắn | Tín hiệu giảm được | Effort | Stealth gain |
|---|---|---|---|---|---|
| C1 | Process Herpaderping | `CreateFile`→`WriteFile`→`NtCreateSection`→`NtCreateProcessEx`→`WriteFile`(ghi đè file giả)→`NtCreateThreadEx`→close. File on-disk là binary sạch, memory chạy shellcode | S1, S2, S4 (section-backed) | Trung bình-Cao | Cao |
| C2 | Process Ghosting | `CreateFile`→`WriteFile`→`NtCreateSection`→**xóa file** (giữ section handle)→`NtCreateProcessEx`→`NtCreateThreadEx`. File chưa từng tồn tại khi process chạy | S1, S2, S4, S6 (không file on-disk) | Cao | Rất cao |

### Nhóm D — Thay đổi payload format (không thay đổi injection mechanism)

| # | Hướng | Mô tả ngắn | Lợi ích chính | Effort | Stealth gain |
|---|---|---|---|---|---|
| D1 | DLL Injection (Reflective) | Bọc shellcode thành DLL → RDI stub load trong target → `DllMain` gọi beacon | Maintainability, debug, mở rộng capability | Trung bình | Không đáng kể |
| D2 | PE Injection (Hollowing) | Bọc shellcode thành EXE → hollow `waitfor.exe` → map PE | Maintainability, process trông "chuẩn" hơn | Trung bình | Không — thêm `NtUnmapViewOfSection` |

---

## Tổng hợp — xếp hạng theo stealth gain

```
Rất cao:  C2 Process Ghosting         (0 tín hiệu S1+S2+S6)
Cao:      C1 Process Herpaderping     (0 tín hiệu S1+S2, file mismatch)
          B3 Dirty Vanity             (0 tín hiệu S1+S2)
Trung bình: B1 Target existing process (0 tín hiệu S1)
          B2 PoolParty                (0 tín hiệu S1+S3)
Thấp:     A2 Module Stomping          (chỉ S4)
          A3 Process Hollowing        (thêm S2 từ NtUnmapViewOfSection)
Rất thấp:  A4 PPID Spoofing           (chỉ S5)
Không:     D1/D2 Payload format       (maintainability, không stealth)
```

---

## Khuyến nghị hướng đi

1. **Nếu muốn giữ nguyên code hiện tại, tối thiểu thay đổi:** không làm gì. Early Bird APC + direct syscalls đã verified working, đủ dùng cho Phase A dropper.

2. **Nếu muốn tăng stealth đáng kể mà effort hợp lý:** **C1 Herpaderping** — thay `CreateProcessW(SUSPENDED) + cross-process mem` bằng `write→section→process→modify file→thread`. Shellcode hiện tại không cần thay đổi.

3. **Nếu muốn stealth tối đa:** **C2 Process Ghosting** — như Herpaderping nhưng xóa file trước khi tạo process. Cần handle cẩn thận section handle lifetime.

4. **Nếu muốn maintainability cao hơn:** **D1 Reflective DLL** — bọc shellcode thành DLL, giữ nguyên injection chain hiện tại. Không tăng stealth nhưng payload dễ debug/extend.

## Quyết định

_(để trống — sẽ điền sau khi chọn hướng)_
