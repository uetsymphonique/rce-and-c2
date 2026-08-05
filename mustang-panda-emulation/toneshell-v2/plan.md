# TONESHELL — Stealth Rewrite Plan

Kế hoạch thay đổi luồng C2 hiện tại của TONESHELL để giảm bề mặt detection. Đây là **rewrite chính luồng** (không phải variant), chấp nhận drift một phần khỏi MITRE 2025 Mustang Panda Reference Table (rows 168-170: T1218.010 regsvr32, T1218.013 mavinject).

**Giữ nguyên** (không liên quan chain đang đổi):
- LNK → cmd → `EssosUpdate.exe` sideload `wsdapi.dll` (trigger)
- Sandbox checks (T1497.001 process-name / T1497.002 foreground-window)
- `Handler()` throw + catch → hop (T1622 Debugger Evasion)
- Authenticode self-sign `wsdapi.dll` (T1553.002 Code Signing)
- Shellcode: FNV1A API resolve, triple-XOR decrypt, PIC
- C2 protocol wire (magic `0x18 0x04 0x04`, XOR body, hostname session ID)

**Loại bỏ**:
- `regsvr32.exe wsdapi.dll` spawn (T1218.010)
- `waitfor.exe` + `mavinject.exe /INJECTRUNNING` chain (T1218.013)
- Export `DllRegisterServer` khỏi `wsdapi.dll`

---

## 1. Injection chain mới — Early Bird APC + hybrid syscalls

### 1.1. Chain (actual implementation)

```
EssosUpdate.exe                                     # sideload trigger (không đổi)
  └─ wsdapi.dll:WSDAPI export → Handler()           # checks + custom exception (không đổi)
      └─ catch(CustomException&) → InjectAndSpawn() # REWRITE
          ├─ Halos Gate: resolve SSN cho 5 Nt* syscalls từ ntdll in-memory
          ├─ Decrypt shellcode trong local memory (triple-XOR)
          ├─ CreateProcessW("waitfor.exe", CREATE_SUSPENDED)  # kernel32 — compatible mọi build
          ├─ NtAllocateVirtualMemory(remote, size, RW)         # direct syscall
          ├─ NtWriteVirtualMemory(remote, shellcode)           # direct syscall
          ├─ NtProtectVirtualMemory(remote, RX)                # direct syscall — RW→RX
          ├─ NtQueueApcThread(main_thread, shellcode_base)     # direct syscall — Early Bird
          └─ NtResumeThread(main_thread)                       # direct syscall
      shellcode runs trong waitfor.exe → C2 với jitter (mục 2)
```

Process tree:
```
V1 (cũ): explorer → cmd → EssosUpdate → regsvr32 → waitfor + mavinject       (5 nodes)
V2 (mới): explorer → cmd → EssosUpdate → waitfor                              (3 nodes)
```

`wsdapi.dll` Image Load: 3 lần (V1) → 1 lần (V2). Shellcode raw trong waitfor.exe — không DLL, không LoadLibrary.

### 1.2. Rationale

| Điểm | Ý nghĩa |
|---|---|
| **CreateProcessW** cho spawn | `NtCreateUserProcess` signature thay đổi giữa Windows builds, `PS_CREATE_INFO` union layout mong manh → thực tế không portable. CreateProcessW + CREATE_SUSPENDED ổn định mọi build, process creation từ signed binary ít đáng ngờ. |
| **5 direct syscalls** cho injection | `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtQueueApcThread`, `NtResumeThread` — bypass userland EDR hooks ở 5 điểm bị hook nặng nhất. Resolve SSN qua Halos Gate (PEB → ntdll export → check `0xE9` hook → neighbor fallback). |
| **Ghi shellcode thẳng** (không `LoadLibraryW`) | Loại `Image Load` event cho `wsdapi.dll` trong `waitfor.exe` — dấu hiệu nổi bật nhất của mavinject variant. Đổi lại thêm "unbacked executable memory" — nhưng pattern chung của mọi in-memory loader, ít đặc thù hơn. |
| **RW → RX transition** (không RWX) | Tránh `PAGE_EXECUTE_READWRITE` — EDR thường flag mọi alloc RWX vào remote process. |
| **`waitfor.exe`** làm host | Main thread block trên `WaitForSingleObject` → hợp Early Bird (APC fire khi alertable wait đầu tiên). Microsoft-signed system utility. |
| **`SUSPENDED` + APC + `Resume`** (Early Bird) | Không cần `SuspendThread`/`GetThreadContext`/`SetThreadContext`. APC fire trước main logic của thread. |
| **Không cần `regsvr32`** | Chain cũ cần regsvr32 chỉ để có context "sạch" gọi `DllRegisterServer` — giờ decrypt + inject thẳng từ EssosUpdate.exe. |

### 1.3. Detection surface mới

| Behavior | Tactic / TID |
|---|---|
| Cross-process memory write từ `EssosUpdate.exe` → `waitfor.exe` + `NtQueueApcThread` | Stealth / T1055.004 — Process Injection: Asynchronous Procedure Call |
| Halos Gate: resolve SSN từ ntdll + invoke `syscall` bypass ntdll stub | Stealth / T1106 — Native API |
| Decrypt embedded shellcode in local memory | Stealth / T1140 — Deobfuscate/Decode Files or Information |
| Unbacked executable memory trong `waitfor.exe` (RX không map file) | (memory heuristic — không TID riêng) |

**Rows cũ xoá** khỏi Flow.md + Phase file downstream: T1218.010, T1218.013. **Rows mới thêm**: T1055.004, T1106.

### 1.4. Files changed (actual)

**New files (5)**:

| File | Vai trò |
|---|---|
| `src/common/syscalls.asm` | 6 ML64 syscall stubs (`mov r10, rcx; mov eax, SSN; syscall; ret`). Chỉ dùng 5 (NtCreateUserProcess giữ lại không gọi). |
| `src/common/syscalls.hpp` | Typedefs `PS_CREATE_INFO`, `PS_ATTRIBUTE_LIST`, `RTL_USER_PROCESS_PARAMETERS`; extern `SysNt*` declarations; `RtlCreateProcessParametersEx_t`; `InitSyscalls()` / `SysGetRtlCreateProcessParametersEx()`. |
| `src/common/syscalls.cpp` | Halos Gate resolver: PEB → ntdll base → parse export → check hook (`0xE9`/`0xEB`) → neighbor fallback → patch SSN vào .asm stubs. Resolve 5 active + 1 dormant syscall. |
| `src/common/inject.hpp` | `DWORD InjectAndSpawn(shared_func_pointers* fp, logger_ctx* log_ctx);` |
| `src/common/inject.cpp` | Decrypt shellcode → CreateProcessW(SUSPENDED) → 5x direct syscall injection → cleanup. Pattern `do-while(false); break;` giống RunPayload(). |

**Modified files (4)**:

| File | Thay đổi |
|---|---|
| `src/common/handler.cpp` | Thêm `#include "inject.hpp"` + `#include "register.hpp"`. Catch block dùng `#ifdef TONESHELL_DIRECT_SYSCALL` switch giữa `InjectAndSpawn()` (wsdapi) / `RegisterSelf()` (gflagsui). Cập nhật comment block ATT&CK (T1106, T1055.004). |
| `src/wsdapi/wsdapi.def` | Xoá `DllRegisterServer`. |
| `src/wsdapi/CMakeLists.txt` | Thêm `inject.cpp`, `syscalls.cpp`, `syscalls.asm`; bỏ `register.cpp`; thêm define `TONESHELL_DIRECT_SYSCALL`; bỏ `DLL_REG_LOG_FILE`. |
| `CMakeLists.txt` | `LANGUAGES CXX C ASM_MASM`. |

**Unchanged (shared with gflagsui/target: test4 path)**:

| File | Ghi chú |
|---|---|
| `src/common/register.cpp` | Vẫn chứa `RegisterSelf()` + `DllRegisterServer()` — dùng bởi gflagsui target (Protections Test 4). |
| `src/common/register.hpp` | Giữ nguyên. |
| `src/wsdapi/dllmain.cpp` | Không đổi — `InWaitforProcess()` + `DLL_PROCESS_ATTACH` thread trở thành dead code cho TONESHELL path (vẫn live cho gflagsui). |

### 1.5. Direct syscall — implementation notes

- Resolve `ntdll.dll` base từ PEB.Ldr → parse Export Directory → tìm `Nt*`/`Zw*` exports.
- Stub layout Win10/11 x64: `mov r10, rcx ; mov eax, <SYSCALL_NUM> ; syscall ; ret` → SYSCALL_NUM là dword tại `stub+4`.
- Hook detection: byte đầu = `0xE9` (jmp) hoặc `0xEB` (short jmp) → Halos Gate fallback: syscall num tăng đơn điệu theo ordinal → tính từ neighbor sạch.
- MSVC x64 không hỗ trợ inline asm → `.asm` file compile bằng ML64.
- Syscall numbers không hard-code → portable giữa các Windows builds.

---

## 2. Adaptive jitter — 2-tier + response bypass ✅ DONE

Import chiến lược của `dnscat2/go-client`. TONESHELL persistent TCP, áp dụng ở tầng `PerformTaskLoop`.

### 2.1. Two-tier schedule

| State | Range | Điều kiện |
|---|---|---|
| **Burst** | `0` (immediate) | Server vừa trả task thực (EXEC_CMD / FILE_DOWNLOAD / FILE_UPLOAD / RECONNECT) — beacon ngay để nộp kết quả hoặc nhận task tiếp |
| **Idle** | 5000 + rand(0..25000) ms → **5–30 s** | Server trả IDLE hoặc beacon lỗi — không có task pending |

### 2.2. Immediate follow-up after task

Protocol one-shot socket (`connect → send → recv → close`):
- Server trả task thực: beacon kế tiếp delay = 0 (burst)
- Hoàn thành execution task: beacon tiếp theo delay = 0 gửi `NotifyTaskComplete`
- Kết quả: burst pattern (idle dài → 1-2 beacon nhanh → idle) giống Cobalt Strike / Saitama fingerprint

### 2.3. Compile-time knobs

Trong `CMakePresets.json::configurePresets[0].cacheVariables`:

| Variable | Default | Ý nghĩa |
|---|---|---|
| `TONESHELL_JITTER_ACTIVE_MIN_MS` | `1000` | Cận dưới bucket Active |
| `TONESHELL_JITTER_ACTIVE_MAX_MS` | `3000` | Cận trên bucket Active |
| `TONESHELL_JITTER_IDLE_MIN_MS` | `5000` | Cận dưới bucket Idle |
| `TONESHELL_JITTER_IDLE_MAX_MS` | `30000` | Cận trên bucket Idle |

### 2.4. PRNG

`xorshift64` (không cần crypto strength). Seed từ `__rdtsc() ^ fp_GetTickCount64()`.

### 2.5. Files modified for jitter

| File | Thay đổi |
|---|---|
| `src/shellcode/prng.hpp` | `xorshift64_state` + `xorshift64_seed` + `xorshift64_next` |
| `src/shellcode/shellcode.hpp` | `GetTickCount64_t` + `fp_GetTickCount64` trong `func_pointers` + `FAIL_GET_GETTICKCOUNT64` |
| `src/shellcode/shellcode_util.cpp` | Resolve `GetTickCount64` từ kernel32 trong `FetchFunctions` |
| `src/shellcode/entry.cpp` | `ComputeJitter()` + `PerformTaskLoop` với 2-tier jitter + immediate follow-up |
| `src/shellcode/CMakeLists.txt` | `-DTONESHELL_JITTER_*` compile definitions cho `shellcode-pe` |
| `CMakePresets.json` | 4 cache variable jitter |

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
| — | `wsdapi.dll` resolve syscall numbers từ ntdll in-memory (Halos Gate) | Stealth / T1027.007 — Dynamic API Resolution |
| — | `wsdapi.dll` decrypt embedded shellcode (triple-XOR) trong local memory | Stealth / T1140 — Deobfuscate/Decode Files or Information |
| — | `wsdapi.dll` spawn `waitfor.exe` SUSPENDED via `CreateProcessW` | Execution / T1106 — Native API |
| — | `wsdapi.dll` allocate + write shellcode to `waitfor.exe` remote memory | Stealth / T1055 — Process Injection (parent) |
| — | `wsdapi.dll` queue APC to main thread + resume (Early Bird) | Stealth / T1055.004 — Process Injection: APC |
| — | shellcode `PerformTaskLoop` uses adaptive jitter 1-3s active / 5-30s idle | C2 / T1029 — Scheduled Transfer |

Chạy `/document-flow` lại và `/map-technique` cho các hàng mới sau khi implement xong.

---

## 4. Roadmap implement

1. **Phase A — syscalls + injection chain** ✅ DONE
   - [x] Thêm `enable_language(ASM_MASM)` vào root `CMakeLists.txt`
   - [x] Viết `src/common/syscalls.hpp` (Halos Gate resolver + structs + externs)
   - [x] Viết `src/common/syscalls.asm` (ML64 stubs: 6 hàm Nt*, dùng 5)
   - [x] Viết `src/common/syscalls.cpp` (Halos Gate implementation)
   - [x] Viết `src/common/inject.hpp` + `src/common/inject.cpp` (InjectAndSpawn)
   - [x] Sửa `handler.cpp` — `#ifdef TONESHELL_DIRECT_SYSCALL` switch
   - [x] Xoá `DllRegisterServer` khỏi `wsdapi.def`
   - [x] Xoá `DLL_REG_LOG_FILE` khỏi `src/wsdapi/CMakeLists.txt`
   - [x] Update `src/wsdapi/CMakeLists.txt` — add new files, remove register.cpp
   - [x] Rebuild + test: decrypt OK, inject OK, C2 beacon OK

2. **Phase B — jitter (mục 2)** ✅ DONE
   - [x] Thêm 4 cache vars vào `CMakePresets.json`
   - [x] Thêm `-DTONESHELL_JITTER_*` compile definitions vào `src/shellcode/CMakeLists.txt`
   - [x] Thêm `GetTickCount64_t` + `fp_GetTickCount64` vào `func_pointers`
   - [x] Thêm resolve `GetTickCount64` từ kernel32 trong `FetchFunctions`
   - [x] Viết `xorshift64` helper trong `src/shellcode/prng.hpp`
   - [x] Sửa `PerformTaskLoop` trong `entry.cpp` — 2-tier jitter + immediate follow-up
   - [x] Test end-to-end với controlServer: beacon confirmed

3. **Phase C — docs**
   - [ ] Update `Flow.md` (xoá 5 rows cũ, thêm 5 rows mới)
   - [ ] Chạy `/map-technique` cho rows mới
   - [ ] Update `README.md`: đổi mô tả chain (bỏ regsvr32/mavinject), thêm section jitter
   - [ ] Update `Build.md`: thêm 4 knob jitter vào bảng CMake cache variables

---

## 5. Trade-off summary

| Aspect | Trước (V1) | Sau (V2) | Đánh giá |
|---|---|---|---|
| Fidelity với Mustang Panda 2025 | 100% (regsvr32 + mavinject là TTP thật) | Partial (mất 2 rows, thêm 2 rows tương đương) | Chấp nhận |
| Process tree | 5 nodes (explorer→cmd→EssosUpdate→regsvr32→waitfor + mavinject) | 3 nodes (explorer→cmd→EssosUpdate→waitfor) | Ngắn hơn, ít node hơn |
| `wsdapi.dll` Image Load events | 3 (EssosUpdate, regsvr32, waitfor) | 1 (EssosUpdate) | Big win |
| LOLBAS artifacts | 2 (regsvr32.exe, mavinject.exe) | 0 | Big win |
| Process creation method | CreateProcessW (kernel32) | CreateProcessW (kernel32) | Ngang |
| Injection method | kernel32 → ntdll (hookable) | Direct syscall (bypass userland hooks) | Big win |
| Cross-process memory events | 1 (mavinject write + LoadLibrary) | 1 (in-process write + APC) | Ngang |
| Beacon rhythm fingerprint | Fixed hoặc single-value | 2-tier adaptive jitter + response bypass | Big win |
| YARA/EDR hooking on ntdll | Vulnerable (dùng imports thường) | Bypassed (direct syscall) | Big win |
| Compile complexity | Standard C++ only | C++ + ASM_MASM + Halos Gate + PRNG | Chi phí tăng |

---

## 6. Lessons learned

- **`NtCreateUserProcess` không portable**: Signature + struct layout (`PS_CREATE_INFO`, `RTL_USER_PROCESS_PARAMETERS`) thay đổi giữa Windows builds. Đã thử pad PS_CREATE_INFO lên 24 bytes vẫn `STATUS_INVALID_PARAMETER`. Solution: dùng `CreateProcessW` cho spawn, giữ direct syscall cho injection.
- **Halos Gate neighbor fallback hoạt động**: Trên target machine không có EDR hook nên SSN được extract trực tiếp từ stub. Fallback path chưa được test trong điều kiện có hook nhưng logic đã sẵn sàng.
- **`handler.cpp` shared giữa 2 targets**: Dùng `#ifdef TONESHELL_DIRECT_SYSCALL` để wsdapi đi path mới, gflagsui giữ path cũ (regsvr32+mavinject). Không break Protections Test 4.
- **`register.cpp` không bị xóa**: Vẫn cần cho gflagsui target. wsdapi target đơn giản bỏ nó khỏi source list.
