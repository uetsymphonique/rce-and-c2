# TONESHELL — Build

**Toolchain:** CMake ≥ 3.26 + Ninja Multi-Config generator + MSVC + MASM (Visual Studio Build Tools). MASM is required for `syscalls.asm` (direct-syscall stubs). See `CMakePresets.json` for the pinned configure preset.

## Prerequisites

- CMake ≥ 3.26 with `CMakePresets.json` version 6 support (Visual Studio 17.7+ or standalone CMake 3.26+).
- MSVC toolchain (Visual Studio 2022 Build Tools) invoked from a Developer Command Prompt so `cl.exe`, `link.exe`, `ninja` are on `PATH`.
- 7-Zip at `C:\Program Files\7-Zip\7z.exe` (used to build the `250325_Pentos_Board_Minutes.zip` payload archive).
- PowerShell (for `sign_artifact.ps1` and `embed_payload.ps1` post-build hooks).
- Vulnerable legitimate binaries staged at the toneshell/ root before building:
  - `EssosUpdate.exe` — renamed [`wsddebug_host.exe`](https://learn.microsoft.com/en-us/windows/win32/wsdapi/debugging-tools) (Windows SDK / WDK). 2025 evaluations used `10.0.22621.0` build with SHA256 `3DC7F38CB68FA316205BEC35AFEF875DC0A748030D4005A491BB6FE350E6F8B2`.
  - `gflags.exe` — [Global Flags Editor](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags) from Debugging Tools for Windows. 2025 evaluations used SHA256 `8A5DD351E4A1FB5CCE2816D17FA7130240938735B5AB5F0C7C67996D687557DA`. **Only required for the Protections Test 4 build**; skip if you use the TONESHELL-only preset below.

## Third-party dependencies (auto-fetched)

Fetched at configure time via `FetchContent` into `external/`:

- [assemblyline](https://github.com/robleh/assemblyline) — pinned to commit `1e7e7bbcbf8a340250bd3aaf6f8f06a645fca495`. Used to build position-independent shellcode.
- [googletest](https://github.com/google/googletest) — pinned to commit `03597a01ee50ed33e9dfd640b249b4be3799d395`. Unit tests only.

## Build knobs (CMake cache variables)

Set in `CMakePresets.json` (`configurePresets[0].cacheVariables`) or overridden with `-D<NAME>=<VALUE>` at configure time. Only the TONESHELL-side targets read these — the Protections Test 4 shellcode still uses its upstream hardcoded values.

| Variable | Default | Purpose |
|---|---|---|
| `TONESHELL_LOG_DIR` | `C:/Windows/Temp` | Directory the shellcode + DLL runtime logs (`wsdapih.log`, `wsdapisr.log`, `wsdapi_dat.log`) get written to. Default is user-writable so the LNK chain runs without admin. |
| `TONESHELL_C2_HOST` | `192.168.56.2` | C2 server host/IP baked into the shellcode. |
| `TONESHELL_C2_PORT` | `8443` | C2 server TCP port baked into the shellcode. |
| `TONESHELL_JITTER_ACTIVE_MIN_MS` | `1000` | Min jitter (ms) after a real task completes — burst mode. |
| `TONESHELL_JITTER_ACTIVE_MAX_MS` | `3000` | Max jitter (ms) after a real task completes. |
| `TONESHELL_JITTER_IDLE_MIN_MS` | `5000` | Min jitter (ms) on idle beacon (no tasking). |
| `TONESHELL_JITTER_IDLE_MAX_MS` | `30000` | Max jitter (ms) on idle beacon. |
| `TONESHELL_MAGIC_0` | `0xC7` | C2 protocol magic byte 0 (header signature). |
| `TONESHELL_MAGIC_1` | `0x3A` | C2 protocol magic byte 1. |
| `TONESHELL_MAGIC_2` | `0x1F` | C2 protocol magic byte 2. |

### Compile definitions (not cache variables)

| Define | Set in | Purpose |
|---|---|---|
| `TONESHELL_DIRECT_SYSCALL` | `src/wsdapi/CMakeLists.txt` | Enables direct-syscall injection path (Halos Gate + shared section + Early Bird APC). When not defined, falls back to legacy regsvr32 + mavinject path. Always defined for the `wsdapi` target. |

### Sources that consume them

- `src/wsdapi/CMakeLists.txt` — `TONESHELL_LOG_DIR` for `DLL_HANDLER_LOG_FILE` / `DLL_SH_RUNNER_LOG_FILE`.
- `src/shellcode/CMakeLists.txt` — `TONESHELL_LOG_DIR`, `TONESHELL_C2_HOST`, `TONESHELL_C2_PORT` for `SERVER` / `PORT` / `SH_LOG_FILE`; jitter and magic variables for the `shellcode-pe` target. The `test4shellcode-pe` target intentionally keeps upstream hardcoded values.
- `src/CMakeLists.txt` — `TONESHELL_MAGIC_0/1/2` for the DLL handler (shared between wsdapi and gflagsui).

## Workflow presets

Defined in `CMakePresets.json` under `workflowPresets`:

| Workflow | Configure → Build → Test | Notes |
|---|---|---|
| `cicd-release` | `default` → `release` → `release` | Full build: TONESHELL + Protections Test 4. Requires `gflags.exe` staged. |
| `cicd-debug` | `default` → `debug` → `debug` | Same targets, Debug config. |
| `cicd-release-toneshell` | `default` → `release-toneshell` → `release` | **TONESHELL-only** (targets: `shellcode`, `wsdapi`, `toneshell-test`). Skips `test4`, `gflagsui`, `test4shellcode` — `gflags.exe` not required. |

## Build commands

Run from `resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell/`.

### TONESHELL-only (recommended for detection emulation)

```powershell
cmake.exe --workflow --preset cicd-release-toneshell
```

### Full build (TONESHELL + Protections Test 4)

Only if you need the Test 4 dropper — requires `gflags.exe` staged in the toneshell/ root.

```powershell
cmake.exe --workflow --preset cicd-release
# Debug variant
cmake.exe --workflow --preset cicd-debug
```

### Override knobs at configure time

If you need to point at a different C2 or log dir without editing `CMakePresets.json`, override during configure (workflow presets skip separate configure steps, so use two-step build instead):

```powershell
cmake.exe --preset default -DTONESHELL_C2_HOST=10.0.0.5 -DTONESHELL_C2_PORT=443 -DTONESHELL_LOG_DIR=C:/Users/Public
cmake.exe --build build --preset release-toneshell
```

## Install

The upstream `install()` rules in root `CMakeLists.txt` reference both TONESHELL and Test 4 targets. If you built with `cicd-release-toneshell` (Test 4 targets skipped), `cmake --install` will fail on the missing Test 4 binaries.

### After `cicd-release-toneshell` — copy the deliverable manually

Only `250325_Pentos_Board_Minutes.zip` is needed to deploy to the victim:

```powershell
$src = "build/src/wsdapi/Release"
$dst = "install/Release"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item "$src/250325_Pentos_Board_Minutes.zip" -Destination $dst
Copy-Item "$src/toneshell.pfx"                   -Destination $dst
Copy-Item "$src/wsdapi.dll"                      -Destination $dst
```

### After full `cicd-release` — use CMake install

```powershell
cmake.exe --install ./build --config Release
cmake.exe --install ./build --config Debug
```

## Output artifacts

Relative to `build/` after a release build:

| Artifact | Path | Notes |
|---|---|---|
| Malicious DLL | `src/wsdapi/Release/wsdapi.dll` | Self-signed (`Tully Enterprises`) via `sign_artifact.ps1` post-build. |
| Payload archive | `src/wsdapi/Release/250325_Pentos_Board_Minutes.zip` | Contains `wsdapi.dll`, `EssosUpdate.exe`, `Essos Competitiveness Brief.lnk`. Password `Pentos`. **This is what gets deployed to the victim.** |
| Signing cert | `src/wsdapi/Release/toneshell.pfx` | Exported PFX (password `Pentos`). |
| Raw shellcode | `src/shellcode/Release/shellcode.bin` | Embedded into `wsdapi.dll` at build time via `embed_payload.ps1`; usually not needed standalone. |
| Embed header | `src/wsdapi/embedded.hpp` | Generated in source tree — encrypted shellcode + wrapped XOR key. Regenerated each build. |
| Unit test binary | `tests/gtest/Release/toneshell-test.exe` | 30 GoogleTest cases, invoked by the `test` step of the workflow preset. |

Test 4 artifacts (only produced by `cicd-release`): `gflagsui.dll`, `test4.exe`, `test4shellcode.bin`, `protections4.zip` — all under `build/src/test4/**/Release/`.

## Verifying build

The workflow preset runs `ctest` at the end; a green build reports `100% tests passed, 0 tests failed out of 30`. If `toneshell-test.exe` fails, the workflow returns non-zero and the archive should not be trusted.
