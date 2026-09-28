# controlShell — Flow

**Entry:** `ToneShellShell.run()` dispatch loop  ·  **Artifact summary:** operator shell that routes C2 tasks to TONESHELL implant on WS01 and, via the XpMssql module, drives six lateral channels on IIS01: xpshell (cmd/psh, deprecated), xpstage-aes/hex (binary staging), xpexfil-aes/hex (exfil), xpagent (Service Broker in-DB async), xprun/xprun-out (sp_OA direct PE exec), and xpfile (T-SQL file ops)

Behaviors are grouped by command path in operational order. Row numbers are sequential across all tables. Artifact classes follow the six-class filter; `[no-artifact]` tags intent-bearing links with no victim-host trace.

---

## xpinit

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1 | operator stores MSSQL host/login/password (+ optional staged sqlcmd exec path) in XpMssql session state | - [no-artifact] -> #3, #5, #10, #16 | - | in-memory only; feeds all tunnel sqlcmd invocations; staged go-sqlcmd path overrides host's installed sqlcmd |
| 2 | operator stages go-sqlcmd binary on WS01 via `put` (FILE_DOWNLOAD id=3) and passes its full path to `xpinit` | go-sqlcmd binary on WS01 [file] -> #3 | Command and Control / T1105 - Ingress Tool Transfer | binary built from `../../../go-sqlcmd/`; replaces the host's installed `sqlcmd` so the string `sqlcmd` does not appear in any tunnel command line |
| 3 | WS01 implant spawns sqlcmd modifying MSSQL configuration: `sp_OA` + `xp_cmdshell` enabled via `sp_configure`; `ADMINISTER BULK OPERATIONS` granted to `svc_app_dev` login | - [no-artifact] -> #5, #10, #16, #23, #31, #47, #62, #65 | Persistence / T1505.001 - Server Software Component: SQL Stored Procedures | `sp_configure 'Ole Automation Procedures',1` + `'xp_cmdshell',1` + GRANT in one batch; visible in SQL audit |
| 4 | WS01 implant spawns sqlcmd querying `SELECT @@SERVERNAME` + `sys.dm_server_services WHERE servicename LIKE 'SQL Server%'` on IIS01 | - [no-artifact] | Discovery / T1082 - System Information Discovery / Discovery / T1007 - System Service Discovery | enumerates server name and SQL service account (`service_account` column) — SQL-equivalent of `sc query`; printed to operator as xpinit connectivity confirmation |

---

## xpshell cmd (deprecated)

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 5 | WS01 implant spawns sqlcmd invoking `sp_OACreate Scripting.FileSystemObject` + `sp_OAMethod OpenTextFile/Write` to write `.bat` to `C:\ProgramData\` on IIS01 | `.bat` file on IIS01 [file] -> #6 | Execution / T1559.001 - Inter-Process Communication: Component Object Model | COM server `Scripting.FileSystemObject`; requires Ole Automation Procedures enabled |
| 6 | WS01 implant spawns sqlcmd invoking `xp_cmdshell` to execute `.bat` on IIS01; bat redirects stdout+stderr to `.txt` | `.txt` output file on IIS01 [file] -> #7 | Execution / T1059.003 - Command and Scripting Interpreter: Windows Command Shell | `xp_cmdshell` spawns `cmd.exe` as `NT SERVICE\MSSQL$SQLEXPRESS`; output file co-located in `C:\ProgramData\` |
| 7 | WS01 implant spawns sqlcmd invoking `xp_cmdshell 'type <out>.txt'` to read output file on IIS01 | - [no-artifact] | Collection / T1005 - Data from Local System | result returned to operator via C2 poll |
| 8 | WS01 implant spawns sqlcmd invoking `xp_cmdshell 'del /f <bat> <txt>'` to delete both temp files on IIS01 | deleted `.bat`/`.txt` on IIS01 [file] | Stealth / T1070.004 - Indicator Removal: File Deletion | post-execution cleanup |

---

## xpshell psh (deprecated)

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 9 | WS01 implant spawns sqlcmd invoking `sp_OACreate Scripting.FileSystemObject` + `sp_OAMethod OpenTextFile/Write` to write `.ps1` to `C:\ProgramData\` on IIS01 | `.ps1` file on IIS01 [file] -> #10 | Execution / T1559.001 - Inter-Process Communication: Component Object Model | same COM/sp_OA mechanism as #5; script staged without PowerShell involvement |
| 10 | WS01 implant spawns sqlcmd invoking `xp_cmdshell 'powershell -ExecutionPolicy Bypass -NoProfile -File <ps1>'` on IIS01 | PowerShell child process on IIS01 [process] | Execution / T1059.001 - Command and Scripting Interpreter: PowerShell | `xp_cmdshell` parent; stdout captured inline |
| 11 | WS01 implant spawns sqlcmd invoking `xp_cmdshell 'del /f <ps1>'` to delete script file on IIS01 | deleted `.ps1` on IIS01 [file] | Stealth / T1070.004 - Indicator Removal: File Deletion | post-execution cleanup |

---

## xpstage-aes (deprecated)

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 12 | controlServer reads payload binary and AES-256-CBC encrypts it (IV prepended), writes base64-chunked INSERT SQL to payloads dir | INSERT SQL file in payloads dir [file] -> #13 | - | 8000-char NVARCHAR rows; key generated per-staging run |
| 13 | WS01 implant receives `FILE_DOWNLOAD` (id=3) task and downloads INSERT SQL file from C2 server to `C:\Windows\Temp\` | SQL file on WS01 [file] -> #14 | Command and Control / T1105 - Ingress Tool Transfer | standard C2 file-push; transfer confirmed via task-poll before next step |
| 14 | WS01 implant spawns `sqlcmd -i <sql>` bulk-inserting base64 payload chunks into `tempdb..stg` on IIS01 | rows in `tempdb..stg` [no-artifact] -> #16 | Lateral Movement / T1570 - Lateral Tool Transfer | no file on IIS01 disk; observable via SQL audit on INSERT into tempdb |
| 15 | WS01 implant stages decode PowerShell script to `C:\ProgramData\` via sp_OA FSO `OpenTextFile/Write` | `.ps1` file on IIS01 [file] -> #16 | Execution / T1559.001 - Inter-Process Communication: Component Object Model | same sp_OA FSO staging as #9 (cmd_xpshell_psh); script written without PowerShell involvement |
| 16 | IIS01 PowerShell (via `xp_cmdshell`) opens SqlClient to `tempdb`, reads + concatenates all `stg` rows, AES-256-CBC decrypts, writes binary to `C:\ProgramData\<name>` | payload binary on IIS01 [file] | Stealth / T1140 - Deobfuscate/Decode Files or Information / Command and Control / T1105 - Ingress Tool Transfer | SqlClient loopback from IIS01 to `IIS01\SQLEXPRESS`; payload lands in `C:\ProgramData\` |
| 17 | WS01 implant deletes decode `.ps1` from `C:\ProgramData\` via `xp_cmdshell 'del /f'` | deleted `.ps1` on IIS01 [file] | Stealth / T1070.004 - Indicator Removal: File Deletion | post-run cleanup; same mechanism as #11 |
| 18 | WS01 implant deletes INSERT SQL file from `C:\Windows\Temp\` via `cmd /c del /f` | deleted SQL file on WS01 [file] | Stealth / T1070.004 - Indicator Removal: File Deletion | post-stage cleanup on WS01 |
| 19 | WS01 implant spawns sqlcmd invoking `DROP TABLE tempdb..stg` on IIS01 | - [no-artifact] | Stealth / T1070 - Indicator Removal | staging table removed; no DB artifact remains |

---

## xpstage-hex

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 20 | controlServer generates hex INSERT SQL file via `POST /api/v1.0/mssql/stage {format: hex}`; server hex-encodes payload binary and writes 8000-char hex INSERT rows | INSERT SQL file in C2 payloads dir [file] -> #21 | - | ~2 chars per byte; no encryption; contrast with #12 (AES+base64); larger SQL file but no process spawn on IIS01 for decode |
| 21 | WS01 implant receives `FILE_DOWNLOAD` (id=3), downloads hex INSERT SQL to `C:\Windows\Temp\` as `<stage_*.stl>` | SQL file on WS01 [file] -> #22 | Command and Control / T1105 - Ingress Tool Transfer | same C2 file-push mechanism as #13, #27; SQL staged with benign `.stl` extension (masquerade) |
| 22 | WS01 implant spawns `sqlcmd -i <sql>` bulk-inserting hex payload rows into `tempdb..stg` on IIS01 | rows in `tempdb..stg` [no-artifact] -> #23 | Lateral Movement / T1570 - Lateral Tool Transfer | no file on IIS01 disk; rows hold VARCHAR(8000) hex chunks; observable via SQL audit on INSERT into tempdb |
| 23 | WS01 implant spawns sqlcmd T-SQL decode batch: concat hex from `tempdb..stg`, `CONVERT(VARBINARY(MAX),'0x'+@hex,1)`, ADODB.Stream `Write` + `SaveToFile` to `C:\ProgramData\<stem>.stl`; `--rename` appends FSO `MoveFile` to original name | payload binary on IIS01 [file] | Stealth / T1140 - Deobfuscate/Decode Files or Information / Execution / T1559.001 - Inter-Process Communication: Component Object Model | T-SQL `CONVERT` decodes hex in-process inside `sqlservr.exe` via sp_OA COM; default keeps `<stem>.stl` at rest (`--rename` opt-in); no cmd.exe or PowerShell spawn on IIS01 |
| 24 | WS01 implant EXEC `cmd /c del /f <sql>` deletes hex INSERT SQL file from `C:\Windows\Temp\` | deleted SQL file on WS01 [file] | Stealth / T1070.004 - Indicator Removal: File Deletion | post-stage cleanup on WS01 |
| 25 | WS01 implant spawns sqlcmd invoking `DROP TABLE tempdb..stg` on IIS01 | - [no-artifact] | Stealth / T1070 - Indicator Removal | staging table removed; no DB artifact remains |

---

## session management

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 26 | operator sends `FILE_UPLOAD` (id=7) task; WS01 implant pushes file from local path to C2 server `files/` dir | file in C2 files dir [file] | Exfiltration / T1041 - Exfiltration Over C2 Channel | exfiltration primitive |
| 27 | operator sends `FILE_DOWNLOAD` (id=3) task; WS01 implant downloads file from C2 `payloads/` dir to local path | file on WS01 [file] | Command and Control / T1105 - Ingress Tool Transfer | tool-transfer primitive |
| 28 | operator sends `EXEC` (id=5) task; WS01 implant executes shell command via `CreateProcessW`, returns output | child process on WS01 [process] | Execution / T1106 - Native API | no cmd.exe shell wrapper; output returned via C2 poll |
| 29 | operator sends `TERMINATE` (id=255) task; WS01 implant self-destructs | - [no-artifact] | - | no further C2 beacons after receipt |

---

## xpexfil-aes (deprecated)

### xpexfil-aes - setup

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 30 | controlServer generates AES-256-CBC key via `os.urandom(32)`, base64-encodes in Python process memory | - [no-artifact] -> #33, #40 | - | key never touches victim host; single key reused across all chunks for the call |
| 31 | WS01 implant spawns sqlcmd invoking `SELECT DATALENGTH(BulkColumn) FROM OPENROWSET(BULK '<path>', SINGLE_BLOB) AS x` against IIS01; Python computes `num_chunks = ceil(size / chunk_mb x 1024^2)` | - [no-artifact] | Discovery / T1083 - File and Directory Discovery | shared file-size helper; measures file size to shape chunking; OPENROWSET requires `ADMINISTER BULK OPERATIONS` (granted by xpinit); no process spawn on IIS01 |

### xpexfil-aes - per-chunk loop (×num_chunks)

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 32 | WS01 implant stages per-chunk exfil PowerShell script to `C:\ProgramData\` via sp_OA FSO `OpenTextFile/Write` | `.ps1` file on IIS01 [file] -> #33 | Execution / T1559.001 - Inter-Process Communication: Component Object Model | same sp_OA FSO staging as #9 (cmd_xpshell_psh); one `.ps1` per chunk |
| 33 | IIS01 PowerShell opens target file via `[IO.File]::OpenRead`, calls `FileStream.Seek(offset)` + `Read(length)` to read only chunk bytes, then AES-256-CBC encrypts with random IV prepended to ciphertext | encrypted blob in IIS01 memory [memory] -> #34 | Collection / T1005 - Data from Local System / Collection / T1560.003 - Archive Collected Data: Archive via Custom Method | PowerShell spawned by xp_cmdshell as `NT SERVICE\MSSQL$SQLEXPRESS`; only the chunk window is read; no plaintext file written |
| 34 | IIS01 PowerShell base64-encodes encrypted blob via `ToBase64Transform` CryptoStream into MemoryStream | MIME base64 string in IIS01 memory [memory] -> #35 | Stealth / T1027.013 - Obfuscated Files or Information: Encrypted/Encoded File | `ToBase64Transform` emits CRLF every 72 chars; no file artifact |
| 35 | IIS01 PowerShell INSERTs base64 string as 8000-char NVARCHAR(MAX) chunks into `tempdb..exfil` via SqlClient loopback | rows in `tempdb..exfil` [no-artifact] -> #38 | Collection / T1074.002 - Data Staged: Remote Data Staging | `GRANT SELECT ON exfil TO PUBLIC`; SqlClient loopback `IIS01\SQLEXPRESS`; observable via SQL audit |
| 36 | WS01 implant deletes exfil `.ps1` from `C:\ProgramData\` via `xp_cmdshell 'del /f'` | deleted `.ps1` on IIS01 [file] | Stealth / T1070.004 - Indicator Removal: File Deletion | post-run cleanup; same mechanism as #11; one per chunk |
| 37 | Python operator shell polls `OBJECT_ID('tempdb..exfil','U')` via sqlcmd every 15 s until row exists, up to `insert_timeout_s` | - [no-artifact] | - | safety wait - guards against slow INSERT before extract runs |
| 38 | WS01 PowerShell reads `tempdb..exfil` rows via SqlClient from `IIS01\SQLEXPRESS` and concatenates into StringBuilder | concatenated base64 string in WS01 memory [memory] -> #39 | Collection / T1005 - Data from Local System | `SELECT chunk ... ORDER BY id`; cross-host SqlClient from WS01 to IIS01; reads back staged data |
| 39 | WS01 PowerShell decodes base64 via `FromBase64Transform` CryptoStream to recover raw ciphertext bytes | ciphertext bytes in WS01 MemoryStream [memory] -> #40 | Stealth / T1140 - Deobfuscate/Decode Files or Information | `FromBase64Transform` defaults `IgnoreWhiteSpaces`; handles MIME CRLF from #34 |
| 40 | WS01 PowerShell AES-256-CBC decrypts ciphertext (IV from `blob[0..15]`) and writes plaintext chunk to `C:\Windows\Temp\<local_name>.chunk{i}` via `[IO.File]::WriteAllBytes` | plaintext chunk file on WS01 [file] -> #41 | Collection / T1074.001 - Data Staged: Local Data Staging | each chunk is a separate file; lives only until FILE_UPLOAD completes |
| 41 | WS01 implant sends `FILE_UPLOAD` (id=7) task with `fileName=<local_name>.chunk{i}` to push chunk file to controlServer `files/<local_name>.chunk{i}`; operator shell blocks on `_poll_output(timeout_s=180)` until `TASK_STATUS_FINISHED` | chunk file in C2 `files/` dir [file] -> #44 | Exfiltration / T1041 - Exfiltration Over C2 Channel | per-chunk blocking pull; explicit `fileName` prevents Go server from generating a random name |
| 42 | WS01 implant deletes `C:\Windows\Temp\<local_name>.chunk{i}` via `cmd /c del /f` | deleted chunk file on WS01 [file] | Stealth / T1070.004 - Indicator Removal: File Deletion | post-pull cleanup; runs only after FILE_UPLOAD task confirmed FINISHED |
| 43 | WS01 implant spawns sqlcmd invoking `DROP TABLE tempdb..exfil` on IIS01 | - [no-artifact] | Stealth / T1070 - Indicator Removal | per-chunk drop after extract+pull+delete; `tempdb..exfil` must not exist when next chunk begins |

### xpexfil-aes - reassembly

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 44 | Python operator shell reads `files/<local_name>.chunk0` ... `files/<local_name>.chunk{N-1}` in order, streams each into `files/<local_name>` via 1 MB read loop, then deletes each chunk file | assembled plaintext file in C2 `files/` dir [file] | - | local file-system operation on C2 host; no network I/O; chunk files removed after concatenation |

---

## xpexfil-hex

### xpexfil-hex - setup

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 45 | WS01 implant spawns sqlcmd invoking `SELECT DATALENGTH(BulkColumn) FROM OPENROWSET(BULK '<path>', SINGLE_BLOB) AS x` against IIS01; Python computes `num_chunks = ceil(size / chunk_mb x 1024^2)` | - [no-artifact] | Discovery / T1083 - File and Directory Discovery | same shared `_get_remote_file_size` helper as #31; measures file size to shape chunking; no process spawn on IIS01 |
| 46 | WS01 implant spawns sqlcmd invoking `EXECUTE AS LOGIN='sa'; GRANT ADMINISTER BULK OPERATIONS TO [<login>]` on IIS01 | - [no-artifact] -> #47 | Privilege Escalation / T1098 - Account Manipulation | grants server-level permission to `svc_app_dev` via sa impersonation; expands login's effective privilege set; persists until revoked |
| 47 | WS01 implant spawns sqlcmd with single T-SQL batch: `OPENROWSET(BULK)` reads file into `@data VARBINARY(MAX)`, WHILE loop slices via `SUBSTRING`, hex-encodes each window, INSERTs 8000-char rows into `tempdb..exfil` | rows in `tempdb..exfil` [no-artifact] -> #48 | Lateral Movement / T1570 - Lateral Tool Transfer / Collection / T1005 - Data from Local System | single T-SQL batch; OPENROWSET bulk-reads target file into SQL memory under `ADMINISTER BULK OPERATIONS`; no process spawn on IIS01; SELECT returns (num_chunks, file_bytes, total_rows) |

### xpexfil-hex - per-chunk loop (×num_chunks)

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 48 | WS01 PowerShell (via `cmd_exec_raw`) uses SqlClient to `SELECT chunk FROM tempdb..exfil WHERE chunk_idx=i ORDER BY id`, concatenates rows into StringBuilder, writes raw hex text to `C:\Windows\Temp\<local_name>.hex{i}` via `[IO.File]::WriteAllText` | hex text file on WS01 [file] -> #49 | Collection / T1074.001 - Data Staged: Local Data Staging | PowerShell on WS01, not IIS01; no process spawn on IIS01; hex text file exists only until FILE_UPLOAD completes |
| 49 | WS01 implant sends `FILE_UPLOAD` (id=7) task to push `C:\Windows\Temp\<local_name>.hex{i}` to controlServer `files/<local_name>.hex{i}`; operator shell blocks on `_poll_output` until FINISHED | hex chunk file in C2 `files/` dir [file] -> #52 | Exfiltration / T1041 - Exfiltration Over C2 Channel | explicit `fileName` parameter prevents server from generating random name |
| 50 | WS01 implant deletes `C:\Windows\Temp\<local_name>.hex{i}` via `cmd /c del /f` | deleted hex chunk file on WS01 [file] | Stealth / T1070.004 - Indicator Removal: File Deletion | file deletion on WS01; runs after FILE_UPLOAD confirmed FINISHED |

### xpexfil-hex - reassembly

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 51 | WS01 implant spawns sqlcmd invoking `DROP TABLE tempdb..exfil` on IIS01 after all chunks extracted | - [no-artifact] | Stealth / T1070 - Indicator Removal | single post-loop `DROP TABLE tempdb..exfil` (unlike xpexfil-aes per-chunk drop #43); no sub-technique covers database object removal |
| 52 | Python operator shell reads `files/<local_name>.hex0` ... `files/<local_name>.hex{N-1}` in order; each hex string decoded via `bytes.fromhex()` and streamed into `files/<local_name>`; hex files deleted after concatenation | assembled binary file in C2 `files/` dir [file] | - | local C2 file-system operation; no network I/O; hex files removed after reassembly |

---

## xpagent init

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 53 | C2 operator copies `xpagent_init.sql` from `controlServer/sql/` to `payloads/` on C2 host via `shutil.copy2` | SQL file in C2 payloads dir [file] -> #54 | - | local C2 file-system op; source is the DDL script for all xpagent DB objects |
| 54 | WS01 implant receives `FILE_DOWNLOAD` (id=3) and downloads `xpagent_init.sql` from C2 payloads dir to `C:\Windows\Temp\xpagent_init.stl` | SQL file on WS01 [file] -> #55 | Command and Control / T1105 - Ingress Tool Transfer | same C2 file-push mechanism as #13 and #27; staged with benign `.stl` extension (masquerade) |
| 55 | WS01 implant runs `sqlcmd -i C:\Windows\Temp\xpagent_init.stl` executing DDL against `IIS01\SQLEXPRESS`: creates `xpagent` database, `dbo.cmd`/`dbo.out` tables, AFTER INSERT trigger, Service Broker queue/service, activation proc `agent_worker` | DB schema objects in `xpagent` database [no-artifact] -> #57, #58, #60, #61 | Persistence / T1505.001 - Server Software Component: SQL Stored Procedures / Persistence / T1546 - Event Triggered Execution | `agent_worker` activated via Service Broker events; trigger fires on every operator command INSERT; persists through SQL restarts, removed only by `xpagent kill` (#61) |
| 56 | WS01 implant deletes `C:\Windows\Temp\xpagent_init.stl` via `cmd /c del /f` | deleted `.stl` on WS01 [file] | Stealth / T1070.004 - Indicator Removal: File Deletion | post-init cleanup on WS01 |

---

## xpexec / xpexec-bg

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 57 | WS01 implant runs `sqlcmd -Q "INSERT INTO xpagent.dbo.cmd(cmd) VALUES(...)"` inserting operator command text; AFTER INSERT trigger fires `BEGIN DIALOG CONVERSATION ... SEND` enqueuing a Service Broker message | row in `xpagent.dbo.cmd` + SB message queued [no-artifact] -> #58 | - | `xpexec-bg` stops here and returns cmd_id; `xpexec` continues to #59; SB conversation is self-dialog within `xpagent` DB |
| 58 | IIS01 SQL Server Service Broker activates `agent_worker` proc (EXECUTE AS OWNER = sa); proc RECEIVEs message, parses `cmd_id\|command` body, calls `xp_cmdshell @cmd` (variable), INSERTs stdout rows into `xpagent.dbo.out`, UPDATEs `dbo.cmd.status` to 2/3, calls `END CONVERSATION` | output rows in `xpagent.dbo.out` + status=2 in `dbo.cmd` [no-artifact] -> #59, #60 | Execution / T1059.003 - Command and Scripting Interpreter: Windows Command Shell | `agent_worker` calls `xp_cmdshell @cmd` spawning `cmd.exe` as `NT SERVICE\MSSQL$SQLEXPRESS`; autonomous in-DB execution |
| 59 | WS01 implant runs `sqlcmd -Q "SELECT status FROM xpagent.dbo.cmd WHERE id=<cmd_id>"` every 2 s until status=2 or status=3; operator shell blocks on `_exec_q` poll loop | - [no-artifact] -> #60 | - | polling equivalent of task-status poll on C2 API; driven by operator shell timer |
| 60 | WS01 implant runs `sqlcmd -Q "SELECT chunk FROM xpagent.dbo.out WHERE cmd_id=<cmd_id> ORDER BY seq"` to retrieve command output | - [no-artifact] | Collection / T1005 - Data from Local System | reads command output stored by `agent_worker` in `xpagent.dbo.out`; output printed to operator |

---

## xpagent kill

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 61 | WS01 implant runs sqlcmd with `USE master; IF EXISTS (SELECT 1 FROM sys.databases WHERE name=N'xpagent') BEGIN ALTER DATABASE xpagent SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE xpagent; END` on IIS01 | - [no-artifact] | Stealth / T1070.009 - Indicator Removal: Clear Persistence | drops the entire `xpagent` database and all persistent objects from #55 (stored proc, trigger, SB queue/service, tables); DDL DROP events visible in SQL Audit |

---

## xpfile

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 62 | operator invokes `xpfile exists <path>`; WS01 implant spawns sqlcmd invoking `EXEC master.dbo.xp_fileexist '<path>'` on IIS01 | - [no-artifact] | Collection / T1005 - Data from Local System | returns (file_exists, file_is_a_directory, parent_directory_exists) columns; no process spawn on IIS01 |
| 63 | operator invokes `xpfile del <path>`; WS01 implant spawns sqlcmd invoking `sp_OACreate 'Scripting.FileSystemObject'` + `sp_OAMethod 'DeleteFile'` on IIS01 | deleted target file on IIS01 [file] | Stealth / T1070.004 - Indicator Removal: File Deletion | COM in-process via sp_OA; returns `deleted` or `error: hr=<code>`; no cmd.exe or process spawn on IIS01 |
| 64 | operator invokes `xpfile cat <path>`; WS01 implant spawns sqlcmd invoking `SELECT CAST(BulkColumn AS NVARCHAR(MAX)) FROM OPENROWSET(BULK '<path>', SINGLE_CLOB) AS x` on IIS01 | - [no-artifact] | Collection / T1005 - Data from Local System | T-SQL in-process read via OPENROWSET; no process spawn on IIS01; requires `ADMINISTER BULK OPERATIONS` (granted by xpinit) |
| 65 | operator invokes `xpfile ls <path>`; WS01 implant spawns sqlcmd invoking `EXEC master.dbo.xp_dirtree '<path>',1,1` on IIS01 | - [no-artifact] | Discovery / T1083 - File and Directory Discovery | returns subdirectory/file names with depth and file flag; no process spawn on IIS01 |

---

## xprun / xprun-out

| # | Behavior (`actor action artifact`) | Artifact [class] -> consumed by | Tactic / TID - Technique Name | Context (baseline) |
|---|---|---|---|---|
| 66 | WS01 implant spawns sqlcmd: `sp_OACreate 'WScript.Shell'` + `sp_OAMethod 'Run'` (bWaitOnReturn=1) on IIS01; Shell.Run calls ShellExecuteEx to launch target PE | target.exe process on IIS01 [process] | Execution / T1559.001 - Inter-Process Communication: Component Object Model | `WScript.Shell` is a COM server; sp_OA invokes it in-process inside sqlservr.exe; process chain `sqlservr.exe -> target.exe`; no cmd.exe spawn |
| 67 | WS01 implant spawns sqlcmd: sp_OA WScript.Shell.Run with `-o <rand.txt>` injected; PE writes stdout to temp file on IIS01 | target.exe process on IIS01 [process]; output file on IIS01 [file] -> #68, #69 | Execution / T1559.001 - Inter-Process Communication: Component Object Model | same WScript.Shell COM mechanism as #66; target must support `-o <file>` flag for stdout redirect |
| 68 | WS01 implant spawns sqlcmd: `SELECT CAST(BulkColumn AS NVARCHAR(MAX)) FROM OPENROWSET(BULK '<rand.txt>', SINGLE_CLOB)` on IIS01 reads PE stdout back to operator | - [no-artifact] | Collection / T1005 - Data from Local System | same OPENROWSET mechanism as #64 (xpfile cat); reads output file from #67 on IIS01's local disk; no process spawn |
| 69 | WS01 implant spawns sqlcmd: `sp_OACreate 'Scripting.FileSystemObject'` + `sp_OAMethod 'DeleteFile'` on IIS01 deletes temp output file | deleted temp output file on IIS01 [file] | Stealth / T1070.004 - Indicator Removal: File Deletion | same sp_OA FSO mechanism as #63 (xpfile del); cleanup of file from #67 |
