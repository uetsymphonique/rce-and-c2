# toneshell_shell.py — Flow

**Entry:** `ToneShellShell.run()` dispatch loop  ·  **Artifact summary:** operator shell that routes C2 tasks to TONESHELL implant on WS01 and, via the XpMssql module, drives xp_cmdshell execution and DB-channel staging on IIS01

Behaviors are grouped by command path in operational order. Artifact classes follow the six-class filter; `[no-artifact]` tags intent-bearing links with no victim-host trace.

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| **— xpinit —** | | | | |
| 1 | operator stores MSSQL host/login/password in XpMssql session state | — [no-artifact] → #2, #3, #8, #13 | — | in-memory only; feeds all subsequent sqlcmd invocations |
| 2 | WS01 implant spawns sqlcmd modifying MSSQL configuration: `sp_OA` + `xp_cmdshell` enabled via `sp_configure` | — [no-artifact] → #3 | — | `sp_configure 'Ole Automation Procedures',1` + `'xp_cmdshell',1`; visible in SQL audit |
| **— xpshell cmd —** | | | | |
| 3 | WS01 implant spawns sqlcmd invoking `sp_OACreate Scripting.FileSystemObject` + `sp_OAMethod OpenTextFile/Write` to write `.bat` to `C:\ProgramData\` on IIS01 | `.bat` file on IIS01 [file] → #4 | — | COM server `Scripting.FileSystemObject`; requires Ole Automation Procedures enabled |
| 4 | WS01 implant spawns sqlcmd invoking `xp_cmdshell` to execute `.bat` on IIS01; bat redirects stdout+stderr to `.txt` | `.txt` output file on IIS01 [file] → #5 | — | `xp_cmdshell` spawns `cmd.exe` as `NT SERVICE\MSSQL$SQLEXPRESS`; output file co-located in `C:\ProgramData\` |
| 5 | WS01 implant spawns sqlcmd invoking `xp_cmdshell 'type <out>.txt'` to read output file on IIS01 | — [no-artifact] | — | result returned to operator via C2 poll |
| 6 | WS01 implant spawns sqlcmd invoking `xp_cmdshell 'del /f <bat> <txt>'` to delete both temp files on IIS01 | — [no-artifact] | — | post-execution cleanup |
| **— xpshell psh —** | | | | |
| 7 | WS01 implant spawns sqlcmd invoking `sp_OACreate Scripting.FileSystemObject` + `sp_OAMethod OpenTextFile/Write` to write `.ps1` to `C:\ProgramData\` on IIS01 | `.ps1` file on IIS01 [file] → #8 | — | same COM/sp_OA mechanism as #3; script staged without PowerShell involvement |
| 8 | WS01 implant spawns sqlcmd invoking `xp_cmdshell 'powershell -ExecutionPolicy Bypass -NoProfile -File <ps1>'` on IIS01 | PowerShell child process on IIS01 [process] | — | `xp_cmdshell` parent; stdout captured inline |
| 9 | WS01 implant spawns sqlcmd invoking `xp_cmdshell 'del /f <ps1>'` to delete script file on IIS01 | — [no-artifact] | — | post-execution cleanup |
| **— xpstage —** | | | | |
| 10 | controlServer reads payload binary and AES-256-CBC encrypts it (IV prepended), writes base64-chunked INSERT SQL to payloads dir | INSERT SQL file in payloads dir [file] → #11 | — | 8000-char NVARCHAR rows; key generated per-staging run |
| 11 | WS01 implant receives `FILE_DOWNLOAD` (id=3) task and downloads INSERT SQL file from C2 server to `C:\Windows\Temp\` | SQL file on WS01 [file] → #12 | — | standard C2 file-push; transfer confirmed via task-poll before next step |
| 12 | WS01 implant spawns `sqlcmd -i <sql>` bulk-inserting base64 payload chunks into `tempdb..stg` on IIS01 | rows in `tempdb..stg` [no-artifact] → #13 | — | no file on IIS01 disk; observable via SQL audit on INSERT into tempdb |
| 13 | IIS01 PowerShell (via `xp_cmdshell`) opens SqlClient connection to `tempdb`, reads + concatenates all `stg` rows, AES-256-CBC decrypts, writes binary to `C:\ProgramData\<name>` | payload binary on IIS01 [file] | — | SqlClient loopback from IIS01 to `IIS01\SQLEXPRESS`; payload lands in `C:\ProgramData\` |
| 14 | WS01 implant deletes INSERT SQL file from `C:\Windows\Temp\` via `cmd /c del /f` | — [no-artifact] | — | post-stage cleanup on WS01 |
| 15 | WS01 implant spawns sqlcmd invoking `DROP TABLE tempdb..stg` on IIS01 | — [no-artifact] | — | staging table removed; no DB artifact remains |
| **— session management —** | | | | |
| 16 | operator sends `FILE_UPLOAD` (id=7) task; WS01 implant pushes file from local path to C2 server `files/` dir | file in C2 files dir [file] | — | exfiltration primitive |
| 17 | operator sends `FILE_DOWNLOAD` (id=3) task; WS01 implant downloads file from C2 `payloads/` dir to local path | file on WS01 [file] | — | tool-transfer primitive |
| 18 | operator sends `EXEC` (id=5) task; WS01 implant executes shell command via `CreateProcessW`, returns output | — [no-artifact] | — | no cmd.exe shell wrapper; output returned via C2 poll |
| 19 | operator sends `TERMINATE` (id=255) task; WS01 implant self-destructs | — [no-artifact] | — | no further C2 beacons after receipt |
