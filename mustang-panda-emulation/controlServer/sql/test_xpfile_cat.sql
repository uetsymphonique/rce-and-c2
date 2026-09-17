-- Diagnostic: sp_OA string return + OPENROWSET alternative
-- Chạy: sqlcmd -S iis01.testlab.local -U svc_app_dev -P "D3vPortal!2025" -C -i test_xpfile_cat.sql

EXECUTE AS LOGIN='sa';

-- Step 1: Write test file
DECLARE @hr INT, @fso INT, @f INT;
EXEC @hr = sp_OACreate 'Scripting.FileSystemObject', @fso OUT;
PRINT '1a Create FSO hr=0x' + CONVERT(VARCHAR(10), @hr, 1);
EXEC @hr = sp_OAMethod @fso, 'OpenTextFile', @f OUT, 'C:\ProgramData\_test.txt', 2, 1;
PRINT '1b OpenTextFile hr=0x' + CONVERT(VARCHAR(10), @hr, 1) + ' f=' + CAST(ISNULL(@f,0) AS VARCHAR(20));
EXEC @hr = sp_OAMethod @f, 'Write', NULL, 'hello123';
PRINT '1c Write hr=0x' + CONVERT(VARCHAR(10), @hr, 1);
EXEC sp_OAMethod @f, 'Close';
EXEC sp_OADestroy @fso;

-- Step 2: sp_OA reads (expect NULL based on known issue)
DECLARE @s1 INT, @t1 NVARCHAR(MAX), @t2 NVARCHAR(MAX);
EXEC @hr = sp_OACreate 'ADODB.Stream', @s1 OUT;
PRINT '2a Create Stream hr=0x' + CONVERT(VARCHAR(10), @hr, 1) + ' obj=' + CAST(ISNULL(@s1,0) AS VARCHAR(20));
EXEC @hr = sp_OASetProperty @s1, 'Type', 2;
EXEC @hr = sp_OASetProperty @s1, 'Charset', 'ascii';
EXEC @hr = sp_OAMethod @s1, 'Open';
EXEC @hr = sp_OAMethod @s1, 'LoadFromFile', NULL, 'C:\ProgramData\_test.txt';
PRINT '2b LoadFromFile hr=0x' + CONVERT(VARCHAR(10), @hr, 1);
-- Check Size property (INT, not string)
DECLARE @sz BIGINT;
EXEC @hr = sp_OAGetProperty @s1, 'Size', @sz OUT;
PRINT '2c Size hr=0x' + CONVERT(VARCHAR(10), @hr, 1) + ' val=' + CAST(ISNULL(@sz,-1) AS VARCHAR(20));
-- Try ReadText with sp_OAMethod
EXEC @hr = sp_OAMethod @s1, 'ReadText', @t1 OUT, -1;
PRINT '2d sp_OAMethod ReadText hr=0x' + CONVERT(VARCHAR(10), @hr, 1) + ' val=' + ISNULL(@t1,'NULL');
-- Get error info if failed
IF @hr <> 0 EXEC sp_OAGetErrorInfo @s1;
EXEC sp_OAMethod @s1, 'Close';
EXEC sp_OADestroy @s1;

-- Step 3: FSO ReadAll
DECLARE @fso2 INT, @f2 INT, @t3 NVARCHAR(MAX);
EXEC @hr = sp_OACreate 'Scripting.FileSystemObject', @fso2 OUT;
EXEC @hr = sp_OAMethod @fso2, 'OpenTextFile', @f2 OUT, 'C:\ProgramData\_test.txt', 1;
PRINT '3a OpenTextFile hr=0x' + CONVERT(VARCHAR(10), @hr, 1) + ' f=' + CAST(ISNULL(@f2,0) AS VARCHAR(20));
EXEC @hr = sp_OAMethod @f2, 'ReadAll', @t3 OUT;
PRINT '3b FSO ReadAll hr=0x' + CONVERT(VARCHAR(10), @hr, 1) + ' val=' + ISNULL(@t3,'NULL');
IF @hr <> 0 EXEC sp_OAGetErrorInfo @f2;
EXEC sp_OAMethod @f2, 'Close';
EXEC sp_OADestroy @fso2;

-- Step 4: OPENROWSET BULK (native T-SQL, no sp_OA)
PRINT '--- OPENROWSET tests ---';
SELECT 'test_file' AS src, CAST(BulkColumn AS VARCHAR(MAX)) AS content
FROM OPENROWSET(BULK 'C:\ProgramData\_test.txt', SINGLE_CLOB) AS x;

SELECT 'sys_out' AS src, LEFT(CAST(BulkColumn AS VARCHAR(MAX)), 200) AS content
FROM OPENROWSET(BULK 'C:\ProgramData\sys_out.txt', SINGLE_CLOB) AS x;

-- Cleanup
DECLARE @fso3 INT;
EXEC sp_OACreate 'Scripting.FileSystemObject', @fso3 OUT;
EXEC sp_OAMethod @fso3, 'DeleteFile', NULL, 'C:\ProgramData\_test.txt';
EXEC sp_OADestroy @fso3;
PRINT '[+] done';
