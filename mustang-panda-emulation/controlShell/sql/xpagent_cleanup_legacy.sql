-- xpagent_cleanup_legacy.sql
-- Dọn artifact từ các lần thử failed (tempdb cert, master cert login, tempdb SB/tables/proc).
-- Chạy một lần sau khi xpagent_init.sql thành công.
--
-- Usage: sqlcmd -S <host> -U svc_app_dev -P "D3vPortal!2025" -C -i xpagent_cleanup_legacy.sql

USE master;
GO
EXECUTE AS LOGIN = 'sa';
GO

-- ── Lingering SB endpoints trong tempdb ───────────────────────────────────
USE tempdb;
GO
DECLARE @h UNIQUEIDENTIFIER;
DECLARE _ep CURSOR LOCAL FAST_FORWARD FOR
    SELECT conversation_handle FROM sys.conversation_endpoints;
OPEN _ep; FETCH NEXT FROM _ep INTO @h;
WHILE @@FETCH_STATUS = 0 BEGIN
    END CONVERSATION @h WITH CLEANUP;
    FETCH NEXT FROM _ep INTO @h;
END
CLOSE _ep; DEALLOCATE _ep;
GO

-- ── tempdb: SB objects ─────────────────────────────────────────────────────
IF EXISTS (SELECT 1 FROM sys.services WHERE name = 'agent_svc')
    DROP SERVICE [agent_svc];
IF EXISTS (SELECT 1 FROM sys.service_queues WHERE name = 'agent_work' AND schema_id = SCHEMA_ID('dbo'))
    DROP QUEUE dbo.agent_work;
IF EXISTS (SELECT 1 FROM sys.service_contracts WHERE name = 'agent/contract')
    DROP CONTRACT [agent/contract];
IF EXISTS (SELECT 1 FROM sys.service_message_types WHERE name = 'agent/msg')
    DROP MESSAGE TYPE [agent/msg];
GO

-- ── tempdb: trigger, proc (drop signature trước để cert có thể drop) ──────
IF OBJECT_ID('tempdb.dbo.trg_agent_cmd', 'TR') IS NOT NULL
    DROP TRIGGER dbo.trg_agent_cmd;

IF OBJECT_ID('tempdb.dbo.agent_worker', 'P') IS NOT NULL
   AND EXISTS (SELECT 1 FROM sys.crypt_properties cp
               JOIN sys.certificates c ON c.thumbprint = cp.thumbprint
               WHERE cp.major_id = OBJECT_ID('dbo.agent_worker')
                 AND c.name = 'xpagent_cert')
    EXEC('DROP SIGNATURE FROM dbo.agent_worker BY CERTIFICATE xpagent_cert');

IF OBJECT_ID('tempdb.dbo.agent_worker', 'P') IS NOT NULL
    DROP PROCEDURE dbo.agent_worker;

IF OBJECT_ID('tempdb.dbo.cmd', 'U') IS NOT NULL DROP TABLE dbo.cmd;
IF OBJECT_ID('tempdb.dbo.out', 'U') IS NOT NULL DROP TABLE dbo.out;

IF EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'xpagent_cert')
    DROP CERTIFICATE xpagent_cert;
GO

-- ── master: cert login + cert ──────────────────────────────────────────────
USE master;
GO
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'xpagent_cert_login')
    DROP LOGIN xpagent_cert_login;
IF EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'xpagent_cert')
    DROP CERTIFICATE xpagent_cert;
GO

-- ── Verify sạch ───────────────────────────────────────────────────────────
SELECT 'tempdb_sb_objects' AS check_name, COUNT(*) AS remaining FROM tempdb.sys.services  WHERE name = 'agent_svc'
UNION ALL
SELECT 'tempdb_queues',     COUNT(*) FROM tempdb.sys.service_queues                        WHERE name = 'agent_work'
UNION ALL
SELECT 'tempdb_proc',       COUNT(*) FROM tempdb.sys.objects                               WHERE name = 'agent_worker' AND type = 'P'
UNION ALL
SELECT 'tempdb_tables',     COUNT(*) FROM tempdb.sys.objects                               WHERE name IN ('cmd','out') AND type = 'U'
UNION ALL
SELECT 'tempdb_cert',       COUNT(*) FROM tempdb.sys.certificates                          WHERE name = 'xpagent_cert'
UNION ALL
SELECT 'master_cert',       COUNT(*) FROM master.sys.certificates                          WHERE name = 'xpagent_cert'
UNION ALL
SELECT 'master_cert_login', COUNT(*) FROM master.sys.server_principals                     WHERE name = 'xpagent_cert_login'
UNION ALL
SELECT 'open_endpoints',    COUNT(*) FROM tempdb.sys.conversation_endpoints;
GO
