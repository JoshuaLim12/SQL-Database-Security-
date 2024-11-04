-- Section 1: Create the AIS Database and Tables
IF DB_ID('AIS') IS NULL
BEGIN
    CREATE DATABASE AIS;
END;
GO

USE AIS;
GO

-- Create the Student Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Student')
BEGIN
    CREATE TABLE Student (
        ID VARCHAR(6) PRIMARY KEY,   
        SystemPwd VARBINARY(
		max),      -- Password will be encrypted
        Name VARCHAR(100) NOT NULL,
        Phone VARCHAR(20),
        SensitiveInfo NVARCHAR(255),  -- Example: Address
        CreatedBy NVARCHAR(50),       -- Who created the record
        CreatedDate DATETIME DEFAULT GETDATE()  -- Timestamp of record creation
    );
END;
GO

-- Create the Lecturer Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Lecturer')
BEGIN
    CREATE TABLE Lecturer (
        ID varchar(6) PRIMARY KEY,    
        SystemPwd VARBINARY(max),     -- Password will encrypted
        Name varchar(100) NOT NULL,
        Phone varchar(20),
        Department varchar(30),
        SensitiveInfo NVARCHAR(255), -- Example: Address
        CreatedBy NVARCHAR(50),     -- Who created the record
        CreatedDate DATETIME DEFAULT GETDATE()  -- Timestamp of record creation
    );
END;
GO

-- Create the Subject Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Subject')
BEGIN
    CREATE TABLE Subject (
        Code varchar(5) PRIMARY KEY,
        Title varchar(30)
    );
END;
GO

-- Create the Result Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Result')
BEGIN
    CREATE TABLE Result (
        ID int PRIMARY KEY IDENTITY(1,1),
        StudentID varchar(6) REFERENCES Student(ID),
        LecturerID varchar(6) REFERENCES Lecturer(ID),
        SubjectCode varchar(5) REFERENCES Subject(Code),
        AssessmentDate date,
        Grade varchar(2)
    );
END;
GO

-- Section 2: Setup Transparent Data Encryption (TDE)
-- Create Master Key 
USE master;
GO
IF NOT EXISTS (SELECT * FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
BEGIN
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'MasterKeyPassword@123';
END
GO

-- Create TDE Certificate
IF NOT EXISTS (SELECT * FROM sys.certificates WHERE name = 'TDECert')
BEGIN
    CREATE CERTIFICATE TDECert
    WITH SUBJECT = 'TDE_Cert';
END
GO

-- Backup Certificate and Private Key for TDE Cert
Use master;
GO

IF EXISTS (SELECT * FROM sys.certificates WHERE name = 'TDECert')
BEGIN
    BACKUP CERTIFICATE TDECert
    TO FILE = N'/var/opt/mssql/backups/tde/TDECert.cert' 
    WITH PRIVATE KEY (
        FILE = N'/var/opt/mssql/backups/tde/TDECert.key',
        ENCRYPTION BY PASSWORD = 'MasterKeyPassword@123'
    );
END
GO

-- Create Database Encryption Key (DEK)
USE AIS;
GO

IF NOT EXISTS (SELECT * FROM sys.dm_database_encryption_keys WHERE database_id = DB_ID('AIS'))
BEGIN
    CREATE DATABASE ENCRYPTION KEY
    WITH ALGORITHM = AES_256
    ENCRYPTION BY SERVER CERTIFICATE TDECert;
END
GO

-- Enable Encryption for Database
IF (SELECT encryption_state FROM sys.dm_database_encryption_keys WHERE database_id = DB_ID('AIS')) != 3
BEGIN
    ALTER DATABASE AIS
    SET ENCRYPTION ON;
END
GO

-- Display Encryption Status
Use master;
GO

SELECT 
    db_name(a.database_id) AS DBName,
    CASE 
        WHEN a.encryption_state = 0 THEN 'No Encryption'
        WHEN a.encryption_state = 1 THEN 'Unencrypted'
        WHEN a.encryption_state = 2 THEN 'Encryption in Progress'
        WHEN a.encryption_state = 3 THEN 'Encrypted'
        WHEN a.encryption_state = 4 THEN 'Key Change in Progress'
        WHEN a.encryption_state = 5 THEN 'Decryption in Progress'
        ELSE 'Unknown'
    END AS encryption_state_desc,
    a.encryptor_type, 
    b.name AS 'DEK Encrypted By'
FROM sys.dm_database_encryption_keys a
INNER JOIN sys.certificates b 
    ON a.encryptor_thumbprint = b.thumbprint;
GO


-- Section 3: Setup Backup Database 
USE master;
GO

IF NOT EXISTS (SELECT * FROM sys.certificates WHERE name = 'BackupCert')
BEGIN
    CREATE CERTIFICATE BackupCert
    WITH SUBJECT = 'Backup_Cert';
END
GO

-- Backup Certificate and Private Key for Backup Cert
IF EXISTS (SELECT * FROM sys.certificates WHERE name = 'BackupCert')
BEGIN
	BACKUP CERTIFICATE BackupCert
	TO FILE = N'/var/opt/mssql/backups/backup/BackupCert.cert' 
	WITH PRIVATE KEY (
		FILE = N'/var/opt/mssql/backups/backup/BackupCert.key',  
		ENCRYPTION BY PASSWORD = 'MasterKeyPassword@123'  
	);
END
GO

-- Manual Backups
-- Full Backup
DECLARE @FileName AS VARCHAR(255)
DECLARE @FilePath AS VARCHAR(255)
SET @FileName = ('AIS_Full_Backup_' + CONVERT(VARCHAR(30), GETDATE(), 112) + '.bak')
SET @FilePath = N'/var/opt/mssql/backups/full/' + @FileName
BACKUP DATABASE AIS
TO DISK = @FilePath
WITH FORMAT,
ENCRYPTION (
    ALGORITHM = AES_256,
    SERVER CERTIFICATE = BackupCert
);
GO

-- Differential  Backup
DECLARE @FileName AS VARCHAR(255)
DECLARE @FilePath AS VARCHAR(255)
SET @FileName = ('AIS_Differential_Backup_' + CONVERT(VARCHAR(30), GETDATE(), 112) + '_' + REPLACE(CONVERT(VARCHAR(8), GETDATE(), 108), ':', '-') + '.bak')
SET @FilePath = N'/var/opt/mssql/backups/differential/' + @FileName

-- Perform the differential backup with encryption, creating a new backup file each time
BACKUP DATABASE AIS
TO DISK = @FilePath
WITH DIFFERENTIAL,
     ENCRYPTION (
         ALGORITHM = AES_256,
         SERVER CERTIFICATE = BackupCert
     );
GO


-- T-Log Backup
DECLARE @FileName AS VARCHAR(255)
DECLARE @FilePath AS VARCHAR(255)
SET @FileName = ('AIS_TLog_Backup_' + CONVERT(VARCHAR(30), GETDATE(), 112) + '_' + REPLACE(CONVERT(VARCHAR(8), GETDATE(), 108), ':', '-') + '.bak')
SET @FilePath = N'/var/opt/mssql/backups/tlog/' + @FileName
BACKUP LOG AIS
TO DISK = @FilePath
WITH ENCRYPTION (
    ALGORITHM = AES_256,
    SERVER CERTIFICATE = BackupCert
);
GO

-- Section 4: Setup Server Audit
USE master;
GO
-- Create server audits for DDL, DML, DCL, and Login attempts
-- Login Attempts Server Audit
IF NOT EXISTS (SELECT * FROM sys.server_audits WHERE name = 'Login_ServerAudit')
BEGIN
    CREATE SERVER AUDIT Login_ServerAudit
    TO FILE (FILEPATH = '/var/opt/mssql/audit_logs/login_audit/');
    ALTER SERVER AUDIT Login_ServerAudit WITH (STATE = ON);
END;
GO
-- DDL Server Audit
IF NOT EXISTS (SELECT * FROM sys.server_audits WHERE name = 'DDL_ServerAudit')
BEGIN
    CREATE SERVER AUDIT DDL_ServerAudit
    TO FILE (FILEPATH = '/var/opt/mssql/audit_logs/ddl_audit/');
    ALTER SERVER AUDIT DDL_ServerAudit WITH (STATE = ON);
END;
GO

-- DML Server Audit
IF NOT EXISTS (SELECT * FROM sys.server_audits WHERE name = 'DML_ServerAudit')
BEGIN
    CREATE SERVER AUDIT DML_ServerAudit
    TO FILE (FILEPATH = '/var/opt/mssql/audit_logs/dml_audit/');
    ALTER SERVER AUDIT DML_ServerAudit WITH (STATE = ON);
END;
GO

-- DCL Server Audit
IF NOT EXISTS (SELECT * FROM sys.server_audits WHERE name = 'DCL_ServerAudit')
BEGIN
    CREATE SERVER AUDIT DCL_ServerAudit
    TO FILE (FILEPATH = '/var/opt/mssql/audit_logs/dcl_audit/');
    ALTER SERVER AUDIT DCL_ServerAudit WITH (STATE = ON);
END;
GO



-- Server Audit Specifications
USE master;
GO
-- Track login attempts (successful and failed)
IF NOT EXISTS (SELECT * FROM sys.server_audit_specifications WHERE name = 'LoginAuditSpec')
BEGIN
    CREATE SERVER AUDIT SPECIFICATION LoginAuditSpec
    FOR SERVER AUDIT Login_ServerAudit
    ADD (SUCCESSFUL_LOGIN_GROUP),  -- Successful logins
    ADD (FAILED_LOGIN_GROUP)        -- Failed logins
    WITH (STATE = ON);
END;
GO


-- Database Audit Specifications (DDL, DML, DCL)
USE AIS;
GO

-- DDL Auditing: Track database object changes (create, alter, drop)
IF NOT EXISTS (SELECT * FROM sys.database_audit_specifications WHERE name = 'DDLAuditSpec')
BEGIN
    CREATE DATABASE AUDIT SPECIFICATION DDLAuditSpec
    FOR SERVER AUDIT DDL_ServerAudit
    ADD (DATABASE_OBJECT_CHANGE_GROUP),
    ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP)  -- Permission changes
    WITH (STATE = ON);
END;
GO

-- DML Auditing: Track data manipulation (insert, update, delete)
IF NOT EXISTS (SELECT * FROM sys.database_audit_specifications WHERE name = 'DMLAuditSpec')
BEGIN
    CREATE DATABASE AUDIT SPECIFICATION DMLAuditSpec
    FOR SERVER AUDIT DML_ServerAudit
    ADD (INSERT ON DATABASE::AIS BY PUBLIC),
    ADD (UPDATE ON DATABASE::AIS BY PUBLIC),
    ADD (DELETE ON DATABASE::AIS BY PUBLIC)
    WITH (STATE = ON);
END;
GO

-- DCL Auditing: Track permission changes, user creation, and deletion
IF NOT EXISTS (SELECT * FROM sys.database_audit_specifications WHERE name = 'DCLAuditSpec')
BEGIN
    CREATE DATABASE AUDIT SPECIFICATION DCLAuditSpec
    FOR SERVER AUDIT DCL_ServerAudit
    ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),   -- User creation, deletion, or changes
    ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP) -- Permission changes
    WITH (STATE = ON);
END;
GO

USE master;
GO
-- Enable the server audits if they are not already enabled
ALTER SERVER AUDIT Login_ServerAudit WITH (STATE = ON);
ALTER SERVER AUDIT DDL_ServerAudit WITH (STATE = ON);
ALTER SERVER AUDIT DML_ServerAudit WITH (STATE = ON);
ALTER SERVER AUDIT DCL_ServerAudit WITH (STATE = ON);
GO

-- check server audit
SELECT 
	audit_id,
	name AS ServerAudit,
	is_state_enabled
FROM sys.server_audits;
GO


-- System Versioned Temporal Tables
USE AIS;
GO

-- Alter an existing table to add system-versioning period columns
ALTER TABLE Student
ADD 
    SysStartTime DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL DEFAULT GETUTCDATE(),
    SysEndTime DATETIME2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.9999999'),
    PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime);

-- Enable system-versioning on the Student table with a specified history table
ALTER TABLE Student
SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.StudentHistory));


-- Alter the Lecturer table to add system-vers`ioning period columns
ALTER TABLE Lecturer
ADD 
    SysStartTime DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL DEFAULT GETUTCDATE(),
    SysEndTime DATETIME2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.9999999'),
    PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime);

-- Enable system-versioning on the Lecturer table with a specified history table
ALTER TABLE Lecturer
SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.LecturerHistory));


-- Alter the Subject table to add system-versioning period columns
ALTER TABLE Subject
ADD 
    SysStartTime DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL DEFAULT GETUTCDATE(),
    SysEndTime DATETIME2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.9999999'),
    PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime);

-- Enable system-versioning on the Subject table with a specified history table
ALTER TABLE Subject
SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.SubjectHistory));


-- Alter the Result table to add system-versioning period columns
ALTER TABLE Result
ADD 
    SysStartTime DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL DEFAULT GETUTCDATE(),
    SysEndTime DATETIME2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.9999999'),
    PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime);

-- Enable system-versioning on the Result table with a specified history table
ALTER TABLE Result
SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.ResultHistory));


-- check system-versioned temporal table
SELECT 
    t.name AS TableName,
    t.temporal_type_desc AS TemporalType,
    ht.name AS HistoryTableName
FROM sys.tables t
LEFT JOIN sys.tables ht
    ON t.history_table_id = ht.object_id
WHERE t.temporal_type > 0;


-- Section 5: Setup Backup Tables for Deleted Records and Recovery Stored Procedure
-- Backup Deleted Student
USE AIS;
IF OBJECT_ID('DeletedStudentsBackup', 'U') IS NULL
BEGIN
	CREATE TABLE DeletedStudentsBackup (
		ID VARCHAR(6),
		SystemPwd VARBINARY(100), -- Backup the encrypted password
		Name NVARCHAR(100),
		Phone NVARCHAR(20),
		SensitiveInfo NVARCHAR(255),
		DeletedBy NVARCHAR(50),
		DeletionDate DATETIME DEFAULT GETDATE()
	);
END;
GO

IF OBJECT_ID('trg_BackupDelete_Student', 'TR') IS NOT NULL
BEGIN
    DROP TRIGGER trg_BackupDelete_Student;
END;
GO

CREATE TRIGGER trg_BackupDelete_Student
ON Student
AFTER DELETE
AS
BEGIN  
	-- Insert deleted student data (including SystemPwd) into backup table
	INSERT INTO DeletedStudentsBackup (ID, SystemPwd, Name, Phone, SensitiveInfo, DeletedBy, DeletionDate)
	SELECT ID, SystemPwd, Name, Phone, SensitiveInfo, SYSTEM_USER, GETDATE()
	FROM DELETED;
END;
GO

-- Backup Deleted Lecturer
IF OBJECT_ID('DeletedLecturersBackup', 'U') IS NULL
BEGIN
    CREATE TABLE DeletedLecturersBackup (
        ID VARCHAR(6),
		SystemPwd VARBINARY(100),
        Name NVARCHAR(100),
        Phone NVARCHAR(20),
        Department NVARCHAR(30),
        SensitiveInfo NVARCHAR(255),
        DeletedBy NVARCHAR(50),
        DeletionDate DATETIME DEFAULT GETDATE()
    );
END;
GO

IF OBJECT_ID('trg_BackupDelete_Lecturer', 'TR') IS NOT NULL
BEGIN
    DROP TRIGGER trg_BackupDelete_Lecturer;
END;
GO

CREATE TRIGGER trg_BackupDelete_Lecturer
ON Lecturer
AFTER DELETE
AS
BEGIN
	-- Insert deleted lecturer data (including SystemPwd) into backup table
	INSERT INTO DeletedLecturersBackup (ID, SystemPwd, Name, Phone, Department, SensitiveInfo, DeletedBy, DeletionDate)
	SELECT ID, SystemPwd, Name, Phone, Department, SensitiveInfo, SYSTEM_USER, GETDATE()
	FROM DELETED;
END;
GO


-- Backup Subject Table
IF OBJECT_ID('DeletedSubjectsBackup', 'U') IS NULL
BEGIN
    CREATE TABLE DeletedSubjectsBackup (
        Code VARCHAR(5),
        Title NVARCHAR(30),
        DeletedBy NVARCHAR(50),
        DeletionDate DATETIME DEFAULT GETDATE()
    );
END;
GO

IF OBJECT_ID('trg_BackupDelete_Subject', 'TR') IS NOT NULL
BEGIN
    DROP TRIGGER trg_BackupDelete_Subject;
END;
GO

CREATE TRIGGER trg_BackupDelete_Subject
ON Subject
AFTER DELETE
AS
BEGIN
	-- Insert deleted subject data into backup table
    INSERT INTO DeletedSubjectsBackup (Code, Title, DeletedBy, DeletionDate)
	SELECT Code, Title, SYSTEM_USER, GETDATE()
	FROM DELETED;
END;
GO

SELECT * FROM DeletedStudentsBackup;


-- Recovery
-- Stored Procedure to recover deleted student
IF OBJECT_ID('sp_RecoverDeletedStudent', 'P') IS NOT NULL
BEGIN
    DROP PROCEDURE sp_RecoverDeletedStudent;
END;
GO

CREATE PROCEDURE sp_RecoverDeletedStudent
    @StudentID VARCHAR(6)
AS
BEGIN
    -- Recover the deleted student from the backup table
    INSERT INTO Student (ID, SystemPwd, Name, Phone, SensitiveInfo, CreatedBy, CreatedDate)
    SELECT ID, SystemPwd, Name, Phone, SensitiveInfo, DeletedBy, DeletionDate
    FROM DeletedStudentsBackup
    WHERE ID = @StudentID;

    -- Remove the recovered student from the backup table
    DELETE FROM DeletedStudentsBackup
    WHERE ID = @StudentID;
END;
GO


-- Stored Procedure to recover deleted lecturer
IF OBJECT_ID('sp_RecoverDeletedLecturer', 'P') IS NOT NULL
BEGIN
    DROP PROCEDURE sp_RecoverDeletedLecturer;
END;
GO

CREATE PROCEDURE sp_RecoverDeletedLecturer
    @LecturerID VARCHAR(6)
AS
BEGIN
    -- Recover the deleted lecturer from the backup table
    INSERT INTO Lecturer (ID, SystemPwd, Name, Phone, Department, SensitiveInfo, CreatedBy, CreatedDate)
    SELECT ID, SystemPwd, Name, Phone, Department, SensitiveInfo, DeletedBy, DeletionDate
    FROM DeletedLecturersBackup
    WHERE ID = @LecturerID;

    -- Remove the recovered lecturer from the backup table
    DELETE FROM DeletedLecturersBackup
    WHERE ID = @LecturerID;
END;
GO

-- Stored Procedure to recover deleted subject
IF OBJECT_ID('sp_RecoverDeletedSubject', 'P') IS NOT NULL
BEGIN
    DROP PROCEDURE sp_RecoverDeletedSubject;
END;
GO

CREATE PROCEDURE sp_RecoverDeletedSubject
    @SubjectCode VARCHAR(5)
AS
BEGIN
    -- Recover the deleted subject from the backup table
    INSERT INTO Subject (Code, Title)
    SELECT Code, Title
    FROM DeletedSubjectsBackup
    WHERE Code = @SubjectCode;

    -- Remove the recovered subject from the backup table
    DELETE FROM DeletedSubjectsBackup
    WHERE Code = @SubjectCode;
END;
GO


-- Section 6: Column-level Encryption (CLE)
-- Create a Master Key 
USE AIS;
IF NOT EXISTS (SELECT * FROM sys.symmetric_keys WHERE symmetric_key_id = 101)
BEGIN
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'VeryStrongPassword123!';
END;
GO

-- Create a Certificate for encryption 
IF NOT EXISTS (SELECT * FROM sys.certificates WHERE name = 'AISCert')
BEGIN
    CREATE CERTIFICATE AISCert
    WITH SUBJECT = 'AIS_Cert';
END;
GO

-- Create the Symmetric Key
IF NOT EXISTS (SELECT * FROM sys.symmetric_keys WHERE name = 'PasswordEncryptionKey')
BEGIN
    CREATE SYMMETRIC KEY PasswordEncryptionKey
    WITH ALGORITHM = AES_256
    ENCRYPTION BY CERTIFICATE AISCert;
END;
GO

-- Check CLE Setup
SELECT * FROM sys.symmetric_keys;

SELECT * 
FROM sys.certificates
WHERE name = 'AISCert';


-- Section 7: Encrypt User Password
-- Open the symmetric key to encrypt the password
OPEN SYMMETRIC KEY PasswordEncryptionKey DECRYPTION BY CERTIFICATE AISCert;

-- Insert data into the Student table
IF NOT EXISTS (SELECT 1 FROM Student)
BEGIN
    INSERT INTO Student (ID, SystemPwd, Name, Phone, SensitiveInfo, CreatedBy, CreatedDate)
    VALUES 
    ('S0001', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'StudentPass123!')),
     'Alex', '0123456789', 'Address: 666 Main St, KL', 'Admin1', GETDATE()),

    ('S0002', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'StudentPass456!')),
     'Darren', '0198765432', 'Address: 336 Elm St, KL', 'Admin2', GETDATE());
END;
GO

-- Insert data into the Lecturer table
IF NOT EXISTS (SELECT 1 FROM Lecturer)
BEGIN
    INSERT INTO Lecturer (ID, SystemPwd, Name, Phone, Department, SensitiveInfo, CreatedBy, CreatedDate)
    VALUES 
    ('L0001', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'LecturerPass123!')),
     'Dr. Blake', '0112233445', 'Math', 'Address: Bukit Jalil, KL', 'Admin1', GETDATE()),

    ('L0002', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'LecturerPass456!')),
     'Prof. Michael', '0119988776', 'Physics', 'Address: Puchong, Selangor', 'Admin2', GETDATE());
END;
GO

-- Close the symmetric key after encryption
CLOSE SYMMETRIC KEY PasswordEncryptionKey;
GO

-- Insert data into the Subject table
IF NOT EXISTS (SELECT 1 FROM Subject)
BEGIN
    INSERT INTO Subject (Code, Title)
    VALUES 
    ('MTH01', 'Mathematics 101'),
    ('PHY01', 'Physics 101'),
    ('CSC01', 'Computer Science 101'),
    ('ENG01', 'English 101');
END;
GO

-- Insert data into the Result table
IF NOT EXISTS (SELECT 1 FROM Result)
BEGIN
    INSERT INTO Result (StudentID, LecturerID, SubjectCode, AssessmentDate, Grade)
    VALUES 
    ('S0001', 'L0001', 'MTH01', '2024-07-10', 'A'),
    ('S0001', 'L0002', 'PHY01', '2024-07-11', 'B'),
    ('S0002', 'L0001', 'MTH01', '2024-08-12', 'B'),
    ('S0002', 'L0002', 'PHY01', '2024-08-13', 'A'),
    ('S0001', 'L0001', 'CSC01', '2024-09-14', 'A'),
    ('S0002', 'L0001', 'CSC01', '2024-09-14', 'A');
END;
GO


-- Section 8: Create Users Table (Login System)
-- Insert initial data into the Users table with encrypted password hashes
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Users')
BEGIN
    CREATE TABLE Users (
        Username NVARCHAR(50) PRIMARY KEY,
        Password VARBINARY(MAX)
    );
END;
GO

-- Open the symmetric key to encrypt the password
OPEN SYMMETRIC KEY PasswordEncryptionKey DECRYPTION BY CERTIFICATE AISCert;

IF NOT EXISTS (SELECT 1 FROM Users)
BEGIN
	INSERT INTO Users (Username, Password )
		VALUES
		('Admin1', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'AdminPass123!'))),
		('Admin2', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'AdminPass456!'))),
		('S0001', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'StudentPass123!'))),
		('S0002', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'StudentPass456!'))),
		('L0001', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'LecturerPass123!'))),
		('L0002', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'LecturerPass456!')));
END;
GO


-- Close the symmetric key after encryption
CLOSE SYMMETRIC KEY PasswordEncryptionKey;
GO

-- Trigger to synchronize Student table with Users table
IF OBJECT_ID('trg_Student_UserSync', 'TR') IS NOT NULL
BEGIN
    DROP TRIGGER trg_Student_UserSync;
END;
GO

-- Create the trigger to sync Students with Users table after insert, update, and delete
CREATE TRIGGER trg_Student_UserSync
ON Student
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    -- Handle INSERT or UPDATE
    IF EXISTS (SELECT * FROM inserted)
    BEGIN
        -- Merge Student data into Users table to sync username and encrypted password
        MERGE INTO Users AS target
        USING (SELECT ID, SystemPwd FROM inserted) AS source
        ON (target.Username = source.ID)
        WHEN MATCHED THEN
            UPDATE SET target.Password = source.SystemPwd
        WHEN NOT MATCHED BY TARGET THEN
            INSERT (Username, Password)
            VALUES (source.ID, source.SystemPwd);
    END

    -- Handle DELETE
    IF EXISTS (SELECT * FROM deleted)
    BEGIN
        -- Delete corresponding user from the Users table when a student is deleted
        DELETE FROM Users
        WHERE Username IN (SELECT ID FROM deleted);
    END
END;
GO


-- Trigger to synchronize Lecturer table with Users table
IF OBJECT_ID('trg_Lecturer_UserSync', 'TR') IS NOT NULL
BEGIN
    DROP TRIGGER trg_Lecturer_UserSync;
END;
GO

-- Create the trigger to sync Lecturers with Users table after insert, update, and delete
CREATE TRIGGER trg_Lecturer_UserSync
ON Lecturer
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    -- Handle INSERT or UPDATE
    IF EXISTS (SELECT * FROM inserted)
    BEGIN
        -- Merge Lecturer data into Users table to sync username and encrypted password
        MERGE INTO Users AS target
        USING (SELECT ID, SystemPwd FROM inserted) AS source
        ON (target.Username = source.ID)
        WHEN MATCHED THEN
            UPDATE SET target.Password = source.SystemPwd
        WHEN NOT MATCHED BY TARGET THEN
            INSERT (Username, Password)
            VALUES (source.ID, source.SystemPwd);
    END

    -- Handle DELETE
    IF EXISTS (SELECT * FROM deleted)
    BEGIN
        -- Delete corresponding user from the Users table when a lecturer is deleted
        DELETE FROM Users
        WHERE Username IN (SELECT ID FROM deleted);
    END
END;
GO

-- Open the symmetric key to decrypt the data for comparison
OPEN SYMMETRIC KEY PasswordEncryptionKey DECRYPTION BY CERTIFICATE AISCert;

-- Compare Student passwords with Users table
SELECT 
    s.ID AS StudentID, 
    u.Username AS Username, 
    CASE 
        WHEN CONVERT(NVARCHAR(100), DecryptByKey(s.SystemPwd)) = CONVERT(NVARCHAR(100), DecryptByKey(u.Password)) 
        THEN 'Match' ELSE 'No Match' 
    END AS MatchStatus
FROM 
    Student s
JOIN 
    Users u ON s.ID = u.Username;


-- Compare Lecturer passwords with Users table
SELECT 
    l.ID AS LecturerID, 
    u.Username AS Username, 
    CASE 
        WHEN CONVERT(NVARCHAR(100), DecryptByKey(l.SystemPwd)) = CONVERT(NVARCHAR(100), DecryptByKey(u.Password)) 
        THEN 'Match' ELSE 'No Match' 
    END AS MatchStatus
FROM 
    Lecturer l
JOIN 
    Users u ON l.ID = u.Username;

-- Close the symmetric key after comparison
CLOSE SYMMETRIC KEY PasswordEncryptionKey;

SELECT * FROM Users;
SELECT * FROM Student;
SELECT * FROM Lecturer;

-- Section 9: Role-Based Access Control
-- Create roles 
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'DataAdminRole')
BEGIN
    CREATE ROLE DataAdminRole;
END;

IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'LecturerRole')
BEGIN
    CREATE ROLE LecturerRole;
END;

IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'StudentRole')
BEGIN
    CREATE ROLE StudentRole;
END;
GO

-- Create login
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'Admin1')
BEGIN
    CREATE LOGIN Admin1 WITH PASSWORD = 'AdminPass123!';
END;

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'Admin2')
BEGIN
    CREATE LOGIN Admin2 WITH PASSWORD = 'AdminPass456!';
END;

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'S0001')
BEGIN
    CREATE LOGIN S0001 WITH PASSWORD = 'StudentPass123!';
END;

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'S0002')
BEGIN
    CREATE LOGIN S0002 WITH PASSWORD = 'StudentPass456!';
END;

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'L0001')
BEGIN
    CREATE LOGIN L0001 WITH PASSWORD = 'LecturerPass123!';
END;

IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'L0002')
BEGIN
    CREATE LOGIN L0002 WITH PASSWORD = 'LecturerPass456!';
END;
GO

-- Create database users 
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'Admin1')
BEGIN
    CREATE USER Admin1 FOR LOGIN Admin1;
END;

IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'Admin2')
BEGIN
    CREATE USER Admin2 FOR LOGIN Admin2;
END;

IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'S0001')
BEGIN
    CREATE USER S0001 FOR LOGIN S0001;
END;

IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'S0002')
BEGIN
    CREATE USER S0002 FOR LOGIN S0002;
END;

IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'L0001')
BEGIN
    CREATE USER L0001 FOR LOGIN L0001;
END;

IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'L0002')
BEGIN
    CREATE USER L0002 FOR LOGIN L0002;
END;
GO

-- Assign roles to users if not already assigned
IF NOT EXISTS (SELECT * FROM sys.database_role_members WHERE member_principal_id = USER_ID('Admin1') AND role_principal_id = USER_ID('DataAdminRole'))
BEGIN
    ALTER ROLE DataAdminRole ADD MEMBER Admin1;
END;

IF NOT EXISTS (SELECT * FROM sys.database_role_members WHERE member_principal_id = USER_ID('Admin2') AND role_principal_id = USER_ID('DataAdminRole'))
BEGIN
    ALTER ROLE DataAdminRole ADD MEMBER Admin2;
END;

IF NOT EXISTS (SELECT * FROM sys.database_role_members WHERE member_principal_id = USER_ID('Student1') AND role_principal_id = USER_ID('StudentRole'))
BEGIN
    ALTER ROLE StudentRole ADD MEMBER S0001;
END;

IF NOT EXISTS (SELECT * FROM sys.database_role_members WHERE member_principal_id = USER_ID('Student2') AND role_principal_id = USER_ID('StudentRole'))
BEGIN
    ALTER ROLE StudentRole ADD MEMBER S0002;
END;

IF NOT EXISTS (SELECT * FROM sys.database_role_members WHERE member_principal_id = USER_ID('Lecturer1') AND role_principal_id = USER_ID('LecturerRole'))
BEGIN
    ALTER ROLE LecturerRole ADD MEMBER L0001;
END;

IF NOT EXISTS (SELECT * FROM sys.database_role_members WHERE member_principal_id = USER_ID('Lecturer2') AND role_principal_id = USER_ID('LecturerRole'))
BEGIN
    ALTER ROLE LecturerRole ADD MEMBER L0002;
END;
GO

-- Create Views and Procedures
-- Create AdminUserView
IF EXISTS (SELECT * FROM sys.views WHERE name = 'AdminUsersView')
BEGIN
    DROP VIEW AdminUsersView;
END;
GO

CREATE VIEW AdminUsersView AS
SELECT 
	Username,
	CASE 
        WHEN Password IS NOT NULL THEN 'Encrypted' 
        ELSE NULL 
    END AS SystemPwd
FROM Users;
GO

-- Create AdminStudentView 
IF EXISTS (SELECT * FROM sys.views WHERE name = 'AdminStudentView')
BEGIN
    DROP VIEW AdminStudentView;
END;
GO

CREATE VIEW AdminStudentView AS
SELECT 
	ID,
	CASE 
        WHEN SystemPwd IS NOT NULL THEN 'Encrypted' 
        ELSE NULL 
    END AS SystemPwd, 
	Name, Phone, CreatedBy, CreatedDate
FROM Student;
GO

SELECT * FROM AdminStudentView;

-- Create AdminLecturerView
IF EXISTS (SELECT * FROM sys.views WHERE name = 'AdminLecturerView')
BEGIN
    DROP VIEW AdminLecturerView;
END;
GO


CREATE VIEW AdminLecturerView AS
SELECT 
	ID,
	CASE 
        WHEN SystemPwd IS NOT NULL THEN 'Encrypted' 
        ELSE NULL 
    END AS SystemPwd, 
	Name, Phone, Department, CreatedBy, CreatedDate
FROM Lecturer;
GO

-- Create DeletedStudentsBackupView
IF EXISTS (SELECT * FROM sys.views WHERE name = 'DeletedStudentsBackupView')
BEGIN
    DROP VIEW DeletedStudentsBackupView;
END;
GO

CREATE VIEW DeletedStudentsBackupView AS
SELECT 
    ID, 
	CASE 
        WHEN SystemPwd IS NOT NULL THEN 'Encrypted' 
        ELSE NULL 
    END AS SystemPwd,  -- Mask the SystemPwd
    Name, 
    Phone, 
    'Confidential' AS SensitiveInfo, -- Mask the SensitiveInfo
    DeletedBy, 
    DeletionDate
FROM DeletedStudentsBackup;
GO


-- Create DeletedLecturersBackupView
IF EXISTS (SELECT * FROM sys.views WHERE name = 'DeletedLecturersBackupView')
BEGIN
    DROP VIEW DeletedLecturersBackupView;
END;
GO

CREATE VIEW DeletedLecturersBackupView AS
SELECT 
    ID, 
	CASE 
        WHEN SystemPwd IS NOT NULL THEN 'Encrypted' 
        ELSE NULL 
    END AS SystemPwd,  -- Mask the SystemPwd
    Name, 
    Phone, 
    'Confidential' AS SensitiveInfo, -- Mask the SensitiveInfo
    DeletedBy, 
    DeletionDate
FROM DeletedLecturersBackup;
GO




-- Create StudentResultView
IF EXISTS (SELECT * FROM sys.views WHERE name = 'StudentResultView')
BEGIN
    DROP VIEW StudentResultView;
END;
GO
CREATE VIEW StudentResultView AS
SELECT 
    r.ID, 
    r.StudentID, 
    r.LecturerID, 
    r.SubjectCode, 
    r.AssessmentDate, 
    r.Grade
FROM 
    Result r
JOIN 
    Student s ON r.StudentID = s.ID
WHERE 
    s.ID = USER_NAME();  -- Restrict to the logged-in student
GO

-- Create LecturerView
IF EXISTS (SELECT * FROM sys.views WHERE name = 'LecturerView')
BEGIN
    DROP VIEW LecturerView;
END;
GO
CREATE VIEW LecturerView AS
SELECT ID, Name, Phone, Department
FROM Lecturer;
GO


-- Create LecturerStudentView
IF EXISTS (SELECT * FROM sys.views WHERE name = 'LecturerStudentView')
BEGIN
    DROP VIEW LecturerStudentView;
END;
GO
CREATE VIEW LecturerStudentView AS
SELECT ID, Name, Phone
FROM Student;
GO

-- Create a trigger to allow lecturers to update only the results they have added
IF OBJECT_ID('trg_LecturerOwnResultUpdate', 'TR') IS NOT NULL
BEGIN
    DROP TRIGGER trg_LecturerOwnResultUpdate;
END;
GO
CREATE TRIGGER trg_LecturerOwnResultUpdate
ON Result
FOR INSERT, UPDATE
AS
BEGIN
    DECLARE @LecturerID VARCHAR(6);
    SET @LecturerID = USER_NAME();  -- Get the current logged-in lecturer's ID

    -- Check if the lecturer is trying to update results added by another lecturer
    IF EXISTS (
        SELECT 1 
        FROM inserted i
        JOIN deleted d ON i.ID = d.ID
        WHERE d.LecturerID <> @LecturerID  -- Check if the result was added by someone else
    )
    BEGIN
        -- Rollback the update and raise an error if the lecturer doesn't own the result
        ROLLBACK TRANSACTION;
        RAISERROR('You can only update the results you have added.', 16, 1);
    END
END;
GO

-- Create the procedure to show the student's decrypted password
IF OBJECT_ID('sp_StudentSelfInfo', 'P') IS NOT NULL
BEGIN
    DROP PROCEDURE sp_StudentSelfInfo;
END;
GO

CREATE PROCEDURE sp_StudentSelfInfo
AS
BEGIN
    -- Open the symmetric key for decryption
    OPEN SYMMETRIC KEY PasswordEncryptionKey DECRYPTION BY CERTIFICATE AISCert;

    -- Query only the current student's own record
    SELECT 
        ID, 
        CONVERT(NVARCHAR(100), DecryptByKey(SystemPwd)) AS DecryptedPwd, 
        Name, 
        Phone, 
        SensitiveInfo
    FROM Student
    WHERE ID = USER_NAME();  -- Ensure the student can only view their own data

    -- Close the symmetric key after decryption
    CLOSE SYMMETRIC KEY PasswordEncryptionKey;
END;
GO

-- Create the procedure for updating student information
IF OBJECT_ID('sp_StudentUpdateInfo', 'P') IS NOT NULL
BEGIN
    DROP PROCEDURE sp_StudentUpdateInfo;
END;
GO
CREATE PROCEDURE sp_StudentUpdateInfo
    @Phone NVARCHAR(20) = NULL,
    @SensitiveInfo NVARCHAR(255) = NULL,
    @NewPassword NVARCHAR(100) = NULL 
AS
BEGIN
    -- Open the symmetric key for encryption (for updating the password if needed)
    OPEN SYMMETRIC KEY PasswordEncryptionKey DECRYPTION BY CERTIFICATE AISCert;

    -- Update the phone number if it is provided
    IF @Phone IS NOT NULL
    BEGIN
        UPDATE Student
        SET Phone = @Phone
        WHERE ID = USER_NAME();  -- Restrict update to the student's own record
    END

    -- Update the sensitive information if it is provided
    IF @SensitiveInfo IS NOT NULL
    BEGIN
        UPDATE Student
        SET SensitiveInfo = @SensitiveInfo
        WHERE ID = USER_NAME();  -- Restrict update to the student's own record
    END

    -- If the @NewPassword parameter is provided, update the password
    IF @NewPassword IS NOT NULL
    BEGIN
        -- Encrypt the new password before updating it
        UPDATE Student
        SET SystemPwd = EncryptByKey(Key_GUID('PasswordEncryptionKey'), @NewPassword)
        WHERE ID = USER_NAME();  -- Restrict update to the student's own record
    END

    -- Close the symmetric key after the operation
    CLOSE SYMMETRIC KEY PasswordEncryptionKey;
END;
GO


-- Create the procedure to show the lecturer's decrypted password
IF OBJECT_ID('sp_LecturerSelfInfo', 'P') IS NOT NULL
BEGIN
    DROP PROCEDURE sp_LecturerSelfInfo;
END;
GO
CREATE PROCEDURE sp_LecturerSelfInfo
AS
BEGIN
    -- Open the symmetric key for decryption
    OPEN SYMMETRIC KEY PasswordEncryptionKey DECRYPTION BY CERTIFICATE AISCert;

    -- Query only the current lecturer's own record
    SELECT 
        ID, 
        CONVERT(NVARCHAR(100), DecryptByKey(SystemPwd)) AS DecryptedPwd, 
        Name, 
        Phone, 
		Department,
        SensitiveInfo
    FROM Lecturer
    WHERE ID = USER_NAME();  -- Ensure the lecturer can only view their own data

    -- Close the symmetric key after decryption
    CLOSE SYMMETRIC KEY PasswordEncryptionKey;
END;
GO

-- Create the procedure for updating lecturer information
IF OBJECT_ID('sp_LecturerUpdateInfo', 'P') IS NOT NULL
BEGIN
    DROP PROCEDURE sp_LecturerUpdateInfo;
END;
GO
CREATE PROCEDURE sp_LecturerUpdateInfo
    @Phone NVARCHAR(20) = NULL,
    @SensitiveInfo NVARCHAR(255) = NULL,
    @NewPassword NVARCHAR(100) = NULL 
AS
BEGIN
    -- Open the symmetric key for encryption (for updating the password if needed)
    OPEN SYMMETRIC KEY PasswordEncryptionKey DECRYPTION BY CERTIFICATE AISCert;

    -- Update the phone number if it's provided
    IF @Phone IS NOT NULL
    BEGIN
        UPDATE Lecturer
        SET Phone = @Phone
        WHERE ID = USER_NAME();  -- Restrict update to the lecturer's own record
    END

    -- Update the sensitive information if it's provided
    IF @SensitiveInfo IS NOT NULL
    BEGIN
        UPDATE Lecturer
        SET SensitiveInfo = @SensitiveInfo
        WHERE ID = USER_NAME();  -- Restrict update to the lecturer's own record
    END

    -- Update the password if it's provided
    IF @NewPassword IS NOT NULL
    BEGIN
        -- Encrypt the new password
        UPDATE Lecturer
        SET SystemPwd = EncryptByKey(Key_GUID('PasswordEncryptionKey'), @NewPassword)
        WHERE ID = USER_NAME();
    END

    -- Close the symmetric key after the operation
    CLOSE SYMMETRIC KEY PasswordEncryptionKey;
END;
GO


-- Permission Management
-- Grant permission to DataAdmin Role
-- Grant DataAdminRole permissions
USE AIS;
GRANT CREATE USER TO DataAdminRole;
GRANT ALTER ANY USER TO DataAdminRole;
GRANT ALTER ANY ROLE TO DataAdminRole
GRANT CONTROL ON DATABASE::AIS TO DataAdminRole;

-- Allow DataAdminRole to perform basic operations 
GRANT SELECT ON AdminUsersView TO DataAdminRole;
GRANT SELECT ON AdminStudentView TO DataAdminRole;
GRANT SELECT ON AdminLecturerView TO DataAdminRole;
GRANT SELECT ON DeletedStudentsBackupView TO DataAdminRole;
GRANT SELECT ON DeletedLecturersBackupView TO DataAdminRole;
GRANT INSERT, DELETE ON Student TO DataAdminRole;
GRANT INSERT, DELETE ON Lecturer TO DataAdminRole;
GRANT SELECT, INSERT, UPDATE, DELETE ON Subject TO DataAdminRole;

-- Allow DataAdminRole to recover deleted data
GRANT EXEC ON sp_RecoverDeletedStudent TO DataAdminRole;
GRANT EXEC ON sp_RecoverDeletedLecturer TO DataAdminRole;
GRANT EXEC ON sp_RecoverDeletedSubject TO DataAdminRole;

-- Prevent DataAdminRole from reading or modifying sensitive information in Student and Lecturer tables
DENY SELECT, UPDATE ON OBJECT::Student(SystemPwd, SensitiveInfo) TO DataAdminRole;
DENY SELECT, UPDATE ON OBJECT::Lecturer(SystemPwd, SensitiveInfo) TO DataAdminRole;
DENY SELECT ON OBJECT:: DeletedStudentsBackup(SystemPwd, SensitiveInfo) TO DataAdminRole;
DENY SELECT ON OBJECT:: DeletedLecturersBackup(SystemPwd, SensitiveInfo) TO DataAdminRole;

-- Deny DataAdminRole any permissions on the Result table (can't read, add, update, or delete student results)
DENY SELECT, INSERT, UPDATE, DELETE ON Result TO DataAdminRole;

-- Deny DataAdminRole the ability to alter objects within dbo schema
DENY ALTER ON SCHEMA::dbo TO DataAdminRole;

-- Ensure that DataAdminRole cannot change or manage database-level audits
DENY ALTER ANY DATABASE AUDIT TO DataAdminRole; 


-- Grant permission to StudentRole
-- Grant access to the symmetric key and certificate (Decryption only)
GRANT CONTROL ON SYMMETRIC KEY::PasswordEncryptionKey TO StudentRole;
GRANT CONTROL ON CERTIFICATE::AISCert TO StudentRole;

-- Grant execute permission on the procedure to the StudentRole (read and update own data)
GRANT EXEC ON sp_StudentSelfInfo TO StudentRole;
GRANT EXEC ON sp_StudentUpdateInfo TO StudentRole;

-- Grant SELECT permission on the view to the StudentRole (view their own results)
GRANT SELECT ON StudentResultView TO StudentRole;

-- Grant SELECT permission on the Subject table
GRANT SELECT ON Subject TO StudentRole;


-- Deny access to Lecturer's data
DENY SELECT ON Lecturer TO StudentRole;

-- Deny access to modify any data in the Student and Result tables except their own details
DENY SELECT, INSERT, UPDATE, DELETE ON Student TO StudentRole;
DENY SELECT, INSERT, UPDATE, DELETE ON Result TO StudentRole;

-- Deny drop permissions to prevent  modifications
DENY ALTER ON DATABASE::AIS TO StudentRole;

-- Grant permissions to LecturerRole
-- Grant access to the symmetric key and certificate
GRANT CONTROL ON SYMMETRIC KEY::PasswordEncryptionKey TO LecturerRole;
GRANT CONTROL ON CERTIFICATE::AISCert TO LecturerRole;

-- Grant EXECUTE permissions on the procedures to manage their own data
GRANT EXECUTE ON sp_LecturerSelfInfo TO LecturerRole;
GRANT EXECUTE ON sp_LecturerUpdateInfo TO LecturerRole;

-- Allow SELECT, INSERT, UPDATE on Result table but restrict lecturers from modifying grades added by others
GRANT SELECT, INSERT, UPDATE ON Result TO LecturerRole;

-- Grant SELECT permission on LecturerStudentView to view student information
GRANT SELECT ON LecturerStudentView TO LecturerRole;
GRANT SELECT ON LecturerView TO LecturerRole;

-- Grant SELECT on Subject table to read subject details
GRANT SELECT ON Subject TO LecturerRole;

-- Deny DELETE permissions on tables to prevent record deletion
DENY DELETE ON Student TO LecturerRole;
DENY DELETE ON Lecturer TO LecturerRole;
DENY DELETE ON Result TO LecturerRole;

-- Prevent LecturerRole from reading or modifying sensitive information in Student and Lecturer tables
DENY SELECT, UPDATE ON OBJECT::Student(SystemPwd, SensitiveInfo) TO LecturerRole;
DENY SELECT, UPDATE ON OBJECT::Lecturer(SystemPwd, SensitiveInfo) TO LecturerRole;

-- Deny DROP permissions to prevent dropping objects
DENY ALTER ON DATABASE::AIS TO LecturerRole;

-- View Permissions for All Roles
SELECT 
    pr.name AS RoleName,
    pe.class_desc,
    pe.permission_name,
    pe.state_desc
FROM 
    sys.database_permissions pe
JOIN 
    sys.database_principals pr
ON 
    pe.grantee_principal_id = pr.principal_id
WHERE 
    pr.name IN ('DataAdminRole', 'LecturerRole', 'StudentRole')
ORDER BY 
    pr.name, pe.permission_name;
GO


-- Section 10: Demo Testing
-- Test Super Admin
-- show permissions given to all roles
EXECUTE AS LOGIN = 'sa';

SELECT 
    pr.name AS RoleName,
    pe.class_desc,
    pe.permission_name,
    pe.state_desc
FROM 
    sys.database_permissions pe
JOIN 
    sys.database_principals pr
ON 
    pe.grantee_principal_id = pr.principal_id
WHERE 
    pr.name IN ('DataAdminRole', 'LecturerRole', 'StudentRole')
ORDER BY 
    pr.name, pe.permission_name;
GO


-- show the members of each role
SELECT 
    dp.name AS RoleName,  -- Role name
    mp.name AS MemberName  -- User assigned to the role
FROM 
    sys.database_role_members drm
JOIN 
    sys.database_principals dp ON drm.role_principal_id = dp.principal_id
JOIN 
    sys.database_principals mp ON drm.member_principal_id = mp.principal_id
WHERE 
    dp.name IN ('DataAdminRole', 'LecturerRole', 'StudentRole')  -- Specify the roles you want to check
ORDER BY 
    dp.name, mp.name;
GO

-- view all data
SELECT * FROM Student;
SELECT * FROM Lecturer;
SELECT * FROM Subject;
SELECT * FROM Result;
GO

-- view login audit log
SELECT event_time, action_id, succeeded, server_principal_name, session_id
FROM sys.fn_get_audit_file('/var/opt/mssql/audit_logs/login_audit/*.sqlaudit', DEFAULT, DEFAULT)
ORDER BY event_time DESC;
GO

-- view ddl audit log
SELECT event_time, action_id, succeeded, object_name, statement, server_principal_name, session_id
FROM sys.fn_get_audit_file('/var/opt/mssql/audit_logs/ddl_audit/*.sqlaudit', DEFAULT, DEFAULT)
ORDER BY event_time DESC;
GO

-- view dml audit log
SELECT event_time, action_id, succeeded, object_name, statement, server_principal_name, session_id
FROM sys.fn_get_audit_file('/var/opt/mssql/audit_logs/dml_audit/*.sqlaudit', DEFAULT, DEFAULT)
ORDER BY event_time DESC;
GO

-- view dcl audit log
SELECT event_time, action_id, succeeded, object_name, statement, server_principal_name, session_id
FROM sys.fn_get_audit_file('/var/opt/mssql/audit_logs/dcl_audit/*.sqlaudit', DEFAULT, DEFAULT)
ORDER BY event_time DESC;
GO



Use AIS;
-- Test Data Admin
EXECUTE AS USER = 'Admin1';

-- Add Student
-- Open Symmetric Key to encrypt the password
OPEN SYMMETRIC KEY PasswordEncryptionKey DECRYPTION BY CERTIFICATE AISCert;

-- Insert a new student into the Student table with a temporary default password
INSERT INTO Student (ID, SystemPwd, Name, Phone, SensitiveInfo, CreatedBy, CreatedDate)
VALUES 
    ('S0003', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'TempPassword@123')),
     'John Doe', '0123456789', 'Address: 123 Main St, KL', SYSTEM_USER, GETDATE()),

	 ('S0004', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'TempPassword@123')),
     'Daniel', '0120001111', 'Address: 456 Main St, KL', SYSTEM_USER, GETDATE()),

	 ('S0005', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'TempPassword@123')),
     'Clara', '0164444333', 'Address: 789 Main St, KL', SYSTEM_USER, GETDATE());

-- Close the Symmetric Key
CLOSE SYMMETRIC KEY PasswordEncryptionKey;

-- Open Symmetric Key to encrypt the password
OPEN SYMMETRIC KEY PasswordEncryptionKey DECRYPTION BY CERTIFICATE AISCert;

-- Insert a new lecturer into the Lecturer table with a temporary default password
INSERT INTO Lecturer (ID, SystemPwd, Name, Phone, Department, SensitiveInfo, CreatedBy, CreatedDate)
VALUES 
    ('L0003', EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'TempPassword@123')),
     'Dr. Jane Smith', '0198765432', 'Biology', 'Address: 456 Elm St, KL', SYSTEM_USER, GETDATE());

-- Close the Symmetric Key
CLOSE SYMMETRIC KEY PasswordEncryptionKey;

-- Create database user for student
CREATE USER S0003 WITHOUT LOGIN;

-- Create database user for lecturer
CREATE USER L0003 WITHOUT LOGIN;

-- Add the student to the StudentRole
ALTER ROLE StudentRole ADD MEMBER S0003;

-- Add the lecturer to the LecturerRole
ALTER ROLE LecturerRole ADD MEMBER L0003;

-- Check if new users have been created
SELECT name AS UserName, type_desc AS UserType, create_date
FROM sys.database_principals
WHERE name IN ('S0003', 'L0003');

-- Insert a new subject into the Subject table
INSERT INTO Subject (Code, Title)
VALUES ('ENG02', 'Advanced English');

SELECT * FROM Subject;

-- Update an existing subject in the Subject table
UPDATE Subject
SET Title = 'English 102'
WHERE Code = 'ENG02';

SELECT * FROM Subject;

-- delete any data
-- Delete a subject from the Subject table
DELETE FROM Subject
WHERE Code = 'ENG02';
SELECT * FROM Subject;

DELETE FROM Student
WHERE ID = 'S0005';
SELECT * FROM AdminStudentView;

SELECT * FROM DeletedSubjectsBackup;
SELECT * FROM DeletedStudentsBackupView;

-- Recover deleted data from DeletedSubjectsBackup to Subject table
INSERT INTO Subject (Code, Title)
SELECT Code, Title
FROM DeletedSubjectsBackup
WHERE Code = 'ENG02';

-- Will throw an error
-- Read students and lecturer password
SELECT SystemPwd FROM Student;
SELECT SystemPwd FROM Lecturer;

-- Update Student Password
OPEN SYMMETRIC KEY PasswordEncryptionKey DECRYPTION BY CERTIFICATE AISCert;
UPDATE Student
SET SystemPwd = EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'NewPassword123!'))
WHERE ID = 'S0001';
CLOSE SYMMETRIC KEY PasswordEncryptionKey;

-- Update Lecturer Password
OPEN SYMMETRIC KEY PasswordEncryptionKey DECRYPTION BY CERTIFICATE AISCert;
UPDATE Lecturer
SET SystemPwd = EncryptByKey(Key_GUID('PasswordEncryptionKey'), CONVERT(NVARCHAR(100), 'NewPassword123!'))
WHERE ID = 'L0001';
CLOSE SYMMETRIC KEY PasswordEncryptionKey;

-- View Result
SELECT * FROM Result;
-- Add new Result
INSERT INTO Result (StudentID, LecturerID, SubjectCode, AssessmentDate, Grade)
VALUES 
	('S0002', 'L0002', 'ENG02', '2024-07-10', 'C');

-- Update Result
UPDATE Result
SET Grade = 'B'
WHERE StudentID = 'S0002' AND LecturerID = 'L0002' AND SubjectCode = 'ENG02';
GO

REVERT;


-- Test Lecturer
EXECUTE AS USER = 'L0001';
-- View own details
EXEC sp_LecturerSelfInfo;
-- Update own details
EXEC sp_LecturerUpdateInfo @Phone = '01122223333';
EXEC sp_LecturerSelfInfo;
-- View result
SELECT * FROM Result;
-- Add new result
INSERT INTO Result (StudentID, LecturerID, SubjectCode, AssessmentDate, Grade)
VALUES ('S0001', 'L0001', 'PHY01', '2024-09-19', 'A'); 
SELECT * FROM Result;

-- Update Own Result
UPDATE Result
SET Grade = 'B'
WHERE StudentID = 'S0001' AND LecturerID = 'L0001' AND SubjectCode = 'PHY01';
GO
SELECT * FROM Result;
-- View Lecturer and Student Data
SELECT * FROM LecturerStudentView;
SELECT * FROM LecturerView;
-- View Subject
SELECT * FROM Subject;

-- Will throw error
-- Update other lecturer data
Update Lecturer
SET Phone = '0123334444'
WHERE ID = 'L0002';
GO
-- Update student's data
Update Student
SET Phone = '0123334444'
WHERE ID = 'S0002';
GO
-- Update result added by other lecturer
UPDATE Result
SET Grade = 'C'
WHERE StudentID = 'S0001' AND LecturerID = 'L0002' AND SubjectCode = 'PHY01';
GO
-- Delete any record from any table
DELETE FROM Result
WHERE StudentID = 'S0001' AND LecturerID = 'L0001' AND SubjectCode = 'PHY01';
GO
-- Drop any object
DROP TABLE Result;

REVERT;


-- Test Student
EXECUTE AS USER = 'S0001';
-- View own info
EXEC sp_StudentSelfInfo;
-- Update own info
EXEC sp_StudentUpdateInfo @Phone = '01199998888';
-- Read own result 
SELECT * FROM StudentResultView;
-- Read subject table
SELECT * FROM Subject;

-- Will throw an error
-- Read lecturer data
SELECT * FROM Lecturer;
-- Read other student data
SELECT * FROM Student;
-- Read other student result
SELECT * FROM Result;
-- Modify other data
UPDATE Result
SET Grade = 'A'
WHERE StudentID = 'S0001' AND LecturerID = 'L0002' AND SubjectCode = 'PHY01';
GO
-- Delete any record
DELETE FROM Result
WHERE StudentID = 'S0001' AND LecturerID = 'L0001' AND SubjectCode = 'PHY01';
GO
-- Drop any object
DROP TABLE Result;

REVERT;
