-------------------------------------------------------------------
-- Filename: 		 oracle_11g.sql
-- Describes：	 Oracle 11g script 
-- Usage:
-- 	Windows：
--			cmd
--			sqlplus / as sysdba
--				SQL>		spool C:\retsql.sql			
--  			SQL>    	@ C:\oracle_11g.sql 
--				SQL>		spool off					
--
--	Linux:	
--			cd /oracle_home
--			sqlplus / as sysdba
--				SQL> 		spool ./retsql.sql
--				SQL> 		@ /opt/oracle/oracle_11g.sql 
--				SQL>		spool off
--
-- v1.0    2018.5

-- 导出 Windows下如 C:\oracle\product\12.1.0\dbhome_1\NETWORK\ADMIN\sqlnet.ora 查看配置
--      Linux下查找路径   find / -name "sqlnet.ora" 
-- 
-- 查看 sqlnet.ora 是否配置了以下参数：
-- 
-- tcp.validnode_checking = yes    -- 激活限制机器访问数据库功能
-- tcp.invited_nodes			   -- 允许访问的ip地址
-- tcp.excluded_nodes=(ip1,ip2,……) -- 不允许访问的ip
-- 修改sqlnet.ora后，重新启动listener服务生效		
-------------------------------------------------------------------------------+


-- Set format for out
set linesize 150
set pagesize 80
col username format a20
col account_status format a20
col password format a20
col CREATED format a20
col USER_ID, format a10
col profile format a20
col resource_name format a35
col limit format a10
col TYPE format a15
col VALUE format a20

col grantee format a25
col owner format a10
col table_name format a10
col grantor format a10
col privilege format a10

col AUDIT_OPTION format a30
col SUCCESS format a20
col FAILURE format a20

col any_path format a100



PROMPT --@@ Oracle version info:
select * from v$version;

PROMPT --@@ All database instances:
select name from v$database;

PROMPT ------------ Identity authentication ----------------------------------------------


PROMPT --@@ 1.Checking user state: 

select username, CREATED, USER_ID, password, profile from dba_users where ACCOUNT_STATUS='OPEN'; 
PROMPT

PROMPT --@@ 2 3.Checking password and attempt login failed strategy:

select username, account_status, profile from dba_users;
PROMPT
select profile, resource_name, limit from dba_profiles where resource_type='PASSWORD';
PROMPT
PROMPT



PROMPT ------------ Access control ----------------------------------------------

PROMPT --@@ All privileged users:
select grantee from dba_role_privs where granted_role='DBA';
PROMPT --@@ 10.Default users grantee roles about grantee='PUBLIC':
select granted_role from dba_role_privs where grantee='PUBLIC';
PROMPT --@@ Checking access of data dictionary must boolean=FALSE!  :
show parameter O7_DICTIONARY_ACCESSIBILITY; 
PROMPT
PROMPT

PROMPT ------------ Syslog and audit ----------------------------------------------


PROMPT --@@ 14.Syslog and Auditstate:
show parameter audit;
PROMPT


PROMPT --@@ 15.Important security events covered by audit:
select AUDIT_OPTION, SUCCESS, FAILURE from dba_stmt_audit_opts;
PROMPT
PROMPT --@@ 19.Protecting audit records:
select grantee, owner, table_name, grantor, privilege from dba_tab_privs where table_name='AUD$';
PROMPT
PROMPT

PROMPT ------------ Resources control ----------------------------------------------


PROMPT --@@ 26.Checking 'IDLE_TIME':
select resource_name, limit from dba_profiles where profile='DEFAULT' and resource_type='KERNEL' and resource_name='IDLE_TIME';

PROMPT --@@ 27.Checking single user resource limit:
select resource_name, limit from dba_profiles where profile='DEFAULT' and resource_type='SESSIONS_PER_USERS';

PROMPT --@@ 28.Checking cpu time limit for a single session:
select resource_name, limit from dba_profiles where profile='DEFAULT' and resource_type='CPU_PER_SESSION';

PROMPT -- Special requirements of other industries ----------------------------------------------

PROMPT -- Has the "Oracle Label Security" been installed? I will determine by looking at whether the "LBACSYS" user has been created or about its database tables.

PROMPT --@@ Whether have username='LBACSYS'
select username, account_status, profile from dba_users where username='LBACSYS';
PROMPT --@@ Something about OWNER='LBACSYS'
select object_type,count(*) from dba_objects where OWNER='LBACSYS' group by object_type;

PROMPT --@@ remote_os_authent:
select value from v$parameter where name='remote_os_authent';
PROMPT

PROMPT --@@ Access control Function:
select any_path from resource_view where any_path like '/sys/acls/%.xml';
PROMPT

PROMPT --@@ Default Account Password (11g):
select * from dba_users_with_defpwd or derby1;
PROMPT

PROMPT --@@ Maximum Number of Connections:
show parameter processes;





