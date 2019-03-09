
---------------------------  Oracle 11g测试通过 -----------------

-- 开启Oralce数据库审计步骤，该审计只审计普通用户，无审计DBA账户

-- 0.查看是否开启审计，使用DBA用户登录sqlplus
show parameter audit;

	-- 参数解释：
		-- audit_sys_operations  的value为false，意味着数据库审计未开启
		

		
-- 2.配置开启数据库审计	
SQL> alter system set audit_sys_operations=true scope=spfile;
SQL> alter system set audit_trail=db_extended scope=spfile;
	-- 参数解释：
		-- audit_trail 可以配置为 OS \ DB ， spfile未初始化文件参数
		-- DB：将audit trail 记录在数据库的审计相关表中，如aud$，审计的结果只有连接信息；
        -- Extended：这样审计结果里面除了连接信息还包含了当时执行的具体SQL语句；
		-- OS：将audit trail 记录在操作系统文件中，文件名由 audit_file_dest 参数指定；
		-- None：不做审计；
	
-- 3.重启数据库：
SQL> startup force;
	-- 备注： 
		-- SQL> shutdown  immediate ;        			 关闭数据库
		-- SQL>	startup；                                启用数据库
		
-- 4.验证是否成功开启，重复 step0


-- 5.审计粒度配置:
SQL>	audit all on admin.selectiveinfo;			-- 对admin.selectiveinfo表开启审计
SQL>	noaudit select any table by luosongchao;	-- 取消luosongchao账户对所有表的select操作审计
	
	
	
-- 6.查看审计记录：使用DBA账户登录后，查看某一用户的操作记录
SQL> select username, extended_timestamp, sql_text from dba_audit_trail where user name=upper<'lishichang');
	-- 参数解释：
		-- dba_audit_trail 表记录所有非DBA账户的操作记录
		
-----------------------------------------------------------------

-- 配置超时锁定参数	IDLE_TIME 
		
-- 1.查看DEFAULT profile配置：
SQL> select resource_name, limit from dba_profiles where profile='DEFAULT' and resource_type='KERNEL';
-- 2.修改 alter profile 当前使用的profile名 字段名limit 值
SQL> alter profile default limit idle_time 5;




