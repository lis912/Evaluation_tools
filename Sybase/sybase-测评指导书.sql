

-- 在unix环境下切换
su – sybase


-- 登录：如果环境变量没有isql命令，需要进入相关的bin目录下，servername即主机名 -U 默认sa用户，-P口令
isql -Usa -P<password or leave it blank> -Sservername

-- 0 查看版本：
1> select @@version

-- 例如：
Adaptive Server Enterprise/15.7.0/EBF 19805 SMP ESD#01 /P/x86_64/Enterprise Lin
	 ux/aseasap/2918/64-bit/FBO/Wed Feb  8 07:50:28 2012 

-- 查看所有的库信息(系统库：master，model，sybsystemdb，sybsystemprocs，tempdb)
1> sp_helpdb
2> go


-- 进入一个库
use 库名	 
	
-- 显示当前库下所有的表名
select name from sysobjects where type='U'
或者
sp_tables
	
	 

-- 1.查看账户状态
1> sp_helpuser
2> go

Users_name		ID_in_db		Group_name		Login_name                                         
---------	 	---------		---------		---------
 dbo             public          1                 	sa                        
guest            public          2              	NULL
probe	         public          3               	probe      
                                                                    
	                                   
-- 2.1 口令策略： systemwide password expiration(密码最大有效期天数=90，符合)
1> sp_configure "systemwide password expiration"
2> go

Parameter Name					Default		Memory Used		Config Value	Run Value	Unit		Type
------------------				---------	---------		---------		---------	---------	---------	
systemwide password expiration		0			0			0				0			days		dynamic
  

-- 	2.2 口令策略： check password for digit(是否启用检查口令中至少有一位数字字符=1，符合) 
1> sp_configure "check password for digit"
2> go

Parameter Name					Default		Memory Used		Config Value	Run Value	Unit		Type
------------------				---------	---------		---------		---------	---------	---------	
check password for digit		0			0				0				0			switch		dynamic


-- 	2.3 口令策略： minimum password length(最小口令长度=8，符合) 
1> sp_configure "minimum password length"
2> go

Parameter Name					Default		Memory Used		Config Value	Run Value	Unit		Type
------------------				---------	---------		---------		---------	---------	---------	
minimum password length			6			6				6				6			bytes		dynamic




-- 3. 登录失败策略： maximum failed logins(最大登录失败允许次数!= 0, 符合)
1> select name,value from master.dbo.sysconfigures where name='maximum failed logins'
2> go

name						value
-------						-------
maximum failed logins		0


-- 4. 远程加密设置,查看 status=net password encryption(启用RSA加密算法对网络连接进行加密，符合)
1> sp_helpserver
2> go


									   
-- 5.1 登录失败审计，log audit logon failure(登录失败审计=1，启用，符合)
1> sp_configure "log audit logon failure"
2> go 

	
-- 5.2 登录成功审计，log audit logon success(登录失败审计=1，启用，符合)
1> sp_configure "log audit logon success"
2> go	


-- 5.3 是否使能审计功能，auditing=1，启用，符合
1> use master
2> go
1> sp_configure "auditing"
2> go


-- 5.4 审计配置策略，如果未开启审计，将不存在sybsecurity库，执行sql语句报错。
1> use sybsecurity
2> go
-- 如果存在sybsecurity库，查看审计策略，查看是否开启Logins、create、delete、drop等动作行为的审计
1> sp_displayaudit		
2> go									   

								 
								 
-- 5.5 查看审计记录表信息，当然如果审计开启了的话，不存在报错。								 
1> select * from AuditTable
2> go						 
								 
								 
-- 5.6 查询审计存储空间，audit queue size(审计内存队列大小>50，默认为100，大约42K)
1> sp_configure "audit queue size"
2> go
	
	

