---------------------------------------------------
-- mysql 5.7
--  Method：
-- mysql > tee ./mylog.sql     记录控制台输出
-- mysql > source mys.sql
-- mysql > notee;			   结束记录

-- 导出 mysql系统的配置文件：my.cnf or my.ini
-- 查找my.cnf路径：  find / -name my.cnf
---------------------------------------------------


-- 输出当前时间
select now();
-- 查看版本信息
select version();


-- 查看所有的数据库实例
show databases;


-- 查看是否有空口令
use mysql
show tables;

select user, password,  authentication_string from user;
select * from db;


-- host字段显示是否有限制登录地址
select host, user, password from user;
select host, user from user;


-- 全局下授予的一些权限  
select user, Shutdown_priv, Grant_priv, File_priv from user;
-- 表级别粒度的权限，可能为空，就是没有添加
select * from tables_priv;
-- 列粒度级别 
select * from columns_priv;

-- 删除多余账号
select host, user from user;


-- 超时锁定：
show variables like '%timeout%';

