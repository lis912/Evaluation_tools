#!/usr/bin/ksh
 
 
# -----------------------------------------------------------
# Filename:			aix3.sh
# Describe: 		Security check for release AIX linux  
# Usage:			chmod 777 aix3.sh 
#					./aix3.sh.sh &> filename.sh     and shell pathname: #!/usr/bin/sh，so Im not sure……
# v1.0    2018.7
# -----------------------------------------------------------


echo "# ---------------------------------------------------------------------"
echo "# Describe: \t\t This file to check AIX system security configuration" 
echo "# Project name:"
echo "# Server name:"
echo "# ---------------------------------------------------------------------"
echo 


# ************************************ 身份鉴别 ************************************
echo
echo
echo
echo "------------ Identity authentication ----------------------------------------------"
echo
# 是否有空口令 
echo "********* [checking Empty password users:]"
echo "[/etc/passwd:]"
more  /etc/passwd
echo
echo
echo "[/etc/security/passwd:]"
more /etc/security/passwd


# 口令策略和强度
echo
echo
echo "********* [Checking password Strength:]"
echo "[more /etc/security/user:]"
more/etc/security/user

# maxage 为密码使用有效期；
# minage为密码修改期限；
# rlogin 是否可以远程访问此账户；
# Minalpha 密码包含字母字符最小数：
# Minlen：密码的最小长度；
# Minother:密码包含的非字母字符最小数；

echo
echo
# 登录失败策略
echo "********* [Login failure policy:]"
echo "[more /etc/security/login.cfg:]"
more /etc/security/login.cfg

 

# 检查ssh 和 telnet
echo
echo
echo "********* [ssh and telnet server status:]"
ps -ef| grep ssh
ps -ef| grep telnet


# ************************************ 访问控制 ************************************
echo "------------ Access control ----------------------------------------------"
echo
echo
# 访问权限：600合格
echo "********* [Checking some files access permission:]"
ls -l /etc/passwd
ls -l /etc/security/passwd 
ls -l /etc/security/user



# ************************************ 安全审计 ************************************
echo "------------ Secure and Audit ----------------------------------------------"
echo
echo
# 查看是否开启系统日志 审计 进程
echo "********* [Syslog and audit status:]"
ps -ef | grep syslog
ps -ef | grep audit
#ps -ef | grep syslog, audit query

echo
echo
# 记录审计的事件类型 class
echo "********* [To see audit info:]"
echo "[more /etc/security/audit:]"
more /etc/security/audit
echo
echo
# 审计文件中的配置项
echo "********* [To see audit config:]"
echo "[more /etc/syslog.conf:]"
more /etc/syslog.conf
echo
echo
# 默认审计记录文件路径
echo "********* [To see auditlog file info:]"
echo "[more /var/log/audit.d:]"
more /var/log/audit.d

# 查看审计日志的访问权限
echo
echo
echo "********* [ls –l /var/adm/wtmp]"
ls –l /var/adm/wtmp
echo
echo
echo "********* [ls –l /var/adm/sulog]"
ls –l /var/adm/sulog
echo
echo
echo "********* [ls –l /etc/security/failedlogin]"
ls –l /etc/security/failedlogin


# ************************************ 入侵防范 ************************************
echo "------------ Intrusion prevention ----------------------------------------------"
echo
echo
# 查看相关内容，是否记录入侵行为
echo "********* [Checking /var/log/secure grep ‘refused’]"
more /var/log/secure | grep refused
echo
echo
# 查看系统安装的补丁包信息：
echo "********* [Patch information of the system：rpm -qa]"
rpm -qa
echo "********* [Patch information ML：instfix -i|grep ML]"
instfix -i|grep ML
# 检查正在运行的服务，是否有运行无关的进程
echo
echo
echo "********* [Select all service: lsitab -a]"
lsitab -a




# ************************************ 资源控制 ************************************
echo "------------ Resource control ----------------------------------------------"
echo
echo
# 查看配置访问地址的限制策略
echo "********* [IP address permit in hosts.allow and hosts.deny ：]"
echo "[more /etc/hosts.allow:]"
more /etc/hosts.allow
echo
echo

echo "[more /etc/hosts.deny :]"
more /etc/hosts.deny 
echo
echo

# 账户登录是否超时锁定策略  =600s
echo "********* [Login timeout lock, ('TMOUT >= 600s')]"
more /etc/profile | grep -n "TMOUT"

echo
echo
# 系统资源使用率 查看cpu使用率、硬盘使用率、内存使用率等。
echo "********* [System resource used rate: prtconf | more]"
echo
prtconf | more

echo
echo
# 系统对主体使用系统资源的限制配置
echo "********* [Describes system resource limit for a user:]"
echo
echo "[more /etc/security/limits :]"
more /etc/security/limits


# 磁盘使用情况
echo "[disk info:]"
df -h



# 内存使用情况
echo "[Memory info:]"
free -m
echo
echo


