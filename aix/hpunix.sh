#!/sbin/sh


# -----------------------------------------------------------
# Filename:			hpunix.sh
# Describe: 		Security check for release hp-unix  
# Usage:			chmod 777 hpunix.sh
#					./hpunix.sh &> filename.sh
# v1.0    2018.7
# -----------------------------------------------------------


echo "# ---------------------------------------------------------------------"
echo -e "# Describe: \t\t This file to check system security configuration" 
echo -e "# Running time:\t\t "`date +'%Y-%m-%d %H:%S'`
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
echo "********* [Cat files: /etc/passwd:]"
more /etc/passwd
echo
echo
echo "********* [Cat files: /etc/shadow:]"
more /etc/shadow
echo
echo
echo "********* [Cat files: /etc/group:]"
more /etc/group
# 密码策略 和登录失败策略 都是在 /etc/default/security
echo
echo
echo "********* [Password policy : more /etc/default/security]"
more /etc/default/security


# 检查ssh 和 telnet
echo
echo
echo "********* [ssh and telnet server status:]"
ps -elf| grep ssh
ps -elf| grep telnet
ps -elf| grep ftp




# ************************************ 访问控制 ************************************
echo "------------ Access control ----------------------------------------------"
echo
echo
# 访问权限：600合格
echo "********* [Checking some files access permission:]"
ls -l /etc/passwd
ls -l /etc/shadow
ls -l /etc/syslog.conf




# ************************************ 安全审计 ************************************
echo "------------ Secure and Audit ----------------------------------------------"
echo
echo
# 查看是否开启系统日志 审计 进程
echo "********* [Syslog and audit status:]"
ps -ef | grep syslog
ps -ef | grep audit
echo
echo
# 日志配置信息
echo "********* [To see syslog config more /etc/syslog.conf:]"
more /etc/syslog.conf
echo
echo


# ************************************ 入侵防范 ************************************
echo "------------ Intrusion prevention ----------------------------------------------"
echo
echo
# 查看系统安装的补丁包信息：
echo "********* [Patch information of the system：swlist -l bundle]"
swlist -l bundle

echo
echo
echo "********* [more /etc/inetd.conf：]"
more /etc/inetd.conf


# 检查正在运行的服务，是否有运行无关的进程
echo
echo
echo "********* [Select all service:]"
ps -ef


# ************************************ 资源控制 ************************************
echo "------------ Resource control ----------------------------------------------"
echo
echo
# 查看配置访问地址的限制策略
echo "********* [IP address permit in hosts.allow and hosts.deny ：]"
echo "[more /etc/securetty:]"
more /etc/securetty
echo
echo

echo "[more /etc/adm/inetd.sec :]"
more /etc/adm/inetd.sec
echo
echo

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



# 系统对主体使用系统资源的限制配置
echo
echo
echo "********* [Describes system resource limit for a user:ulimit -a]"
echo
ulimit -a



# 磁盘使用情况
echo "[disk info:]"
df -h


# 内存使用情况
echo "[Memory info:]"
free -m
echo
echo



