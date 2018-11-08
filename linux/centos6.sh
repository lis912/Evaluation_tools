#!/bin/bash

# -----------------------------------------------------------
# Filename:			centos6.sh
# Describe: 		Security check centos6.x system
# Usage:			chmod 777 centos7.sh 
#					./centos7.sh &> filename.sh  
# v1.1    2018.6
# -----------------------------------------------------------


echo "# ---------------------------------------------------------------------"
echo -e "# Describe: \t\t This file to check system security configuration" 
echo -e "# Running time:\t\t "`date +'%Y-%m-%d %H:%S'`
echo "# Project name:"
echo "# Server name:"
echo "# ---------------------------------------------------------------------"
echo

sysversion=`ifconfig | grep "inet addr"`
if [ ! -n "$sysversion" ]; then
	# 7.x
	Ipddr=`ifconfig | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}'`
else
	# 6.x
	Ipddr=`ifconfig | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}' | awk -F: '{print $2}'`
fi

# 系统软硬件摘要
echo "********* [System Info:] *********"
echo -e "Server platform: \t"`grep 'DMI' /var/log/dmesg`
echo -e "CPU model: \t"`cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq`
echo -e "CPUS: \t\t\t\t" `cat /proc/cpuinfo | grep processor | wc -l | awk '{print $1}'`
echo -e "CPU Type: \t\t\t" `cat /proc/cpuinfo | grep vendor_id | tail -n 1 | awk '{print $3}'`
Disk=$(fdisk -l |grep 'Disk' |awk -F , '{print $1}' | sed 's/Disk identifier.*//g' | sed '/^$/d')
echo -e "Disks info:\t\t\t ${Disk}\n${Line}"
echo -e "System Version: \t" `more /etc/redhat-release`
echo -e "Hostname: \t\t\t" `hostname -s`
echo -e "IP Address: \t\t ${Ipddr}" 

# ************************************ 身份鉴别 ************************************
echo
echo
echo
echo "------------ Identity authentication ----------------------------------------------"
echo
# 是否有空口令 
echo "********* [checking Empty password users:]"


flag=
null_password=`awk -F: 'length($2)==0 {print $1}' /etc/shadow`
if [ ! -n "$null_password" ]; then
	flag=
else
	flag='y'
	echo $null_password
fi


null_password=`awk -F: 'length($2)==0 {print $1}' /etc/passwd`
if [ ! -n "$null_password" ]; then
	flag=
else
	flag='y'
	echo $null_password
fi


null_password=`awk -F: '$2=="!" {print $1}' /etc/shadow`
if [ ! -n "$null_password" ]; then
	flag=
else
	flag='y'
	echo $null_password
fi


null_password=`awk -F: '$2!="x" {print $1}' /etc/passwd`
if [ ! -n "$null_password" ]; then
	flag=
else
	flag='y'
	echo $null_password
fi


if [ ! -n "$flag" ]; then
	echo  "[Y] This system no empty password users!"
fi 
echo
echo

echo
echo
# 密码策略
echo "********* [Password policy:]"
cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print "PASS_MAX_DAYS = "$2}'
cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print "PASS_MIN_DAYS = "$2}'
cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print "PASS_MIN_LEN = "$2}'
cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# | awk '{print "PASS_WARN_AGE = "$2}'

echo
echo
# 口令强度
echo "********* [Checking password Strength:]"
# 查看是否安装了 pam_cracklib.so 模块
echo "[Is pam_cracklib.so installed?] "
rpm -qa | grep cracklib
echo
echo "[Check pam_cracklib.so for password Strength:] "
more /etc/pam.d/system-auth | grep -E 'pam_cracklib.so'
# pam_cracklib.so 包字段定义：
#
# retry=3       定义登录/修改密码失败时，可以重试的次数；
# type=xxx      当添加/修改密码时，系统给出的缺省提示符是什么，用来修改缺省的密码提示文本。默认是不修改的，如上例。
# minlen=8      定义用户密码的最小长度为8位
# ucredit=-2    定义用户密码中最少有2个大写字母(数字为负数，表示至少有多少个大写字母；数字为正数，表示至多有多少个大写字母；下面同理)
# lcredit=-4    定义用户密码中最少有4个小写字母
# dcredit=-1    定义用户密码中最少有1个数字
# ocredit=-1    定义用户密码中最少有1个特殊字符（除数字、字母之外）
# remember=5    修改用户密码时最近5次用过的旧密码就不能重用了

echo
echo
# 登录失败策略
echo "********* [Login failure policy:]"

# 检查系统是否存在pam_tally2.so模块：
echo "[pam_tally2.so pathname:] "
find /lib* -name "pam_tally*"
echo
echo "[Check pam_tally.so for login failure policy:] "
# 查看系统登录失败的策略
login_failure=`more /etc/pam.d/system-auth | grep tally`
if [ ! -n "$login_failure" ]; then
	echo  " [X] Warning: This system no login failure policy!"
else
	echo $login_failure
fi


# pam_tally.so 包字段定义：
# deny  		 指定最大几次认证错误，如果超出此错误，将执行后面的策略
# lock_time  	 锁定多长时间，按秒为单位；
# unlock_time 	 指定认证被锁后，多长时间自动解锁用户；
# no_magic_root  如果用户uid＝0（即root账户或相当于root的帐户）在帐户认证时调用该模块发现失败时，不计入统计；
# even_deny_root root用户在认证出错时，一样被锁定
# root_unlock_time  root用户在失败时，锁定多长时间。该选项一般是配合even_deny_root 一起使用的。
echo
echo


# ************************************ 访问控制 ************************************
echo "------------ Access control ----------------------------------------------"
echo
echo
# 密码过期账户
echo "********* [Password time out users:]"
awk -F: '$2=="!!" {print $1}' /etc/shadow
echo
echo
# 多余账户 
# 对多余帐户进行删除、锁定或禁止其登录如：uucp、nuucp、
# lp、adm、sync、shutdown、halt、news、operator、gopher用户
echo "********* [May be No need users:]"
cat /etc/shadow | grep -E 'uucp|nuucp|lp|adm|sync|shutdown|halt|news|operator|gopher' | awk -F: '{print $1}'
echo

# 访问权限：600合格
echo "********* [Checking shadow and passwd access permission:]"
ls -l /etc/shadow
ls -l /etc/passwd
echo
echo

# 查看 telnet, ftp, ssh启动状态
echo "********* [Checking telnet and ftp status:]"
telnet_status=`netstat -an | grep -E 'telnet | ftp'`
if [ ! -n "$telnet_status" ]; then
	flag=
else
	flag='y'
	echo $telnet_status
fi


telnet_status=`chkconfig --list | grep -E 'telnet | ftp'`
if [ ! -n "$telnet_status" ]; then
	flag=
else
	flag='y'
	echo $telnet_status
fi

if [ ! -n "$flag" ]; then
	echo  "[Y] This system no open 'telnet, ftp' server!"
fi
echo

# 强制访问控制
echo "********* [Mandatory access control:]"
# 查看配置文件 cat /etc/selinux/config， SELINUX=enforcing(强制开启强制访问控制)
cat /etc/selinux/config
echo
echo

# 查看当前进程的域(domin)的信息
echo "[SElinux some subjects domin configuration:]"
echo
ps -eZ | head -n 10
echo
echo
# 查看文件上下文(context)信息
echo "[SElinux object context configuration:]"
ls -Z / | head -n 10
echo
echo


# ************************************ 安全审计 ************************************
echo "------------ Secure and Audit ----------------------------------------------"
echo
echo
# 查看是否开启系统日志 审计 进程
echo "********* [Syslog and audit status:]"
service --status-all | grep rsyslogd
service auditd status
echo
echo
# 查看审计规则
echo "[audit rules:]" `auditctl -l`
echo
echo
# 审计日志的内容
echo "********* [To see the first 10 rows of ‘/var/log/secure’:]"
logfile=`ls /var/log/ | grep -E 'secure-.*'| tail -n 1`
cat /var/log/${logfile} | tail -n 10
echo
echo
# 审计记录的保护
echo "********* [Files Permission for about syslog and audit:]"
ls -l /var/log/messages
ls -l /var/log/secure
ls -l /var/log/audit/audit.log
echo
echo


# ************************************ 入侵防范 ************************************
echo "------------ Intrusion prevention ----------------------------------------------"
echo
echo
# 检查正在运行的服务，是否有运行无关的进程
echo "********* [Select all running service:]"
service --status-all | grep running
echo
echo
# 查看系统安装的补丁包信息：
echo "********* [Patch information of the system：]"
rpm -qa --last | grep patch
echo
echo


# ************************************ 资源控制 ************************************
echo "------------ Resource control ----------------------------------------------"
echo
echo

# ssh服务端配置：设置禁止直接以超级用户ssh登录
echo "********* [SSHD PermitRootLogin ：]"
more /etc/ssh/sshd_config | grep PermitRootLogin
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

# 查看防火墙状态策略
echo "********* [Checking iptables status ：]"
service iptables status
echo
echo
# 账户登录是否超时锁定策略  =600s
echo "********* [Login timeout lock, ('TMOUT >= 600s')]"
TMOUT=`more /etc/profile | grep -n "TMOUT"`
if [ ! -n "$TMOUT" ]; then
	flag=
	echo  "[X] Warning: This system no set TMOUT!"
else
	echo $TMOUT
fi


echo
echo
# 系统对主体使用系统资源的限制配置
echo "********* [Describes system resource limit for a user:]"
echo
echo "<domain> <type> <item> <value>"
more /etc/security/limits.conf | grep -v ^# 
echo
echo

# 系统资源使用率

echo "********* [System resource used rate:]"
echo

# 磁盘使用情况
echo "[disk info:]"
df -h
echo
echo

# 内存使用情况
echo "[Memory info:]"
free -m
echo
echo

# 内存使用率
echo "mem_used_rate = "  `free -m|awk '{if(NR==2){print int($3*100/$2),"%"}}'`
# CPU使用率
cpu_used=`top -b -n 1 | head -n 4 | grep "^Cpu(s)" | awk '{print $2}' | cut -d 'u' -f 1`
echo "cpu_used_rate = " $cpu_used
echo

echo "********* [Cat files: /etc/passwd:]"
more /etc/passwd
echo
echo
echo "********* [Cat files: /etc/shadow:]"
more /etc/shadow

