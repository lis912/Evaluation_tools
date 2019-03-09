#!/bin/bash

# -----------------------------------------------------------
# Filename:			suse.sh
# Describe: 		Security check for release SUSE linux 
# Usage:			chmod 777 suse.sh 
#					./suse.sh &> filename.sh
# v1.0    2018.10
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
echo -e "Server platform: \t"`grep 'DMI' /var/log/boot.msg`
echo -e "CPU model: \t"`cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq`
echo -e "CPU Type: \t\t\t" `cat /proc/cpuinfo | grep vendor_id | tail -n 1 | awk '{print $3}'`
echo -e "CPUS: \t\t\t\t" `cat /proc/cpuinfo | grep processor | wc -l | awk '{print $1}'`
Disk=$(fdisk -l |grep 'Disk' |awk -F , '{print $1}' | sed 's/Disk identifier.*//g' | sed '/^$/d')
echo -e "Disks info:\t\t\t ${Disk}\n${Line}"
echo -e "System Version: \t" `lsb_release -a | grep Description`
echo -e "Hostname: \t\t\t" `hostname -s`
echo -e "IP Address: \t\t ${Ipddr}" 
echo
echo

# 密码策略
echo "********* [Password policy:]"
cat /etc/login.defs | grep PASS | grep -v ^#
echo
echo

# 口令复杂度和登录失败策略
cat /etc/pam.d/common-auth | grep -v ^#
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
echo
echo

# 强制访问控制,如果未安装SElinux，则会命令报错
echo "********* [Mandatory access control:]"
sestatus -v
echo
echo

# 查看是否开启系统日志 审计 进程
echo "********* [Syslog and audit status:]"
service syslog status
service auditd status
echo
echo
# 查看审计规则
echo "[audit rules:]" `auditctl -l`
echo
echo

# 审计记录的保护
echo "********* [Files Permission for about syslog and audit:]"
ls -l /var/log/audit
echo
echo


# 查看系统安装的补丁包信息：
echo "********* [Patch information of the system：]"
rpm -qa --last | grep patch
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
more /etc/hosts.allow | grep -v ^#
echo
echo

echo "[more /etc/hosts.deny :]"
more /etc/hosts.deny | grep -v ^#
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
echo
echo "********* [Cat files: /etc/passwd:]"
more /etc/passwd
echo
echo
echo "********* [Cat files: /etc/shadow:]"
more /etc/shadow
echo
echo
# 检查正在运行的服务，是否有运行无关的进程
echo "********* [Select all running service:]"
service --status-all | grep running
echo
echo
