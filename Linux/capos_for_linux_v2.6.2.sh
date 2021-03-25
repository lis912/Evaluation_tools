#!/bin/sh
#============================================================================   
# 作者:  		李世昌     
# 邮箱:  		lis912@163.com 
# 更新时间:  	2020.11
# 版本:  		v2.6.2
#
# 描述:  		等级保护安全基线配置检查脚本，兼容Red-Hat、CentOS、EulerOS、Asianux、Ubuntu 16、Oracle、Mysql、Postgresql。
#		
# 使用方法： 	建议在root权限下将本脚本导入/tmp目录下执行，可通过 >> 重定向到其他文件后，导出查看。
#		sh capos_for_linux.sh_2.6.2.sh -a    		自动核查；
#		sh capos_for_linux.sh_2.6.2.sh -l    		信息收集；
#		sh capos_for_linux.sh_2.6.2.sh -o    		Oracle数据库核查；
#		sh capos_for_linux.sh_2.6.2.sh -pgsql  		Postgresql数据库核查；
#		sh capos_for_linux.sh_2.6.2.sh -m           Mysql数据库核查，会提示输出root账户口令，输入后回车开始核查，也可以输入字母 q 退出Mysql数据库核查；
#		sh capos_for_linux.sh_2.6.2.sh -h           -h 或其他错误参数显示帮助提示信息。
#
#
# 更新记录：  
#	v2.6.2 
#		1) redhat_or_centos_ceping方法中增加了对 /etc/pam.d/sshd 中登录失败模块的检查；
#  		2) redhat_or_centos_ceping方法中增加了对Red-Hat7版本 /etc/security/pwquality.conf 口令复杂度配置文件的检查；
#		3) 注释中修改并添加了用法信息，更新记录,并对功能方法简单介绍。
#
#============================================================================

# 全局变量
# 系统版本
DISTRO=
# 系统版本号
DISTRO_NUMBER=

# 是否运行有Oracle数据
ORACLE=
# Orcle版本号
ORACLE_NUMBER=

# 是否运行有Mysql数据
MYSQL=
# Mysql版本号
MYSQL_NUMBER=

# 是否运行有Postgresql数据
PGSQL=
# Postgresql版本号
PGSQL_NUMBER=

# 数据库种类汇总
DBS=

# WEB容器版本
WEBSERVER=
# WEB容器版本
WEBSERVER_NUMBER=

# 提示信息颜色预设变量
SETCOLOR_SUCCESS="echo -en \\033[1;32m"
SETCOLOR_FAILURE="echo -en \\033[1;31m"
SETCOLOR_WARNING="echo -en \\033[1;33m"
SETCOLOR_NORMAL="echo -en \\033[0;39m"
time=`date +['%Y-%m-%d %H:%M:%S']`
# 普通信息
LogMsg()
{
        echo "$time INFO: $*" 
        $SETCOLOR_NORMAL
}
# 告警信息
LogWarnMsg()
{
        $SETCOLOR_WARNING
        echo "$time WARN: $*" 
        $SETCOLOR_NORMAL
}
# 成功信息
LogSucMsg()
{     
        $SETCOLOR_SUCCESS
        echo "$time SUCCESS: $*"      
        $SETCOLOR_NORMAL
}
# 错误信息
LogErrorMsg()
{
        $SETCOLOR_FAILURE
        echo "$time ERROR: $*"
        $SETCOLOR_NORMAL
}

#----------------------------------------------------------------------------
# 重定向文件头部文件描述信息
#----------------------------------------------------------------------------
output_file_banner()
{
	echo "# ============================================================================"
	echo -e "# Describe: \t\t This file about security baseline check output" 			
	echo -e "# Running time:\t\t "`date +'%Y-%m-%d %H:%M'`
	echo "# ============================================================================"
	echo
}

#----------------------------------------------------------------------------
# LOGO输出，美化作用
#----------------------------------------------------------------------------
print_logo()
{
cat <<EOF

 ██████╗ █████╗ ██████╗  ██████╗ ███████╗  {v2.6.2 2020.11} 
██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝
██║     ███████║██████╔╝██║   ██║███████╗
██║     ██╔══██║██╔═══╝ ██║   ██║╚════██║
╚██████╗██║  ██║██║     ╚██████╔╝███████║
 ╚═════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝   
            		        

EOF
}

#----------------------------------------------------------------------------
# 脚本帮助提示信息
#----------------------------------------------------------------------------
helpinfo()
{
cat <<EOF
"Usage: $0 [OPTION] [PARAMETER]"
	
${0} -h				=> view usage methods.
${0} -l				=> show information collection.
${0} -o				=> oracle check.
${0} -m [password]			=> mysql check.
${0} -pgsql			=> postgresql check.
${0} -s				=> webserver check.
${0} -a				=> auto check.

EOF
}

#----------------------------------------------------------------------------
# 获取操作系统版本信息: DISTRO->系统类型 ,DISTRO_NUMBER->版本号
#----------------------------------------------------------------------------
get_system_version()
{
	if grep -Eqii "CentOS" /etc/issue || grep -Eq "CentOS" /etc/*-release; then
        DISTRO='CentOS'
		if grep -Eq "7\." /etc/*-release; then
			DISTRO_NUMBER='7'
		elif grep -Eq "6\." /etc/*-release; then
			DISTRO_NUMBER='6'
		elif grep -Eq "5\." /etc/*-release; then
			DISTRO_NUMBER='5'
		elif grep -Eq "4\." /etc/*-release; then
			DISTRO_NUMBER='4'
		else
			DISTRO_NUMBER='unknow'
		fi	
    elif grep -Eqi "Red Hat Enterprise Linux Server" /etc/issue || grep -Eq "Red Hat Enterprise Linux Server" /etc/*-release || grep -Eq "Asianux" /etc/*-release; then
        DISTRO='RedHat'
		if grep -Eq "7\." /etc/*-release; then
			DISTRO_NUMBER='7'
		elif grep -Eq "6\." /etc/*-release; then
			DISTRO_NUMBER='6'
		elif grep -Eq "5\." /etc/*-release; then
			DISTRO_NUMBER='5'
		elif grep -Eq "4\." /etc/*-release; then
			DISTRO_NUMBER='4'
		else
			DISTRO_NUMBER='unknow'
		fi
	elif grep -Eq "EulerOS" /etc/*-release; then
        DISTRO='EulerOS'
		DISTRO_NUMBER='7'
    elif grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then
        DISTRO='Ubuntu'	
	elif [[ -n `uname -a | grep AIX` ]]; then 
		DISTRO='AIX'
		DISTRO_NUMBER=`oslevel`
    else
        DISTRO='unknow'
    fi
}

#----------------------------------------------------------------------------
# 获取WEB容器版本信息:WEBSERVER->类型, WEBSERVER_NUMBER->版本号
#----------------------------------------------------------------------------
get_webserver_info()
{
	[[ -n `whereis nginx | awk -F: '{print $2}'` ]] && WEBSERVER="nginx" && WEBSERVER_NUMBER=$(nginx -v | awk -F/ '{print $2}')
	[[ -n `lastlog | grep weblogic` ]] && [[ -n `netstat -pantu | grep ':7001'` ]] && WEBSERVER="weblogic" 
	[[ -n `cat /etc/passwd | grep apache` ]] && [[ -n `netstat -pantu | grep ':80' | grep 'httpd'` ]] && WEBSERVER="apache" && WEBSERVER_NUMBER=$(apachectl -v | awk -F/ '{print $2}' | grep -v ^$)
}

#----------------------------------------------------------------------------
# 获取数据库类型和版本信息：识别后所属全局变量 ORACLE MYSQL PGSQL 会进行赋值
#----------------------------------------------------------------------------
get_database_version()
{
	if [[ -n `netstat -pantu | grep tnslsnr` ]]; then
		ORACLE="Oracle"
		banner=`su - oracle << EOF 
sqlplus / as sysdba 
exit 
EOF`

		[[ $banner =~ "11g" ]] && ORACLE_NUMBER="11g"
		[[ $banner =~ "10g" ]] && ORACLE_NUMBER="10g"
		[[ $banner =~ "12c" ]] && ORACLE_NUMBER="12c"
	fi

	if [[ -n `netstat -pantu | grep mysqld` ]]; then
		MYSQL="Mysql"
		MYSQL_NUMBER=`mysql -V | awk '{print $5}'`
		MYSQL_NUMBER=${MYSQL_NUMBER%?}
	fi
	
	if [[ -n `netstat -pantu | grep postgres` ]]; then
		PGSQL="PostgreSQL"
		PGSQL_NUMBER=`su - postgres << EOF 
psql -d postgres -U postgres -At -c "select version();" | awk '{print $2}'
exit 
EOF`
PGSQL_NUMBER=`echo ${PGSQL_NUMBER} | awk '{print $2}'`	
	fi
	
	DBS="${ORACLE} ${ORACLE_NUMBER}	${MYSQL} ${MYSQL_NUMBER} ${PGSQL} ${PGSQL_NUMBER}"
	
	[[ -n `netstat -pantu | grep 'redis'` ]] && DBS="${DBS} Redis"
	[[ -n `netstat -pantu | grep mongodb` ]] && DBS="${DBS} Mongodb"
}

#----------------------------------------------------------------------------
# Redhat系操作系统信息收集
#----------------------------------------------------------------------------
redhat_info_collection()
{
	echo
	echo "-------------------------------- Information Collection start --------------------------------"
	echo
	echo -e "Hardware platform: \t"`grep 'DMI' /var/log/dmesg | awk -F'DMI:' '{print $2}'` 
	echo -e "CPU model: \t"`cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq`
	echo -e "CPUS: \t\t\t\t" `cat /proc/cpuinfo | grep processor | wc -l | awk '{print $1}'`
	echo -e "CPU Type: \t\t\t" `cat /proc/cpuinfo | grep vendor_id | tail -n 1 | awk '{print $3}'`
	Disk=$(fdisk -l |grep 'Disk' |awk -F , '{print $1}' | sed 's/Disk identifier.*//g' | sed '/^$/d')
	echo -e "Disks info:\t\t\t ${Disk}\n${Line}"
	echo -e "System Version: \t" `more /etc/redhat-release`
	check_ip_format=`ifconfig | grep "inet addr"`
	if [ ! -n "$check_ip_format" ]; then
		# 7.x
		Ipddr=`ifconfig | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}'`
	else
		# 6.x
		Ipddr=`ifconfig | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}' | awk -F: '{print $2}'`
	fi
	echo -e "Hostname: \t\t\t" `hostname`
	echo -e "IP Address: \t\t ${Ipddr}" 
	echo -e "Middleware or webserver：\t ${WEBSERVER}  ${WEBSERVER_NUMBER}"
	echo -e "DBS：\t\t\t\t ${DBS}"
	echo
	echo "-------------------------------- Information Collection end --------------------------------"
	echo
}

#----------------------------------------------------------------------------
# Ubuntu操作系统信息收集
#----------------------------------------------------------------------------
ubuntu_info_collection()
{
	echo
	echo "-------------------------------- Information Collection start --------------------------------"
	echo
	echo -e "Hardware platform: \t"`lspci |grep Host | head -1 | awk -F: '{print $3}'` 
	echo -e "CPU model: \t"`cat /proc/cpuinfo | grep name  | uniq | awk -F: '{print $2}'`
	echo -e "CPUS: \t\t\t\t" `cat /proc/cpuinfo | grep processor | wc -l | awk '{print $1}'`
	echo -e "CPU Type: \t\t\t" `cat /proc/cpuinfo | grep vendor_id | tail -n 1 | awk '{print $3}'`
	Disk=$(fdisk -l |grep 'Disk' |awk -F , '{print $1}' | sed 's/Disk identifier.*//g' | sed '/^$/d')
	echo -e "Disks info:\t\t\t ${Disk}\n${Line}"
	echo -e "System Version: \t" `cat /etc/lsb-release | grep "DISTRIB_DESCRIPTION" | awk -F'=' '{print $2}'`
	check_ip_format=`ifconfig | grep "inet addr"`
	if [ ! -n "$check_ip_format" ]; then
		Ipddr=`ifconfig | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}'`
	else
		Ipddr=`ifconfig | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}' | awk -F: '{print $2}'`
	fi
	echo -e "Hostname: \t\t\t" `hostname`
	echo -e "IP Address: \t\t ${Ipddr}" 
	echo -e "Middleware or webserver：\t ${WEBSERVER}  ${WEBSERVER_NUMBER}"
	echo -e "DBS：\t\t\t\t ${DBS}"
	echo
	echo "-------------------------------- Information Collection end --------------------------------"
	echo
}

#----------------------------------------------------------------------------
# AIX小型机信息收集，未完善
#----------------------------------------------------------------------------
AIX_info_collection()
{
	prtconf | more
	Ipddr=`ifconfig | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 127 | awk '{print $2}'`
	echo -e "IP Address: \t\t ${Ipddr}" 
}


#----------------------------------------------------------------------------
# 信息收集 -l 参数执行该方法
#----------------------------------------------------------------------------
information_collection()
{
	get_system_version
	get_database_version
	get_webserver_info
	case $DISTRO in
        CentOS)
			redhat_info_collection;;      		
        RedHat)    
			redhat_info_collection;; 
		EulerOS)    
			redhat_info_collection;; 	
		Ubuntu)    
			ubuntu_info_collection;; 
		AIX)    
			AIX_info_collection;; 		
    esac
}

#-------------------------------------------------------------------------------------------
# 红帽系操作系统执行该方法，主要支持7.X，6.X版本。其中部分5.X 4.X 低版本,部分命令无法识别
#-------------------------------------------------------------------------------------------
redhat_or_centos_ceping()
{
	LogMsg "Checking operating system......" 1>&2
	echo "-------------------------------- System checking start --------------------------------"
	
	# --------------------------------------- 空口令用户核查 --------------------------------------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking Empty password users"
	echo "#----------------------------------------------------------------------------"
	
	flag=
	null_password=`awk -F: 'length($2)==0 {print $1}' /etc/shadow`
	
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	null_password=`awk -F: 'length($2)==0 {print $1}' /etc/passwd`
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	null_password=`awk -F: '$2=="!" {print $1}' /etc/shadow`
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	null_password=`awk -F: '$2!="x" {print $1}' /etc/passwd`
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	[[ ! -n "$flag" ]] && echo "[Y] This system no empty password users!"
	
	
	
	# --------------------------------------- 特权账户数量核查 --------------------------------------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking UID=0 users"
	echo "#----------------------------------------------------------------------------"
	awk -F: '($3==0)' /etc/passwd
	echo
	
	# --------------------------------------- 口令过期账户数量核查 --------------------------------------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Password time out users"
	echo "#----------------------------------------------------------------------------"
	for timeout_usename in `awk -F: '$2=="!!" {print $1}' /etc/shadow`; do
		timeout_usenamelist+="$timeout_usename,"
	done
	echo ${timeout_usenamelist%?}
	echo
	
	# --------------------------------------- 多余系统默认账户核查，仅参考，进一步核查是否login权限  --------------------------------------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# May be No need users"
	echo "#----------------------------------------------------------------------------"
	for no_need_usename in `cat /etc/shadow | grep -E 'uucp|nuucp|lp|adm|sync|halt|news|operator|gopher' | awk -F: '{print $1}'`; do
		no_need_usenamelist+="$no_need_usename,"
	done
	echo ${no_need_usenamelist%?}
	echo

	# --------------------------------------- 口令策略核查 --------------------------------------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Policy of password Strength"
	echo "#----------------------------------------------------------------------------"
	cat /etc/login.defs | grep PASS | grep -v ^#
	echo
	case $DISTRO_NUMBER in
        7)
			passwordStrength=`cat /etc/security/pwquality.conf | grep -v ^#  | grep -E 'difok | minlen | dcredit | ucredit | lcredit | ocredit | minclass | maxrepeat | maxclassrepeat | gecoscheck | dictpath'`
			if [ ! -n "$passwordStrength" ]; then
				echo  "[X] After check '/etc/security/pwquality.conf', no pam_cracklib.so/pam_pwquality.so config"
			else
				echo $passwordStrength
			fi;;    				
        *)    
			passwordStrength=`cat /etc/pam.d/system-auth | grep -E 'pam_cracklib.so | pam_pwquality.so'`
			if [ ! -n "$passwordStrength" ]; then
				echo  "[X] After check '/etc/pam.d/system-auth', no pam_cracklib.so/pam_pwquality.so config"
			else
				echo $passwordStrength
			fi;;    		
    esac
	
	# --------------------------------------- 登录失败策略核查 --------------------------------------- #
	echo
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Policy of login failure"
	echo "#----------------------------------------------------------------------------"
	login_failure=`more /etc/pam.d/system-auth | grep tally`	
	if [ -n "$login_failure" ]; then
		echo $login_failure
	else
		echo  "[X] Warning: This system no login failure policy!"
	fi
	echo	
	echo "#----------------------------------------------------------------------------"
	echo "# Policy of ssh login failure"
	echo "#----------------------------------------------------------------------------"
	ssh_login_failure=`cat /etc/ssh/sshd_config | grep -v ^# | grep MaxAuthTries`
	ssh_login_failure2=`cat /etc/pam.d/sshd | grep -v ^# | grep deny=`
	if [ -n "$ssh_login_failure" ]; then
		echo -e "ssh already set :  ${ssh_login_failure}." 
	elif [ -n "$ssh_login_failure2" ]; then	
		echo -e "ssh already set :  ${ssh_login_failure2}." 
	else
		echo  "[X] Warning: No login failure policy of ssh ! "
	fi
	echo
	
	# --------------------------------------- shell登录超时退出登录核查 --------------------------------------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Login timeout lock, ('suggest config parameter: TMOUT >= 600s')"
	echo "#----------------------------------------------------------------------------"
	TMOUT=`cat /etc/profile | grep -n "TMOUT"`
	if [ -n "$TMOUT" ]; then
		echo $TMOUT	
	else
		echo  "[X] Warning: not set TMOUT!"
	fi
	echo

	# --------------------------------------- 重要目录权限核查 --------------------------------------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking some files access permission"
	echo "#----------------------------------------------------------------------------"
	ls -l /etc/shadow
	ls -l /etc/passwd
	ls -l /etc/group
	ls -l /etc/gshadow 
	ls -l /etc/profile
	ls -l /etc/crontab
	ls -l /etc/securetty 
	ls -l /etc/ssh/ssh_config
	ls -l /etc/ssh/sshd_config
	echo

	# --------------------------------------- 核查telnet、ftp、smtp是否开启 --------------------------------------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking telnet and ftp status"
	echo "#----------------------------------------------------------------------------"
	telnet_or_ftp_status=`netstat -an | grep -E 'telnet | ftp | smtp'`
	if [ -n "$telnet_or_ftp_status" ]; then
		echo $telnet_or_ftp_status
	else	
		echo "[Y] This system no open 'telnet, ftp, smtp' server!"
	fi
	echo

	# --------------------------------------- 核查selinux是否开启 --------------------------------------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking MAC(Mandatory access control) status"
	echo "#----------------------------------------------------------------------------"
	cat /etc/selinux/config | grep -v ^# | grep "SELINUX="
	echo

	# ------- 核查rsyslog，auditd服务是否开启，日志是否外发，审计配置，审计策略  -------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Syslog and audit status"
	echo "#----------------------------------------------------------------------------"
	case $DISTRO_NUMBER in
        7)
			systemctl list-unit-files --type=service | grep "rsyslog"
			systemctl list-unit-files --type=service | grep "auditd";;      		
        *)    
			service --status-all | grep rsyslogd
			service auditd status;;        		
    esac
	echo
	
	echo
	echo "[Sent to a central host]:" `grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf`
	echo "#----------------------------------------------------------------------------"
	echo "# Configuration parameter of audit record"
	echo "# Note:Max_log_file=5(Log file capacity); Max_log_file_action=ROTATE(log size); num_logs=4"
	echo "#----------------------------------------------------------------------------"
	cat /etc/audit/auditd.conf | grep max_log_file | grep  -v ^#
	cat /etc/audit/auditd.conf | grep num_logs | grep  -v ^#
	echo "[Audit rules]:" `auditd -l`
	echo
	
	# --------------------------------------- 核查最新日志的最后10行 --------------------------------------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# To see the first 10 rows of ‘/var/log/secure’"
	echo "#----------------------------------------------------------------------------"
	logfile=`ls /var/log/ | grep -E 'secure-.*'| tail -n 1`
	cat /var/log/${logfile} | tail -n 10
	echo
	
	# --------------------------------------- 核查日志审计相关文件权限 --------------------------------------- #
	echo "#----------------------------------------------------------------------------"
	echo "# Files permission for about syslog and audit"
	echo "#----------------------------------------------------------------------------"
	ls -l /var/log/messages
	ls -l /var/log/secure
	ls -l /var/log/audit/audit.log
	ls -l /etc/rsyslog.conf
	ls -l /etc/audit/auditd.conf
	echo

	# --------------------------------------- 显示所有开启的服务 --------------------------------------- #
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Show all running service"
	echo "#----------------------------------------------------------------------------"
	case $DISTRO_NUMBER in
        7)
			systemctl list-unit-files --type=service | grep enabled;;      		
        *)    
			service --status-all | grep running;;        		
    esac
	echo
	
	# --------------------------------------- 系统补丁信息 --------------------------------------- #
	echo "#----------------------------------------------------------------------------"
	echo "# System patch info"
	echo "#----------------------------------------------------------------------------"
	rpm -qa --last | grep patch
	echo

	# --------------------------------------- 核查是否允许root远程登录 --------------------------------------- #
	echo "#----------------------------------------------------------------------------"
	echo "# PermitRootLogin parameter status of ssh"
	echo "#----------------------------------------------------------------------------"
	cat /etc/ssh/sshd_config | grep Root
	echo
	
	# --------------------------------------- 核查地址限制 --------------------------------------- #
	echo "#----------------------------------------------------------------------------"
	echo "# IP address permit in hosts.allow and hosts.deny"
	echo "#----------------------------------------------------------------------------"
	echo "[more /etc/hosts.allow]:"
	cat /etc/hosts.allow | grep -v ^#
	echo "[more /etc/hosts.deny]:"
	cat /etc/hosts.deny | grep -v ^#
	echo

	# --------------------------------------- 核查登录终端数量限制 --------------------------------------- #
	echo "#----------------------------------------------------------------------------"
	echo "# Check /etc/securetty about tty login number"
	echo "#----------------------------------------------------------------------------"
	for tty in `cat /etc/securetty `; do
		ttylist+="$tty,"
	done
	echo ${ttylist%?}
	echo

	# --------------------------------------- 核查防火墙配置 --------------------------------------- #
	echo "#----------------------------------------------------------------------------"
	echo "# Checking iptables status"
	echo "#----------------------------------------------------------------------------"
	iptables -L -n
	echo
	
	# --------------------------------------- 核查资源限制 等保1.0遗留 --------------------------------------- #
	echo "#----------------------------------------------------------------------------"
	echo "# System resource limit for single user"
	echo "#----------------------------------------------------------------------------"
	echo "<domain> <type> <item> <value>"
	cat /etc/security/limits.conf | grep -v ^# 
	echo
	
	echo "#----------------------------------------------------------------------------"
	echo "# System resource used status"
	echo "#----------------------------------------------------------------------------"
	echo "[disk info:]"
	df -h
	echo

	echo "[Memory info]:"
	free -m
	echo
	
	# --------------------------------------- 核查硬件资源运行情况 等保1.0遗留 --------------------------------------- #
	mem_use_info=(`awk '/MemTotal/{memtotal=$2}/MemAvailable/{memavailable=$2}END{printf "%.2f %.2f %.2f",memtotal/1024/1024," "(memtotal-memavailable)/1024/1024," "(memtotal-memavailable)/memtotal*100}' /proc/meminfo`)
	echo mem_used_rate:${mem_use_info[2]}%
	
	TIME_INTERVAL=5
	LAST_CPU_INFO=$(cat /proc/stat | grep -w cpu | awk '{print $2,$3,$4,$5,$6,$7,$8}')
	LAST_SYS_IDLE=$(echo $LAST_CPU_INFO | awk '{print $4}')
	LAST_TOTAL_CPU_T=$(echo $LAST_CPU_INFO | awk '{print $1+$2+$3+$4+$5+$6+$7}')
	sleep ${TIME_INTERVAL}
	NEXT_CPU_INFO=$(cat /proc/stat | grep -w cpu | awk '{print $2,$3,$4,$5,$6,$7,$8}')
	NEXT_SYS_IDLE=$(echo $NEXT_CPU_INFO | awk '{print $4}')
	NEXT_TOTAL_CPU_T=$(echo $NEXT_CPU_INFO | awk '{print $1+$2+$3+$4+$5+$6+$7}')
	SYSTEM_IDLE=`echo ${NEXT_SYS_IDLE} ${LAST_SYS_IDLE} | awk '{print $1-$2}'`
	TOTAL_TIME=`echo ${NEXT_TOTAL_CPU_T} ${LAST_TOTAL_CPU_T} | awk '{print $1-$2}'`
	CPU_USAGE=`echo ${SYSTEM_IDLE} ${TOTAL_TIME} | awk '{printf "%.2f", 100-$1/$2*100}'`
	echo "cpu_used_rate:${CPU_USAGE}%"
	echo
	
	
	# --------------------------------------- 其他参考系统信息 --------------------------------------- #
	echo "#----------------------------------------------------------------------------"
	echo "# MISC"
	echo "#----------------------------------------------------------------------------"
	echo "#[System lastlog info]:"
	lastlog
	echo
	echo "#[crontab info]:"
	crontab -l
	echo
	echo "#[Process and port state]:"
	netstat -pantu
	echo
	echo "-------------------------------- System checking end --------------------------------"
	echo
	ps -ef
}

#-------------------------------------------------------------------------------------------
# ubuntu操作核查系统执行该方法，主要支持16 18版本。
#-------------------------------------------------------------------------------------------
ubuntu_ceping()
{
	LogMsg "Checking operating system......" 1>&2
	echo "-------------------------------- System checking start --------------------------------"
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking Empty password users"
	echo "#----------------------------------------------------------------------------"
	
	flag=
	null_password=`awk -F: 'length($2)==0 {print $1}' /etc/shadow`
	
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	null_password=`awk -F: 'length($2)==0 {print $1}' /etc/passwd`
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	null_password=`awk -F: '$2=="!" {print $1}' /etc/shadow`
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	null_password=`awk -F: '$2!="x" {print $1}' /etc/passwd`
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	[[ ! -n "$flag" ]] && echo "[Y] This system no empty password users!"
	
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking UID=0 users"
	echo "#----------------------------------------------------------------------------"
	awk -F: '($3==0)' /etc/passwd
	echo
	
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Password time out users"
	echo "#----------------------------------------------------------------------------"
	for timeout_usename in `awk -F: '$2=="!!" {print $1}' /etc/shadow`; do
		timeout_usenamelist+="$timeout_usename,"
	done
	echo ${timeout_usenamelist%?}
	echo

		echo
	echo "#----------------------------------------------------------------------------"
	echo "# May be No need users"
	echo "#----------------------------------------------------------------------------"
	for no_need_usename in `cat /etc/shadow | grep -E 'uucp|nuucp|lp|adm|sync|halt|news|operator|gopher' | awk -F: '{print $1}'`; do
		no_need_usenamelist+="$no_need_usename,"
	done
	echo ${no_need_usenamelist%?}
	echo

	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Policy of password Strength"
	echo "#----------------------------------------------------------------------------"
	cat /etc/login.defs | grep PASS | grep -v ^#
	echo
	passwordStrength=`cat /etc/security/pwquality.conf`
	if [ ! -n "$passwordStrength" ]; then
		echo  "[X] After check '/etc/security/pwquality.conf', no libpam-pwquality config,note:apt-get install libpam-pwquality"
	else
		echo $passwordStrength
	fi
	echo
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Policy of login failure"
	echo "#----------------------------------------------------------------------------"
	login_failure=`grep pam_pwquality.so /etc/pam.d/common-password`	
	if [ -n "$login_failure" ]; then
		echo $login_failure
	else
		echo  "[X] Warning: This system no login failure policy!"
	fi
	echo
	
	echo "#----------------------------------------------------------------------------"
	echo "# Policy of ssh login failure"
	echo "#----------------------------------------------------------------------------"
	ssh_login_failure=`cat /etc/ssh/sshd_config | grep -v ^# | grep MaxAuthTries`
	if [ ! -n "$ssh_login_failure" ]; then
		echo  "[X] Warning: Remote management of ssh not set MaxAuthTries(3~5)! "
	else
		echo -e "ssh already set :  ${ssh_login_failure}." 
	fi
	echo
	
	echo "#----------------------------------------------------------------------------"
	echo "# IP address permit in hosts.allow and hosts.deny"
	echo "#----------------------------------------------------------------------------"
	echo "[more /etc/hosts.allow]:"
	cat /etc/hosts.allow | grep -v ^#
	echo "[more /etc/hosts.deny]:"
	cat /etc/hosts.deny | grep -v ^#
	echo
	
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Login timeout lock, ('suggest config parameter: TMOUT >= 600s')"
	echo "#----------------------------------------------------------------------------"
	TMOUT=`cat /etc/profile | grep -n "TMOUT"`
	if [ -n "$TMOUT" ]; then
		echo $TMOUT	
	else
		echo  "[X] Warning: This system no set TMOUT!"
	fi
	echo

	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking some files access permission"
	echo "#----------------------------------------------------------------------------"
	ls -l /etc/shadow
	ls -l /etc/passwd
	ls -l /etc/group
	ls -l /etc/gshadow 
	ls -l /etc/profile
	ls -l /etc/crontab
	ls -l /etc/securetty 
	ls -l /etc/ssh/ssh_config
	ls -l /etc/ssh/sshd_config
	echo

	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking telnet and ftp status"
	echo "#----------------------------------------------------------------------------"
	telnet_or_ftp_status=`netstat -an | grep -E 'telnet | ftp | smtp'`
	if [ -n "$telnet_or_ftp_status" ]; then
		echo $telnet_or_ftp_status
	else	
		echo "[Y] This system no open 'telnet, ftp, smtp' server!"
	fi
	echo

	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking MAC(Mandatory access control) status"
	echo "#----------------------------------------------------------------------------"
	cat /etc/selinux/config | grep -v ^# | grep "SELINUX="
	echo

	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Syslog and audit status"
	echo "#----------------------------------------------------------------------------"
	systemctl list-unit-files --type=service | grep "rsyslog"
	systemctl list-unit-files --type=service | grep "auditd"         		
	echo
	
	echo
	echo "[Sent to a central host]:" `grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf`
	echo "[Audit config]:" `cat /etc/audit/auditd.conf | grep -v ^#`
	echo "[Audit rules]:" `auditd -l`
	echo
	
	echo "#----------------------------------------------------------------------------"
	echo "# Files permission for about syslog and audit"
	echo "#----------------------------------------------------------------------------"
	ls -l /var/log/auth.log
	ls -l /var/log/faillog
	ls -l /etc/rsyslog.conf
	ls -l /etc/audit/auditd.conf
	echo

	echo "#----------------------------------------------------------------------------"
	echo "# Configuration parameter of audit record"
	echo "# Note:Max_log_file=5(Log file capacity); Max_log_file_action=ROTATE(log size); num_logs=4"
	echo "#----------------------------------------------------------------------------"
	cat /etc/audit/auditd.conf | grep max_log_file | grep  -v ^#
	cat /etc/audit/auditd.conf | grep max_log_file_action | grep  -v ^#
	echo
	
	echo "#----------------------------------------------------------------------------"
	echo "# Show all running service"
	echo "#----------------------------------------------------------------------------"
	systemctl list-unit-files --type=service | grep enabled      		
	echo
	
	echo "#----------------------------------------------------------------------------"
	echo "# System patch info"
	echo "#----------------------------------------------------------------------------"
	echo

	echo "#----------------------------------------------------------------------------"
	echo "# PermitRootLogin parameter status of ssh"
	echo "#----------------------------------------------------------------------------"
	cat /etc/ssh/sshd_config | grep Root
	echo
	
	echo "#----------------------------------------------------------------------------"
	echo "# IP address permit in hosts.allow and hosts.deny"
	echo "#----------------------------------------------------------------------------"
	iptables --list
	echo
	
	echo "#----------------------------------------------------------------------------"
	echo "# System resource limit for single user"
	echo "#----------------------------------------------------------------------------"
	echo "<domain> <type> <item> <value>"
	cat /etc/security/limits.conf | grep -v ^# 
	echo
	
	echo "#----------------------------------------------------------------------------"
	echo "# System resource used status"
	echo "#----------------------------------------------------------------------------"
	echo "[disk info:]"
	df -h
	echo

	echo "[Memory info]:"
	free -m
	echo
	
	mem_use_info=(`awk '/MemTotal/{memtotal=$2}/MemAvailable/{memavailable=$2}END{printf "%.2f %.2f %.2f",memtotal/1024/1024," "(memtotal-memavailable)/1024/1024," "(memtotal-memavailable)/memtotal*100}' /proc/meminfo`)
	echo mem_used_rate:${mem_use_info[2]}%
	
	TIME_INTERVAL=5
	LAST_CPU_INFO=$(cat /proc/stat | grep -w cpu | awk '{print $2,$3,$4,$5,$6,$7,$8}')
	LAST_SYS_IDLE=$(echo $LAST_CPU_INFO | awk '{print $4}')
	LAST_TOTAL_CPU_T=$(echo $LAST_CPU_INFO | awk '{print $1+$2+$3+$4+$5+$6+$7}')
	sleep ${TIME_INTERVAL}
	NEXT_CPU_INFO=$(cat /proc/stat | grep -w cpu | awk '{print $2,$3,$4,$5,$6,$7,$8}')
	NEXT_SYS_IDLE=$(echo $NEXT_CPU_INFO | awk '{print $4}')
	NEXT_TOTAL_CPU_T=$(echo $NEXT_CPU_INFO | awk '{print $1+$2+$3+$4+$5+$6+$7}')
	SYSTEM_IDLE=`echo ${NEXT_SYS_IDLE} ${LAST_SYS_IDLE} | awk '{print $1-$2}'`
	TOTAL_TIME=`echo ${NEXT_TOTAL_CPU_T} ${LAST_TOTAL_CPU_T} | awk '{print $1-$2}'`
	CPU_USAGE=`echo ${SYSTEM_IDLE} ${TOTAL_TIME} | awk '{printf "%.2f", 100-$1/$2*100}'`
	echo "cpu_used_rate:${CPU_USAGE}%"
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# MISC"
	echo "#----------------------------------------------------------------------------"
	echo "#[System lastlog info]:"
	lastlog
	echo
	echo "#[crontab info]:"
	crontab -l
	echo
	echo "#[Process and port state]:"
	netstat -pantu
	echo
	echo "-------------------------------- System checking end --------------------------------"
	echo
	ps -ef
}

#-------------------------------------------------------------------------------------------
# AIX操作核查系统执行该方法，未完善。
#-------------------------------------------------------------------------------------------
AIX_ceping()
{
	LogMsg "Checking operating system......" 1>&2
	echo "-------------------------------- System checking start --------------------------------"
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking Empty password users"
	echo "#----------------------------------------------------------------------------"
	flag=
	null_password=`awk -F: 'length($2)==0 {print $1}' /etc/shadow`
	
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	null_password=`awk -F: 'length($2)==0 {print $1}' /etc/passwd`
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	null_password=`awk -F: '$2=="!" {print $1}' /etc/shadow`
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	null_password=`awk -F: '$2!="x" {print $1}' /etc/passwd`
	if [ -n "$null_password" ]; then
		flag='y'
		echo $null_password
	fi
	
	[[ ! -n "$flag" ]] && echo "[Y] This system no empty password users!"
	
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Checking UID=0 users"
	echo "#----------------------------------------------------------------------------"
	awk -F: '$3==0 {print $1}' /etc/passwd
	echo
	ps -ef
}


#----------------------------------------------------------------------------
# Oracle数据库核查，参数 -o 执行该方法，已测试兼容版本：10g 11g 12c
#----------------------------------------------------------------------------
oracle_ceping()
{
	[ ! -n "$ORACLE" ] && LogErrorMsg "Not found Oracle database,please run '${0} -l'" 1>&2 && exit 1
	LogMsg "Checking Oracle database system......" 1>&2
	echo "-------------------------------- Oracle checking start --------------------------------"
	echo
	# 临时SQL文件
	sqlFile=/tmp/tmp_oracle.sql
	# 写入SQL语句
	echo "set echo off feedb off timi off pau off trimsp on head on long 2000000 longchunksize 2000000" > ${sqlFile}
	echo "set linesize 150" >> ${sqlFile}
	echo "set pagesize 80" >> ${sqlFile} 
	echo "col username format a22" >> ${sqlFile}
	echo "col account_status format a20" >> ${sqlFile}
	echo "col password format a20" >> ${sqlFile}
	echo "col CREATED format a20" >> ${sqlFile}
	echo "col USER_ID, format a10" >> ${sqlFile}
	echo "col profile format a20" >> ${sqlFile}
	echo "col resource_name format a35" >> ${sqlFile}
	echo "col limit format a10" >> ${sqlFile}
	echo "col TYPE format a15" >> ${sqlFile}
	echo "col VALUE format a20" >> ${sqlFile}

	echo "col grantee format a25" >> ${sqlFile}
	echo "col owner format a10" >> ${sqlFile}
	echo "col table_name format a10" >> ${sqlFile}
	echo "col grantor format a10" >> ${sqlFile}
	echo "col privilege format a10" >> ${sqlFile}

	echo "col AUDIT_OPTION format a30" >> ${sqlFile}
	echo "col SUCCESS format a20" >> ${sqlFile}
	echo "col FAILURE format a20" >> ${sqlFile}
	echo "col any_path format a100" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Oracle version info" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select * from v\$version;" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # All database instances" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select name from v\$database;" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Checking all user status(note sample account:scott,outln,ordsys)" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select username, CREATED, USER_ID, account_status, profile from dba_users;" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Policie Checking of password and attempt login failed" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select profile, resource_name, limit from dba_profiles where resource_type='PASSWORD';" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Show the default password account" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select * from dba_users_with_defpwd;" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}
	
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Show all users about granted_role='DBA'" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select grantee from dba_role_privs where granted_role='DBA';" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Default users grantee roles about grantee='PUBLIC'" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select granted_role from dba_role_privs where grantee='PUBLIC';" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Checking access of data dictionary must boolean=FALSE" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "show parameter O7_DICTIONARY_ACCESSIBILITY;" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Audit state" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "show parameter audit;" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Important security events covered by audit" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select AUDIT_OPTION, SUCCESS, FAILURE from dba_stmt_audit_opts;" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Protecting audit records status" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select grantee, owner, table_name, grantor, privilege from dba_tab_privs where table_name='AUD$';" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Checking login 'IDLE_TIME' value" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select resource_name, limit from dba_profiles where profile='DEFAULT' and resource_type='KERNEL' and resource_name='IDLE_TIME';" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Checking single user resource limit status" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select resource_name, limit from dba_profiles where profile='DEFAULT' and resource_type='SESSIONS_PER_USERS';" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Checking cpu time limit for a single session" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select resource_name, limit from dba_profiles where profile='DEFAULT' and resource_type='CPU_PER_SESSION';" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Show maximum number of connections" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "show parameter processes;" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Access control function" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select any_path from resource_view where any_path like '/sys/acls/%.xml';" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # Remote_os_authent" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select value from v\$parameter where name='remote_os_authent';" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}

	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "PROMPT # 'Oracle Label Security' install status" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select username, account_status, profile from dba_users where username='LBACSYS';" >> ${sqlFile}
	echo "select object_type,count(*) from dba_objects where OWNER='LBACSYS' group by object_type;" >> ${sqlFile}
	echo "PROMPT" >> ${sqlFile}
	echo "exit" >> ${sqlFile}
	chmod 777  ${sqlFile}

	# 切换至oracle账户执行SQL语句，执行完毕后退回root账户
	su - oracle << EOF
sqlplus / as sysdba @ ${sqlFile}
exit
EOF
	# 删除临时SQL文件
	rm $sqlFile -f
	
	# 查找sqlnet.ora文件
	sqlnet_ora_path=`find / -name "sqlnet.ora" | grep -v samples`
	echo
	echo "#============================================================================#" 
	echo -e "# Checking Oracle configuration files(path:${sqlnet_ora_path})"
	echo "#============================================================================#"
	cat $sqlnet_ora_path | grep -Ev "^$|^[#;]"
	echo
	echo "-------------------------------- Oracle checking end --------------------------------"
	echo
}

#----------------------------------------------------------------------------
# Mysql数据库核查，参数 -m 执行该方法。SQL语句未完善。
#----------------------------------------------------------------------------
mysql_ceping()
{ 	
	[ ! -n "$MYSQL" ] && LogErrorMsg "Not found Mysql database,please run '${0} -l'" 1>&2 && exit 1
	LogMsg "Checking Mysql database system......" 1>&2
	echo
	echo "-------------------------------- Mysql checking start --------------------------------"
	echo
	MYSQL_BIN=$(which mysql)
	loginfotmp=/tmp/tmpinfo	

	# 核查是否为空口令。
	if [ ! -n "$1" ];then
		while :
			do
				while [ ! -n "${mysql_pwd}" ]
					do
						read -p "Enter the mysql(user:root) password: " mysql_pwd
						[[ "q" == $mysql_pwd ]] && LogMsg "Already skip Mysql check." 1>&2 && return
					done
			
				$MYSQL_BIN -uroot -p$mysql_pwd -e "exit" &> $loginfotmp
				loginfo=`grep "ERROR" ${loginfotmp}`
				rm -f $loginfotmp
				if [ ! -n "$loginfo" ]; then
					break
				else
					mysql_pwd=					
					LogErrorMsg "Please confirm the password or check the configuration about mysql connect!" 1>&2
					LogMsg "Of course, you can ‘Ctrl + C’ exit or enter 'q' spin mysql checking." 1>&2
					continue
				fi
			done
	else
		mysql_pwd=$1
		$MYSQL_BIN -uroot -p$mysql_pwd -e "exit" &> $loginfotmp
		loginfo=`grep "ERROR" ${loginfotmp}`
		rm -f $loginfotmp
		if [ -n "$loginfo" ]; then
			LogErrorMsg "Please confirm the password or check the configuration!" 1>&2
			exit 1
		fi
		
	fi
	
	echo "#----------------------------------------------------------------------------"
	echo "# Mysql checking"
	echo "#----------------------------------------------------------------------------"
	echo "# Mysql database status"
	$MYSQL_BIN -uroot -p$mysql_pwd -e "\s"
	echo "# show databases;"
	$MYSQL_BIN -uroot -p$mysql_pwd -e 'show databases;'
	echo "# select version();"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'select host, user, password from user;'
	echo "# password policy( > v5.7 )"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like 'validate_password%';"
	echo "# show tables;"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'show tables;'
	echo "# select user, Shutdown_priv, Grant_priv, File_priv from user;"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'select user, Shutdown_priv, Grant_priv, File_priv from user;'
	echo "# select * from db;"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'select * from db;'
	echo "# select * from tables_priv;"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'select * from tables_priv;'
	echo "# select * from columns_priv;"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e 'select * from columns_priv;'	
	echo "# show global variables like '%general%';"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show global variables like '%general%';"	
	echo "# show variables like 'log_%';"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like 'log_%';"	
	echo "# show variables like 'log_bin';"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like 'log_bin';"
	echo "# show variables like '%timeout%';"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like '%timeout%';"
	mysql_cnf=`find / -name my.cnf `
	echo -e "# Checking Mysql configuration files(path:${mysql_cnf})"
	cat $mysql_cnf | grep -v ^$	
	echo
	echo "-------------------------------- Mysql checking end --------------------------------"
	echo
}

#----------------------------------------------------------------------------
# PostgreSQL数据库核查，参数 -pgsql 执行该方法。
#----------------------------------------------------------------------------
pgsql_ceping()
{
	[ ! -n "$PGSQL" ] && LogErrorMsg "Not found PostgreSQL database,please run '${0} -l'" 1>&2 && exit 1
	LogMsg "Checking PostgreSQL database system......" 1>&2
	echo
	echo "-------------------------------- PostgreSQL checking start --------------------------------"
	echo
	sqlFile=/tmp/tmp_postgres.sql
	PGDATA=`su - postgres << EOF 
cat ~/.bash_profile | grep PGDATA=
exit 
EOF`
	PGDATA=`echo ${PGDATA} | awk -F'PGDATA=' '{print $2}'`

	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "\echo # PostgreSQL version info" >> ${sqlFile}
	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "select version();" >> ${sqlFile}

	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "\echo # List of all instances" >> ${sqlFile}
	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "\l" >> ${sqlFile}

	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "\echo # List of all users info" >> ${sqlFile}
	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "select * from pg_shadow;" >> ${sqlFile}

	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "\echo # Access control function" >> ${sqlFile}
	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "select * from pg_roles;" >> ${sqlFile}
	echo "select * from information_schema.table_privileges where grantee='cc';" >> ${sqlFile}

	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "\echo # Log and audit" >> ${sqlFile}
	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "show log_destination; show log_connections; show log_disconnections; show log_statement; show logging_collector; show log_rotation_size; show log_rotation_age;" >> ${sqlFile}

	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "\echo # PostgreSQL MISC" >> ${sqlFile}
	echo "\echo #============================================================================#" >> ${sqlFile}
	echo "select name, setting from pg_settings where context = 'user' order by 1;" >> ${sqlFile}

	echo "\q" >> ${sqlFile}
	chmod 777 ${sqlFile}
# 切换至postgres账户执行SQL语句，执行完毕后退回root账户
su - postgres << EOF
psql -d postgres -U postgres -f ${sqlFile}
exit
EOF
	rm -f ${sqlFile}
	
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Check password module for ‘libdir/passwordcheck’"
	echo "#----------------------------------------------------------------------------"
	grep "passwordcheck" $PGDATA/postgresql.conf
	echo
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Limit address"
	echo "#----------------------------------------------------------------------------"
	grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $PGDATA/postgresql.conf
	grep "listen_addresses" $PGDATA/postgresql.conf
	echo
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# To see the first 10 rows of ‘$PGDATA/pg_log/’"
	echo "#----------------------------------------------------------------------------"
	pg_logfile=`ls $PGDATA/pg_log/ | grep -E 'postgresql-*' | tail -n 1`
	cat $PGDATA/pg_log/${pg_logfile} | tail -n 10
	echo
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Login timeout"
	echo "#----------------------------------------------------------------------------"
	grep 'tcp_keepalives' $PGDATA/postgresql.conf
	echo
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# Max_connections and Shared_buffers"
	echo "#----------------------------------------------------------------------------"
	cat $PGDATA/postgresql.conf | grep -E 'max_connections|shared_buffers' | grep -Ev "^$|^[#;]"
	echo
	echo "-------------------------------- PostgreSQL checking end --------------------------------"
	echo
}

#----------------------------------------------------------------------------
# Redis缓存数据库核查，测评内容暂未实现。
#----------------------------------------------------------------------------
redis_ceping()
{
	echo
	echo
	redis-server -v
	redis_conf=`find / -name "redis.conf"`
	cp $redis_conf ./
	echo
	echo
}

#----------------------------------------------------------------------------
# WEB容器或中间件核查，测评内容暂未实现。
#----------------------------------------------------------------------------
webserver_ceping()
{
	echo
	echo
	case $WEBSERVER in
        "nginx")
			nginx_cfg=`find / -name "nginx.conf" | grep -v tmp` 
			cp $nginx_cfg ./							;; 			
		"weblogic")
			echo "weblogic ceping function wait edit" ;;
		"apache")
			httpd_conf=$(find / -name httpd.conf)
			cp $httpd_conf	./			;;
		*)  echo "Not found web server!"    ;;
    esac
	echo
	echo
}

#----------------------------------------------------------------------------
# 参数 -a 自动核查入口
#----------------------------------------------------------------------------
check_system()
{
	case $DISTRO in
        CentOS)
			redhat_or_centos_ceping;;      		
        RedHat)    
			redhat_or_centos_ceping;; 
		EulerOS)    
			redhat_or_centos_ceping;;	
		Ubuntu)    
			ubuntu_ceping;; 
		AIX)
			AIX_ceping;;
    esac
	
	[[ "Oracle" == "$ORACLE" ]] && oracle_ceping
	[[ "Mysql" == "$MYSQL" ]] && mysql_ceping
	[[ "PostgreSQL" == "$PGSQL" ]] && pgsql_ceping
	[[ $DBS == "redis" ]] && redis_ceping
	[[ -n "$WEBSERVER" ]] && webserver_ceping
	LogSucMsg "Checking completed！" 1>&2
}


#----------------------------------------------------------------------------
# main_ceping 方法，脚本执行入口
#----------------------------------------------------------------------------
main_ceping()
{	
	print_logo
	# root账户执行核查，非root账户告警退出
	[ "`whoami`" != "root" ] && LogErrorMsg "Please use root user or sudo!" 1>&2 && exit 1
	case $1 in
        -h)  
			helpinfo				;;
		-l)		
			information_collection	;;
		-o)
			oracle_ceping			;;
		-m)
			mysql_ceping $2			;;
		-pgsql)
			pgsql_ceping			;;
		-s)
			get_webserver_info
			webserver_ceping		;;
        -a)                        
			output_file_banner
			information_collection  
			check_system			;;
		*)  helpinfo        		;;
    esac		
}

# main_ceping方法接收参数
main_ceping $1 $2