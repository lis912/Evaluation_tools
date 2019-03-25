#!/bin/bash
#============================================================================
# File:         linux_for_djbh.sh      
# Author:       Li
# Mail:			sjm217@qq.com 
# Date:         2019.3
# Version:      v2.0
#
# Description:
#		等级保护安全基线配置检查脚本，兼容Red-Hat CentOS，Oracle, Mysql.
# Usage:
# 		./linux_for_djbh.sh >> filename.sh
#============================================================================

# 全局变量
DISTRO=
DISTRO_NUMBER=

ORACLE=
ORACLE_NUMBER=

MYSQL=
MYSQL_NUMBER=

DBS=

output_file_banner()
{
	echo "# ============================================================================"
	echo -e "# Describe: \t\t This file about security baseline check output" 			
	echo -e "# Running time:\t\t "`date +'%Y-%m-%d %H:%S'`
	echo "# ============================================================================"
	echo
}

#----------------------------------------------------------------------------
# Gets the system version info
#----------------------------------------------------------------------------
get_system_version()
{
	if grep -Eqii "CentOS" /etc/issue || grep -Eq "CentOS" /etc/*-release; then
        DISTRO='CentOS'
		if grep -Eq "7." /etc/*-release; then
			DISTRO_NUMBER='7'
		elif grep -Eq "6." /etc/*-release; then
			DISTRO_NUMBER='6'
		elif grep -Eq "5." /etc/*-release; then
			DISTRO_NUMBER='5'
		elif grep -Eq "4." /etc/*-release; then
			DISTRO_NUMBER='4'
		else
			DISTRO_NUMBER='unknow'
		fi	
    elif grep -Eqi "Red Hat Enterprise Linux Server" /etc/issue || grep -Eq "Red Hat Enterprise Linux Server" /etc/*-release; then
        DISTRO='RedHat'
		if grep -Eq "7." /etc/*-release; then
			DISTRO_NUMBER='7'
		elif grep -Eq "6." /etc/*-release; then
			DISTRO_NUMBER='6'
		elif grep -Eq "5." /etc/*-release; then
			DISTRO_NUMBER='5'
		elif grep -Eq "4." /etc/*-release; then
			DISTRO_NUMBER='4'
		else
			DISTRO_NUMBER='unknow'
		fi	
    elif grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then
        DISTRO='Ubuntu'
    else
        DISTRO='unknow'
    fi
}

#----------------------------------------------------------------------------
# Gets the database version info
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
	fi
	
	DBS="${ORACLE} ${ORACLE_NUMBER}	${MYSQL} ${MYSQL_NUMBER}"
}

#----------------------------------------------------------------------------
# Information Collection
#----------------------------------------------------------------------------
information_collection()
{
	get_system_version
	get_database_version
	
	echo "#----------------------------------------------------------------------------"
	echo "# Information Collection"
	echo "#----------------------------------------------------------------------------"
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
	echo -e "Middleware or webserver： "
	echo -e "DBS：\t\t\t\t ${DBS}"
	echo
}

#----------------------------------------------------------------------------
# Red-Hat or CentOS check
#----------------------------------------------------------------------------
redhat_or_centos_ceping()
{
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
	
	case $DISTRO_NUMBER in
        7)
			passwordStrength=`cat /etc/pam.d/system-auth | grep -E 'pam_pwquality.so'`
			if [ ! -n "$passwordStrength" ]; then
				echo  "[X] After check '/etc/pam.d/system-auth', no pam_pwquality.so config"
			else
				echo $passwordStrength
			fi;;        		
        *)    
			passwordStrength=`cat /etc/pam.d/system-auth | grep -E 'pam_cracklib.so'`
			if [ ! -n "$passwordStrength" ]; then
				echo  "[X] After check '/etc/pam.d/system-auth', no pam_cracklib.so config"
			else
				echo $passwordStrength
			fi;;  
    esac
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
	if [ ! -n "$ssh_login_failure" ]; then
		echo  "[X] Warning: Remote management of ssh not set MaxAuthTries(3~5)! "
	else
		echo -e "ssh already set :  ${ssh_login_failure}." 
	fi
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
	echo "[Audit rules]:" `auditctl -l`
	echo
	
	echo
	echo "#----------------------------------------------------------------------------"
	echo "# To see the first 10 rows of ‘/var/log/secure’"
	echo "#----------------------------------------------------------------------------"
	logfile=`ls /var/log/ | grep -E 'secure-.*'| tail -n 1`
	cat /var/log/${logfile} | tail -n 10
	echo
	
	echo "#----------------------------------------------------------------------------"
	echo "# Files permission for about syslog and audit"
	echo "#----------------------------------------------------------------------------"
	ls -l /var/log/messages
	ls -l /var/log/secure
	ls -l /var/log/audit/audit.log
	ls -l /etc/rsyslog.conf
	ls -l /etc/audit/auditd.conf
	echo

	echo "#----------------------------------------------------------------------------"
	echo "# Configuration parameter of audit record"
	echo "# Note:Max_log_file=5(Log file capacity); Max_log_file_action=ROTATE(log size); num_logs=4"
	echo "#----------------------------------------------------------------------------"
	cat /etc/audit/auditd.conf | grep max_log_file | grep  -v ^#
	cat /etc/audit/auditd.conf | grep num_logs | grep  -v ^#
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
	
	echo "#----------------------------------------------------------------------------"
	echo "# System patch info"
	echo "#----------------------------------------------------------------------------"
	rpm -qa --last | grep patch
	echo

	echo "#----------------------------------------------------------------------------"
	echo "# PermitRootLogin parameter status of ssh"
	echo "#----------------------------------------------------------------------------"
	cat /etc/ssh/sshd_config | grep Root
	echo
	
	echo "#----------------------------------------------------------------------------"
	echo "# IP address permit in hosts.allow and hosts.deny"
	echo "#----------------------------------------------------------------------------"
	echo "[more /etc/hosts.allow]:"
	cat /etc/hosts.allow | grep -v ^#
	echo "[more /etc/hosts.deny]:"
	cat /etc/hosts.deny | grep -v ^#
	echo

	echo "#----------------------------------------------------------------------------"
	echo "# Check /etc/securetty about tty login number"
	echo "#----------------------------------------------------------------------------"
	for tty in `cat /etc/securetty `; do
		ttylist+="$tty,"
	done
	echo ${ttylist%?}
	echo

	echo "#----------------------------------------------------------------------------"
	echo "# Checking iptables status"
	echo "#----------------------------------------------------------------------------"
	iptables -L -n
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
	
	echo "[mem_used_rate]: = "  `free -m | awk '{if(NR==2){print int($3*100/$2),"%"}}'`

	cpu_used=`top -b -n 1 | head -n 4 | grep "^Cpu(s)" | awk '{print $2}' | cut -d 'u' -f 1`
	echo "[cpu_used_rate]: = " $cpu_used
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
}

#----------------------------------------------------------------------------
# Oracle database checking(compatible 10g 11g 12c)
#----------------------------------------------------------------------------
oracle_ceping()
{
	echo "#----------------------------------------------------------------------------"
	echo "# Oracle checking"
	echo "#----------------------------------------------------------------------------"
	
	# tmp sql file
	sqlFile=/tmp/tmp_oracle.sql

	# write the sql file
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
	echo "PROMPT # Default account password (11g)" >> ${sqlFile}
	echo "PROMPT #============================================================================#" >> ${sqlFile}
	echo "select * from dba_users_with_defpwd;" >> ${sqlFile}
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

	# switch oracle to execute, gone and back root user
	su - oracle << EOF
sqlplus / as sysdba @ ${sqlFile}
exit
EOF
	# delete the tmp sql file
	rm $sqlFile -f
	
	sqlnet_ora_path=`find / -name "sqlnet.ora" | grep -v samples`
	echo
	echo "#============================================================================#" 
	echo -e "# Checking Oracle configuration files(path:${sqlnet_ora_path})"
	echo "#============================================================================#"
	cat $sqlnet_ora_path | grep -Ev "^$|^[#;]"
	echo
}

mysql_ceping()
{ 	
	MYSQL_BIN=$(which mysql)
	
	if [ ! -n "$1" ];then
		read -p "Enter the mysql(user:root) password: " mysql_pwd
	else
		mysql_pwd=$1
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
	echo "# show variables like 'log_%';"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like 'log_%';"	
	echo "# show variables like 'log_bin';"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like 'log_bin';"
	echo "# show variables like '%timeout%';"
	$MYSQL_BIN -uroot -p$mysql_pwd -D mysql -e "show variables like '%timeout%';"
	mysql_cnf=`find / -name my.cnf `
	echo -e "# Checking Mysql configuration files(path:${mysql_cnf})"
	cat $mysql_cnf | grep -v ^$
}

check_system()
{
	[[ "CentOS"=="$DISTRO" ]] || [[ "RedHat"=="$DISTRO" ]] && redhat_or_centos_ceping
	[[ "Oracle" == "$ORACLE" ]] && oracle_ceping
	[[ "Mysql" == "$MYSQL" ]] && mysql_ceping
}

helpinfo()
{
    echo -e "Usage: $0 [OPTION] [PARAMETER]"
	echo 
    echo -e "${0} -h \t => view usage methods."
    echo -e "${0} -l \t => show information collection."
    echo -e "${0} -o \t => oracle check."
    echo -e "${0} -m [password] \t => mysql check."
    echo -e "${0} -a \t => auto check."
	echo 
}

main_ceping()
{	
	case $1 in
        -h)  
			helpinfo				;;
		-l)		
			information_collection	;;
		-o)
			oracle_ceping			;;
		-m)
			mysql_ceping $2			;;
        -a)                        
			output_file_banner
			information_collection  
			check_system			;;
    esac		
}

main_ceping $1 $2