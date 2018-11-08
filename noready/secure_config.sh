#!/bin/bash

# -----------------------------------------------------------
# Filename:			secure_config.sh
# Describe: 		Security config Red-Hat system
# Usage:			chmod 777 secure_config.sh 
#					./secure_config.sh -h  
# v1.0    2018.8.25
# -----------------------------------------------------------

# 脚本配置值
# 本文件名称
selfname=$0
# 参数个数
pramnum=$#
# 参数2，文件名修饰
filen=$2
#备份路径
backup_filemame=/home/xinyuan_config_files_backup
# 待修改备份的配置文件路径
login_defs=/etc/login.defs
system_auth=/etc/pam.d/system-auth
profile=/etc/profile


#########################################################
# 自定义系统配置值
# 口令策略
PASS_MAX_DAYS=9999
PASS_MIN_DAYS=0
PASS_MIN_LEN=0
PASS_WARN_AGE=0
# 口令复杂度
retry=5
difok=3
minlen=
ucredit=-1
lcredit=-3
dcredit=-3
ocredit=-1
remember=24
# 登录失败策略
deny=5 
unlock_time=60 
#定义 y添加 n不添加
even_deny_root=y
root_unlock_time=1800
# 登录超时
TMOUT=600
#########################################################
#获取系统参数  
# 口令策略 login.defs
sys_PASS_MAX_DAYS=`cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}'`
sys_PASS_MIN_DAYS=`cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print $2}'`
sys_PASS_MIN_LEN=`cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}'`
sys_PASS_WARN_AGE=`cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# |awk '{print $2}'`
# /etc/pam.d/system-auth
# 口令复杂度策略
sys_retry=`more /etc/pam.d/system-auth | grep retry | awk -F'retry=' '{print $2}' | awk '{print $1}'`
sys_difok=`more /etc/pam.d/system-auth | grep difok | awk -F'difok=' '{print $2}' | awk '{print $1}'`
sys_minlen=`more /etc/pam.d/system-auth | grep minlen | awk -F'minlen=' '{print $2}' | awk '{print $1}'`
sys_ucredit=`more /etc/pam.d/system-auth | grep ucredit | awk -F'ucredit=' '{print $2}' | awk '{print $1}'`
sys_lcredit=`more /etc/pam.d/system-auth | grep lcredit | awk -F'lcredit=' '{print $2}' | awk '{print $1}'`
sys_dcredit=`more /etc/pam.d/system-auth | grep dcredit | awk -F'dcredit=' '{print $2}' | awk '{print $1}'`
sys_ocredit=`more /etc/pam.d/system-auth | grep ocredit | awk -F'ocredit=' '{print $2}' | awk '{print $1}'`
sys_remember=`more /etc/pam.d/system-auth | grep remember | awk -F'remember=' '{print $2}' | awk '{print $1}'`
# 登录失败策略
sys_deny=`more /etc/pam.d/system-auth | grep deny | awk -F'deny=' '{print $2}' | awk '{print $1}'`
sys_unlock_time=`more /etc/pam.d/system-auth | grep unlock_time | awk -F'unlock_time=' '{print $2}' | awk '{print $1}'`
sys_even_deny_root=`more /etc/pam.d/system-auth | grep even_deny_root | awk -F'even_deny_root=' '{print $2}' | awk '{print $1}'`
sys_root_unlock_time=`more /etc/pam.d/system-auth | grep root_unlock_time | awk -F'root_unlock_time=' '{print $2}' | awk '{print $1}'`
# 会话超时锁定 /etc/profile
sys_TMOUT=`more /etc/profile | grep TMOUT | awk -F'TMOUT=' '{print $2}'`
#########################################################

h_help() {
	echo ==============================================================
	echo Description:
    echo -e "   This Script for configur some security files,"
    echo -e "and the system original configuration file will"
    echo -e "be backed up to \"${backup_filemame}\"."
    echo -e  if you have recovery it, please run \`${selfname} -b\`.
    echo
    echo Usage:
    echo -e "\t" "${selfname} -h      view usage methods."
    echo -e "\t" "${selfname} -l      show system config."
    echo -e "\t" "${selfname} -c      config it and backup original files."
    echo -e "\t" "${selfname} -f      enforcing config system files."
    echo -e "\t" "${selfname} -b      recovery original security config."
    echo -e "\t" "${selfname} -s      show myself parameter value."
    echo -e "\t" "${selfname} -p <filename>   print check results or output to file"
    echo ==============================================================
 
}

l_syscfg() {
	echo
	echo -e "PASS_MAX_DAYS=${sys_PASS_MAX_DAYS}"
	echo -e "PASS_MIN_DAYS=${sys_PASS_MIN_DAYS}"
	echo -e "PASS_MIN_LEN=${sys_PASS_MIN_LEN}"
	echo -e "PASS_WARN_AGE=${sys_PASS_WARN_AGE}"
	echo
	echo -e "retry=${sys_retry}"
	echo -e "difok=${sys_difok}"
	echo -e "minlen=${sys_minlen}"
	echo -e "ucredit=${sys_ucredit}"
	echo -e "lcredit=${sys_lcredit}"
	echo -e "dcredit=${sys_dcredit}"
	echo -e "ocredit=${sys_ocredit}"
	echo -e "remember=${sys_remember}"
	echo
	# 查看系统登录失败的策略
	login_failure=`more /etc/pam.d/system-auth | grep tally`
	if [ ! -n "$login_failure" ]; then
		echo  "No have login failure policy!"
	else
		echo $login_failure
	fi
	echo
	echo -e "TMOUT=${sys_TMOUT}"
	echo
}

sys_backup() {
	if [ ! -d "${backup_filemame}" ]; then
  		mkdir -p ${backup_filemame}
  		cp ${login_defs} ${backup_filemame} -f
		cp ${system_auth} ${backup_filemame} -f
		cp ${profile} ${backup_filemame} -f
	else
		echo -e "Warning: \"${backup_filemame}\" already exists!!! you has been finished the configuration."
		exit
	fi
}

login_failure_policy() {
	word="auth        required      pam_tally2.so"

	test2=(deny unlock_time root_unlock_time)
	declare -a test
	test[0]=$deny
	test[1]=$unlock_time
	test[2]=$root_unlock_time
	if [ "y" == "${even_deny_root}" ]; then
		word+=" even_deny_root"
	fi

	for ((i=0; i<${#test[@]}; i++))
	do
		if [  -z "${test[i]}" ]; then
			continue
		else
			cfg=${test2[i]}=${test[i]}
			word+=" ${cfg}"
		fi
	done

	login_failure=`more /etc/pam.d/system-auth | grep tally`
	if [ ! -n "$login_failure" ]; then
		sed -i "8i\\${word}"  ${system_auth}
	else
		sed -i "s/${login_failure}/${word}/" ${system_auth}
	fi
}


pam_cracklib_version() {
	# 默认是 pam_cracklib.so
	pam_version=`more /etc/pam.d/system-auth | grep 'pam_cracklib'`
	word="password    requisite     pam_cracklib.so try_first_pass"

	# 如果没有获取到pam_cracklib.so，尝试pam_pwquality.so
	if [ ! -n "$pam_version" ]; then
		pam_version=`more /etc/pam.d/system-auth | grep 'pam_pwquality'`
		word="password    requisite     pam_pwquality.so try_first_pass local_users_only"
		# 如果依旧未获取，那么出现了问题，报错返回
		if [ ! -n "$pam_version" ]; then		
			echo "not find 'pam_cracklib.so | pam_pwquality.so' pam_cracklib_version error!!!"
			exit 1
		fi
	fi

	test2=(retry difok minlen ucredit lcredit dcredit ocredit remember)
	declare -a test
	test[0]=$retry
	test[1]=$difok
	test[2]=$minlen
	test[3]=$ucredit
	test[4]=$lcredit
	test[5]=$dcredit
	test[6]=$ocredit
	test[7]=$remember

	for ((i=0; i<${#test[@]}; i++))
	do
		if [  -z "${test[i]}" ]; then
			continue
		else
			cfg=${test2[i]}=${test[i]}
			word+=" ${cfg}"
		fi
	done

	passwordStrength=`more /etc/pam.d/system-auth | grep -E 'password    requisite'`
	sed -i "s/${passwordStrength}/${word}/" ${system_auth}
}

export_tmout() {
	tmout="export TMOUT=${TMOUT}"
	if [ ! -n "$sys_TMOUT" ]; then
		echo ${tmout}>>${profile}
		source ${profile}
	fi
	# 如果不为空，那么就先不配置了吧
	# sysvalue=`more /etc/profile | grep -n "TMOUT"`
	# sed -i "s/${sysvalue}/${tmout}/" ${profile}
}

sys_config() {
	sed -i "s/PASS_MAX_DAYS\t${sys_PASS_MAX_DAYS}/PASS_MAX_DAYS\t${PASS_MAX_DAYS}/" ${login_defs} 
	sed -i "s/PASS_MIN_DAYS\t${sys_PASS_MIN_DAYS}/PASS_MIN_DAYS\t${PASS_MIN_DAYS}/" ${login_defs}
	sed -i "s/PASS_MIN_LEN\t${sys_PASS_MIN_LEN}/PASS_MIN_LEN\t${PASS_MIN_LEN}/" ${login_defs} 
	sed -i "s/PASS_WARN_AGE\t${sys_PASS_WARN_AGE}/PASS_WARN_AGE\t${PASS_WARN_AGE}/" ${login_defs}

	pam_cracklib_version
	login_failure_policy
	export_tmout
	# sed "s/^.*do.*$/bad/" filename
}


c_config() {
	sys_backup
	sys_config
	# l_syscfg
}

f_config() {
	sys_config
}

b_recovery() {
	cp ${backup_filemame}/login.defs ${login_defs} -f
	cp ${backup_filemame}/system-auth  ${system_auth} -f
	cp ${backup_filemame}/profile  ${profile} -f

	rm ${backup_filemame} -rf
}

s_mycfg() {
	echo
	echo "--> ${login_defs}"
	echo PASS_MAX_DAYS=${PASS_MAX_DAYS}
	echo PASS_MIN_DAYS=${PASS_MIN_DAYS}
	echo PASS_MIN_LEN=${PASS_MIN_LEN}
	echo PASS_WARN_AGE=${PASS_WARN_AGE}
	echo
	echo "--> ${system_auth}"
	echo retry=${retry}
	echo difok=${difok}
	echo minlen=${minlen}
	echo ucredit=${ucredit}
	echo lcredit=${lcredit}
	echo dcredit=${dcredit}
	echo ocredit=${ocredit}
	echo ocredit=${ocredit}
	echo
	echo deny=${deny} 
	echo unlock_time=${unlock_time}
	#定义 y添加 n不添加
	echo even_deny_root=${even_deny_root}
	echo root_unlock_time=${root_unlock_time}
	echo
	echo "--> ${profile}"
	echo TMOUT=${TMOUT}
	echo
}	

printcheckret2file() {
time=`date +'%Y%m%d%H%S'`
retfilename=$1-${time}.sh

touch cepingtmp.sh
cat > cepingtmp.sh << EOF
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

Ipddr=`ifconfig | grep "inet" | grep -Ev 'inet6 | 127' |  awk '{print $2}'`
if [ ! -n "$Ipddr" ]; then
	Ipddr=`ifconfig | grep "inet addr" | awk '{ print $2}' | awk -F: '{print $2}' | grep -v 127`
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


echo "********* [Cat files: /etc/passwd:]"
more /etc/passwd
echo
echo
echo "********* [Cat files: /etc/shadow:]"
more /etc/shadow

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
EOF


chmod 777 cepingtmp.sh
./cepingtmp.sh > ${retfilename}
#rm cepingtmp.sh

}

printsimple(){
	echo 
	echo -e "SHOW-ITEM\t\t\tSYS-VAL\tREM-VAL"			
	echo -e "PASS_MAX_DAYS\t\t\t${sys_PASS_MAX_DAYS}\t90"
	echo -e "PASS_MIN_DAYS\t\t\t${sys_PASS_MIN_DAYS}\t2"
	echo -e "PASS_MIN_LEN\t\t\t${sys_PASS_MIN_LEN}\t8"
	echo -e "PASS_WARN_AGE\t\t\t${sys_PASS_WARN_AGE}\t7"
	echo
	echo -e "retry\t\t\t${sys_retry}"
	echo -e "difok\t\t\t${sys_difok}"
	echo -e "minlen\t\t\t${sys_minlen}"
	echo -e "ucredit\t\t\t${sys_ucredit}"
	echo -e "lcredit\t\t\t${sys_lcredit}"
	echo -e "dcredit\t\t\t${sys_dcredit}"
	echo -e "ocredit\t\t\t${sys_ocredit}"
	echo -e "remember\t\t\t${sys_remember}"
	echo
	
	
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
	
	# 账户登录是否超时锁定策略  =600s
	echo "********* [Login timeout lock, ('TMOUT >= 600s')]"
	TMOUT=`more /etc/profile | grep -n "TMOUT"`
	if [ ! -n "$TMOUT" ]; then
		flag=
		echo  "[X] Warning: This system no set TMOUT!"
	else
		echo $TMOUT
	fi
	
	echo "[Check pam_cracklib.so for password Strength:] "
	more /etc/pam.d/system-auth | grep -E 'pam_cracklib.so'
	echo
	
	echo "[Check pam_tally.so for login failure policy:] "
	# 查看系统登录失败的策略
	login_failure=`more /etc/pam.d/system-auth | grep tally`
	if [ ! -n "$login_failure" ]; then
		echo  " [X] Warning: This system no login failure policy!"
	else
		echo $login_failure
	fi
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

	# 系统对主体使用系统资源的限制配置
	echo "********* [Describes system resource limit for a user:]"
	echo
	echo "<domain> <type> <item> <value>"
	more /etc/security/limits.conf | grep -v ^# 
	echo
	echo

	# 访问权限：600合格
	echo "********* [Checking shadow and passwd access permission:]"
	ls -l /etc/shadow
	ls -l /etc/passwd
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
	
	# 强制访问控制
	echo "********* [Mandatory access control:]"
	# 查看配置文件 cat /etc/selinux/config， SELINUX=enforcing(强制开启强制访问控制)
	cat /etc/selinux/config
	echo
	
	# 查看是否开启系统日志 审计 进程
	echo "********* [Syslog and audit status:]"
	service --status-all | grep rsyslogd
	service auditd status
	echo
	echo
	# 查看审计规则
	echo "[audit rules:]" `auditctl -l`
	
	# 审计日志的内容
	echo "********* [To see the first 10 rows of ‘/var/log/secure’:]"
	logfile=`ls /var/log/ | grep -E 'secure-.*'| tail -n 1`
	cat /var/log/${logfile} | tail -n 10
	echo
	# 审计记录的保护
	echo "********* [Files Permission for about syslog and audit:]"
	ls -l /var/log/messages
	ls -l /var/log/secure
	ls -l /var/log/audit/audit.log
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
	
	# 查看防火墙状态策略
	echo "********* [Checking iptables status ：]"
	service iptables status
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
}


p_printcheckret () {
	if [ ${pramnum} -gt 2 ] ; then
		h_help
		exit
	fi

	if [ ${pramnum} -eq 2 ] ; then
		printcheckret2file filen
	else
		printsimple
	fi
}



cfg_main() {
    case $1 in
        -h)           	h_help        	;;
		-l)				l_syscfg 		;;
		-s)				s_mycfg 		;;
        -c)         	c_config      	;;
		-f)				f_config		;;
        -b)      		b_recovery   	;;
		-p)				p_printcheckret ;;
        *)              h_help          ;;
    esac
}



cfg_main $1