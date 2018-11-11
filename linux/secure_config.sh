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
#备份路径
backup_filemame=/home/xinyuan_config_files_backup
# 待修改备份的配置文件路径
login_defs=/etc/login.defs
system_auth=/etc/pam.d/system-auth
profile=/etc/profile

#########################################################
# 自定义系统配置值
# 口令策略
PASS_MAX_DAYS=90
PASS_MIN_DAYS=2
PASS_MIN_LEN=8
PASS_WARN_AGE=7
# 口令复杂度
retry=5
difok=3
minlen=
ucredit=-1
lcredit=-1
dcredit=-1
ocredit=-1
remember=8
# 登录失败策略
deny=5 
unlock_time=600 
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


cfg_main() {
    case $1 in
        -h)           	h_help        	;;
		-l)				l_syscfg 		;;
		-s)				s_mycfg 		;;
        -c)         	c_config      	;;
		-f)				f_config		;;
        -b)      		b_recovery   	;;
        *)              h_help          ;;
    esac
}

cfg_main $1