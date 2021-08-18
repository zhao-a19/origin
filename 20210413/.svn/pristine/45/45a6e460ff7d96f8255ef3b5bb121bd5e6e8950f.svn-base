#!/bin/bash
#消息
MESSAGE=

#设备类型
ID=

#设备序列号
DEVID=

#设备hostname
FW=$(hostname)

#时间
TIME=$(date "+%Y-%m-%d %H:%M:%S")

#PRI
PRI=5

#syslog目的端编码 #0:gbk  1:utf8
SETCODE=

if [ "$#" -eq 2 ]; then
	if [ "$1" = "-m" ]; then
		MESSAGE="$2"
	else
		echo "error.. need args -m message"
		exit 1
	fi
elif [ "$#" -eq 4 ]; then
	if [ "$1" = "-l" ]; then
		PRI="$2"
	elif [ "$1" = "-m" ]; then
		MESSAGE="$2"
	fi
	if [ "$3" = "-l" ]; then
		PRI="$4"
	elif [ "$3" = "-m" ]; then
		MESSAGE="$4"
	fi
else
    echo "error.. need args -m message"
    exit 1
fi

if [ -z "$MESSAGE" ]; then
    echo "error.. need args -m message"
    exit 1
fi

LOGGERPATH="/initrd/abin/logger.sh"
SYSINFO="/var/self/sysinfo.cf"
SERIALCF="/tmp/serial.cf"
SYSSET="/var/self/rules/conf/sysset.cf"


ID=$(grep "DEVTYPE=" $SYSINFO|cut -d "=" -f2)
DEVID=$(grep "DevIndex=" $SYSINFO|cut -d "=" -f2)

if [ -z "$DEVID" ]; then
    DEVID=$(grep "SERIAL=" $SERIALCF|cut -d "=" -f2)
fi

#读取syslog目的端编码
SETCODE=$(grep "SYSLOG_CHARSET=" $SYSSET|cut -d "=" -f2)

if [ "$SETCODE" = "0" ];then
    SETCODE="gbk"
elif [ "$SETCODE" = "1" ]; then
    SETCODE="utf-8"
fi

SYSLOG="/tmp/syslognum.info"
MESSAGETO=`/initrd/abin/syslog_tool "$MESSAGE" "$SETCODE" "$SYSLOG"`

#格式化
logformat="<${PRI}>ID=\"${ID}\" FW=\"${FW}\" TIME=\"${TIME}\" PRI=\"${PRI}\" DEVID=\"${DEVID}\" ${MESSAGETO}"

if [ $PRI -eq 1 ];then
    userlevel=user.alert
elif [ $PRI -eq 2 ];then
    userlevel=user.crit
elif [ $PRI -eq 3 ];then
    userlevel=user.err
elif [ $PRI -eq 4 ];then
    userlevel=user.warning
elif [ $PRI -eq 5 ];then
    userlevel=user.notice
elif [ $PRI -eq 6 ];then
    userlevel=user.info
else
    userlevel=user.debug
fi

#调用logger发送syslog日志
/bin/logger -p $userlevel $logformat

