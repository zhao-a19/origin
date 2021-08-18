#!/bin/bash

function mode_t
{
	file=$1
	item_find=$2
	item_insert=$3

	total=`sed -n "/^${item_find}=/p" $file |wc -l`
	echo "t total num ${total}"

	i=1
	while [[ true ]];
	do
		if [ $i -gt ${total} ];
		then
			break;
		else
			linenum=`sed -n "/^${item_find}=/=" $file |sed -n ${i}p`
			nextline=$((${linenum} + 1))
			#echo $nextline
			findnext=`sed -n "${nextline},${nextline} p" ${file} | cut -d "=" -f1`
			if [ "${findnext}" == "${item_insert}" ];
			then
				echo "already find ${item_insert},ignore"
			else
				fsize=`ls -l ${file}|awk '{print $5}'`
				timestr=`date +%s -r ${file}`
				`sed -i "${linenum} a\${item_insert}=${fsize}${timestr}" ${file}`
			fi
			let 'i+=1'
		fi
	done
	return 0
}

function mode_a
{
	file=$1
	item_find=$2
	total=`sed -n "/^${item_find}=/p" $file |wc -l`
	echo "a total num ${total}"

	hasid=`sed -n "/^ID=/p" $file |wc -l`
	if [ ${hasid} -gt 0 ]; then
		echo "find ID, ignore"
		exit 1
	fi

	i=1
	while [[ true ]];
	do
		if [ $i -gt ${total} ];
		then
			break;
		else
			linenum=`sed -n "/^${item_find}=/=" $file |sed -n ${i}p`
			value=`sed -n "/^${item_find}=/p" $file |sed -n ${i}p|cut -d"=" -f2 |sed 's/\"//g'`
			md5str=`echo ${value}|md5sum|cut -d" " -f0`
			#if [[ ${value:0:1} = \" ]];
			#then
				`sed -i "${linenum} a\ID=${md5str}" ${file}`
			#else
			#	echo "ignore ${value}"
			#fi
			let 'i+=1'
		fi
	done
	return 0
}

function mode_r
{
	file=$1
	item_find=$2
	total=`sed -n "/^${item_find}=/p" $file |wc -l`
	echo "r total num ${total}"

	i=1
	while [[ true ]];
	do
		if [ $i -gt ${total} ];
		then
			break;
		else
			linenum=`sed -n "/^${item_find}=/=" $file |sed -n ${i}p`
			value=`sed -n "/^${item_find}=/p" $file |sed -n ${i}p|cut -d"=" -f2`
			#echo $value
			valuetmp=`echo $value |sed 's/\"//g'`

			if [[ ${valuetmp:0:1} = \' ]];
			then
				valuetmp=${valuetmp//\'/""}
			fi

			#echo ${valuetmp}
			if [[ ${#valuetmp} -eq 32 ]]; then
				echo "${valuetmp}" | grep -q '^[a-f0-9]\+$'
				if [[ $? -eq 0 ]]; then
					echo "32 length... ignore"
					let 'i+=1'
					continue;
				fi
			fi

			#长度为13 全数字
			if [[ ${#valuetmp} -eq 13 ]]; then
				echo "${valuetmp}" | grep -q '^[0-9]\+$'
				if [[ $? -eq 0 ]]; then
					echo "13 length time stamp... ignore"
					let 'i+=1'
					continue;
				fi
			fi

			#24小时时间模式
			if [[ "${item_find}" == "TimeMode" ]] && [[ "${valuetmp}" == "1111122222" ]]; then
				echo "24 hours time mode...ignore"
				let 'i+=1'
				continue;
			fi

			md5str=`echo ${valuetmp}|md5sum|cut -d" " -f0`
			#if [[ ${value:0:1} = \" ]];
			if [[ 1 ]]
			then
				`sed -i "${linenum} c\${item_find}=${md5str}" ${file}`
			else
				echo "ignore ${value}"
			fi
			let 'i+=1'
		fi
	done
	return 0
}


if [ $# -lt 3 ];
then
        echo "  $0 t filename item_find item_insert"
        echo "  $0 a filename item_find"
        echo "  $0 r filename item_find"
        exit 1
fi

mode=$1
file=$2
item_find=$3

if [[ $mode = "t" ]] && [[ $# -eq 4 ]];
then
	mode_t $2 $3 $4
fi

if [[ $mode = "a" ]] && [[ $# -eq 3 ]];
then
	mode_a $2 $3
fi

if [[ $mode = "r" ]] && [[ $# -eq 3 ]];
then
	mode_r $2 $3
fi
