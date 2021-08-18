#!/bin/bash

route -n -A inet6|grep eth|while read -a array1
do
	destination=${array1[0]}
	nexthop=${array1[1]}
	flags=${array1[2]}
	metric=${array1[3]}
	ref=${array1[4]}
	use=${array1[5]}
	iface=${array1[6]}

	if [[ ${nexthop} != "::" ]]
	then
		route -A inet6 del ${destination} gw ${nexthop} metric ${metric} dev ${iface}
	fi
done
