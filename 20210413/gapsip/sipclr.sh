#!/bin/sh

#for sip in `iptables -t nat -nvL --line-number|grep -v Chain|grep -w sipch|awk '{print $1}'|sort -nr`
#real device don't support grep -w
for sip in `iptables -t nat -nvL --line-number|grep -v Chain|grep sipch|cut -d' ' -f1|sort -nr`
do 
    #echo $sip
    iptables -t nat -D PREROUTING $sip
done

iptables -t nat -F sipch

