#!/bin/sh

ifconfig eth10 mtu 1500
ifconfig eth11 mtu 1500
ifconfig eth12 mtu 1500
ifconfig eth13 mtu 1500
ifconfig eth14 mtu 1500

ethtool -C eth10 rx-usecs 10
ethtool -C eth12 rx-usecs 10
ethtool -C eth13 rx-usecs 10
ethtool -C eth14 rx-usecs 10
ethtool -C eth15 rx-usecs 10

ethtool -G eth10 rx 4096 tx 4096
ethtool -G eth11 rx 4096 tx 4096
ethtool -G eth12 rx 4096 tx 4096
ethtool -G eth13 rx 4096 tx 4096
ethtool -G eth14 rx 4096 tx 4096

ethtool -K eth10 gso off
ethtool -K eth11 gso off
ethtool -K eth12 gso off
ethtool -K eth13 gso off
ethtool -K eth14 gso off

ifconfig eth10 txqueuelen 100000
ifconfig eth11 txqueuelen 100000
ifconfig eth12 txqueuelen 100000
ifconfig eth13 txqueuelen 100000
ifconfig eth14 txqueuelen 100000


echo 1 >> /proc/irq/169/smp_affinity
echo 1 >> /proc/irq/170/smp_affinity
echo 1 >> /proc/irq/171/smp_affinity
echo 1 >> /proc/irq/172/smp_affinity

echo 2 >> /proc/irq/183/smp_affinity
echo 2 >> /proc/irq/184/smp_affinity
echo 2 >> /proc/irq/185/smp_affinity
echo 2 >> /proc/irq/186/smp_affinity

echo 4 >> /proc/irq/197/smp_affinity
echo 4 >> /proc/irq/198/smp_affinity
echo 4 >> /proc/irq/199/smp_affinity
echo 4 >> /proc/irq/200/smp_affinity

echo 4 >> /proc/irq/211/smp_affinity
echo 4 >> /proc/irq/212/smp_affinity
echo 4 >> /proc/irq/213/smp_affinity
echo 4 >> /proc/irq/214/smp_affinity

echo 8 >> /proc/irq/225/smp_affinity
echo 8 >> /proc/irq/226/smp_affinity
echo 8 >> /proc/irq/227/smp_affinity
echo 8 >> /proc/irq/228/smp_affinity

sysctl -w net.core.rmem_max=16777216                 
sysctl -w net.core.wmem_max=16777216                 
sysctl -w net.core.rmem_default=600000               
sysctl -w net.core.wmem_default=600000               
sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"     
sysctl -w net.ipv4.tcp_mem="10000000 10000000 10000000"
sysctl -w net.core.netdev_max_backlog=600000         

