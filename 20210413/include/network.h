/*******************************************************************************************
*文件:  network.h
*描述:  应用层以下的协议分析处理
*作者:  王君雷
*日期:  2018-04-03
*修改:
*        创建文件                                                  ------> 2018-04-03
*        添加IPV6相关宏                                            ------> 2018-12-27
*        添加函数get_ipv6_ext_headerlen                            ------> 2019-01-22
*******************************************************************************************/
#ifndef __NETWORK_H_
#define __NETWORK_H_

#include "datatype.h"
#include "netosi.h"

#define IPV4_PROTO(sdata) ((PIP_HEADER)sdata)->ip_p
#define IS_IPV4TCP(sdata) (_ipv4(sdata) && (((PIP_HEADER)sdata)->ip_p == TCP))
#define IS_IPV4UDP(sdata) (_ipv4(sdata) && (((PIP_HEADER)sdata)->ip_p == UDP))
#define IS_IPV4ICMP(sdata) (_ipv4(sdata) && (((PIP_HEADER)sdata)->ip_p == ICMP))
#define IPV4_IPTCP_HEADER_LEN(sdata) (_ipheadlen(sdata) + _tcpheadlen(sdata + (_ipheadlen(sdata)))) //IPV4头部及TCP头部 长度之和
#define IPV4_IPUDP_HEADER_LEN(sdata) (_ipheadlen(sdata) + _udpheadlen(sdata + (_ipheadlen(sdata)))) //IPV4头部及UDP头部 长度之和
#define IPV4_DIP(sdata) (&(((IP_HEADER *)sdata)->ip_dst))
#define IPV4_SIP(sdata) (&(((IP_HEADER *)sdata)->ip_src))
#define IS_IPV4_TCP_SYN(sdata) (IS_IPV4TCP(sdata) && (((_tcpipdata(sdata))->th_flags & TH_SYN) > 0))
#define IS_IPV4_TCP_FIN(sdata) (IS_IPV4TCP(sdata) && (((_tcpipdata(sdata))->th_flags & TH_FIN) > 0))
#define IS_IPV4_TCP_RST(sdata) (IS_IPV4TCP(sdata) && (((_tcpipdata(sdata))->th_flags & TH_RST) > 0))

#define IPV6_PROTO(sdata) ((PIPV6_HEADER)sdata)->ip_nexthd
#define IPV6_DIP(sdata) (&(((PIPV6_HEADER)sdata)->ip_dst))
#define IPV6_SIP(sdata) (&(((PIPV6_HEADER)sdata)->ip_src))

int get_ipv6_ext_headerlen(unsigned char *sdata, int slen, unsigned char *proto);

#endif
