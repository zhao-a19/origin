/*******************************************************************************************
*文件:    connect_manager.h
*描述:    链接管理模块
*
*作者:    宋宇
*日期:    2019-11-10
*修改:    创建文件                                             ------>     2019-11-10
1.增加所有子路径检测函数                                       ------> 2020-03-01
*
*******************************************************************************************/
#ifndef __CONNECT_MANAGE_H__
#define __CONNECT_MANAGE_H__

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include "global_define.h"
#include "FCLogManage.h"


bool check_all_internet(fs_rule_t *rule);

bool check_server_internet(const char *ip, int port);

bool ipv4_tcp_connect(const char *ip, int port);

bool ipv6_tcp_connect(const char *ip, int port);

#endif //__CONNECT_MANAGE_H__