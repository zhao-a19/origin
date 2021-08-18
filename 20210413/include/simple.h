/*******************************************************************************************
*文件:  simple.h
*描述:  通用函数 有多个地方调用 又不好分类的接口放在了这里
*作者:  王君雷
*日期:  2016
*修改:  get_out_mac移动到本文件里
*       添加encodekey函数                        ------> 2017-10-25 王君雷
*       把获取网卡MAC函数移出到单独文件中        ------> 2019-09-09
*******************************************************************************************/
#ifndef __SIMPLE_H__
#define __SIMPLE_H__

#include "mysql.h"

int mysql_init_connect(MYSQL *mysql);//mysql的初始化和连接
int GetAuthName(const char *ip, char *authname, int len);
bool get_out_mac(int ethno, char *mac);
int get_netcard_status(const char *ethname);//网卡使用状态
int create_and_bind_tcp(const char *ip, const int port);
bool IPInRange(const char *rangeip, const char *absip);
unsigned char encodekey(const char *str);
bool RangeIP(const char *ip);

#endif
