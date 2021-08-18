/*******************************************************************************************
*文件:  localip_api.h
*描述:  输入目的IP 输出本地使用的IP
*作者:  王君雷
*日期:  2019-12-17
*修改:
*******************************************************************************************/
#ifndef __LOCALIP_API_H__
#define __LOCALIP_API_H__

//检查路由到参数IP时本地使用的IP
int get_localip(const char *dstip, char *localip, int buffsize);
int get_localip(const char *dstip, char *localip, int buffsize, int times);
//让网闸对端执行，检查路由到参数IP时本地使用的IP
int get_peer_localip(const char *dstip, char *localip, int buffsize);
int get_peer_localip(const char *dstip, char *localip, int buffsize, int times);

#endif
