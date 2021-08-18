/*******************************************************************************************
*文件:  appmatch.h
*描述:  匹配应用模块
*作者:  王君雷
*日期:  2018-12-20
*修改:
*       WEB代理支持分模块生效                                           ------> 2020-11-18
*******************************************************************************************/
#ifndef __APP_MATCH__H__
#define __APP_MATCH__H__

#include "FCSingle.h"
#include "FCWebProxy.h"
#include "datatype.h"

bool DoMsg(uint8 *umsg, int msglen, char *cherror, int *pktchange, int queuenum);
extern CSINGLE *g_tcpapp[];
extern CSINGLE *g_udpapp[];
extern CSINGLE *g_icmpapp;
extern CSINGLE *g_icmpv6app;
extern volatile int g_tcpappnum;
extern volatile int g_udpappnum;
extern volatile int g_icmpappnum;
extern volatile int g_icmpv6appnum;
#endif
