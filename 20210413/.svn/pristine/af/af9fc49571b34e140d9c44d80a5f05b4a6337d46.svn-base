/*******************************************************************************************
*文件:  FCTcpNull.h
*描述:  TCP自定义模块
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_TCPNULL_H__
#define __FC_TCPNULL_H__

#include "FCSingle.h"

class CTCPNULL : public CSINGLE
{
public:
    CTCPNULL();
    ~CTCPNULL();
public:
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
};

#endif
