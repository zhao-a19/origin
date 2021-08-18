/*******************************************************************************************
*文件:  FCUdpNull.h
*描述:  UDP自定义模块
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_UDPNULL_H__
#define __FC_UDPNULL_H__

#include "FCSingle.h"

class CUDPNULL : public CSINGLE
{
public:
    CUDPNULL();
    ~CUDPNULL();
public:
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
};

#endif
