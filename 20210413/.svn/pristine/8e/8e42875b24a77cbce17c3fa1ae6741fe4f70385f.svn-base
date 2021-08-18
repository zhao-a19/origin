/*******************************************************************************************
*文件:  FCTcpSingle.h
*描述:  TCP单向模块
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_TCP_SINGLE_H__
#define __FC_TCP_SINGLE_H__

#include "FCSingle.h"

class CTCPSINGLE : public CSINGLE
{
public:
    CTCPSINGLE();
    ~CTCPSINGLE();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
protected:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
};

#endif
