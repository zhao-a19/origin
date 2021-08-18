/*******************************************************************************************
*文件:  FCRTP.h
*描述:  RTP模块 实时传输协议
*作者:  王君雷
*日期:  2016-11-07
*修改:
*******************************************************************************************/
#ifndef __FC_RTP_H__
#define __FC_RTP_H__

#include "FCSingle.h"

class CRTP : public CSINGLE
{
public:
    CRTP();
    ~CRTP();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
private:
};

#endif
