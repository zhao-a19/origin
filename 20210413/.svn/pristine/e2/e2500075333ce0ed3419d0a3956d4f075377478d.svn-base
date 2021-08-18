/*******************************************************************************************
*文件:  FCIcmpv6Single.h
*描述:  ICMP模块
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_ICMPV6_SINGLE_H__
#define __FC_ICMPV6_SINGLE_H__

#include "FCSingle.h"

class CICMPV6SINGLE : public CSINGLE
{
public:
    CICMPV6SINGLE(void);
    virtual ~CICMPV6SINGLE(void);
public:
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    bool AnalyseCmdRule(char *chcmd, char *chpara, char *cherror);
};

#endif
