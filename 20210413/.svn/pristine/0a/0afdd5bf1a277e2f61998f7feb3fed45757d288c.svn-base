/*******************************************************************************************
*文件:  FCWINCCSingle.h
*描述:  WINCC模块
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_WINCC_H__
#define __FC_WINCC_H__

#include "FCSingle.h"

class CWINCCSINGLE : public CSINGLE
{
public:
    CWINCCSINGLE();
    ~CWINCCSINGLE();
public:
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
    bool FilterCode(char *codeid);
};

#endif
