/*******************************************************************************************
*文件:  FCFEP.h
*描述:  FEP模块 文件交换协议 (航天 军队定制模块)
*作者:  王君雷
*日期:  2016-11-07
*修改:
*******************************************************************************************/
#ifndef __FC_FEP_H__
#define __FC_FEP_H__

#include "FCSingle.h"

class CFEP : public CSINGLE
{
public:
    CFEP();
    ~CFEP();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
private:
};

#endif
