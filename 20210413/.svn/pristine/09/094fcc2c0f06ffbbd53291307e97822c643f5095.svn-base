/*******************************************************************************************
*文件:  FCRECP.h
*描述:  RECP模块 可靠交换控制协议 (航天 军队定制模块)
*作者:  王君雷
*日期:  2016-11-07
*修改:
*******************************************************************************************/
#ifndef __FC_RECP_H__
#define __FC_RECP_H__

#include "FCSingle.h"

class CRECP : public CSINGLE
{
public:
    CRECP();
    ~CRECP();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
private:
};

#endif
