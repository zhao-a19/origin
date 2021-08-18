/*******************************************************************************************
*文件:  FCPDXP_TCP.h
*描述:  PDXP_TCP模块 包数据交换协议 (航天 军队定制模块)
*作者:  王君雷
*日期:  2016-11-07
*修改:
*******************************************************************************************/
#ifndef __FC_PDXP_TCP_H__
#define __FC_PDXP_TCP_H__

#include "FCSingle.h"

class CPDXP_TCP : public CSINGLE
{
public:
    CPDXP_TCP();
    ~CPDXP_TCP();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
private:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
private:
};

#endif
