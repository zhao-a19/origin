/*******************************************************************************************
*文件:  FCDBSync.h
*描述:  DBSYNC模块
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_DBSYNC_H__
#define __FC_DBSYNC_H__

#include "FCSingle.h"

class CDBSYNCSINGLE : public CSINGLE
{
public:
    CDBSYNCSINGLE(void);
    ~CDBSYNCSINGLE(void);
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);

protected:
    unsigned char dbsyncflag[7];
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange);
    bool DecodeRequest(unsigned char *sdata, int slen, char *cherror, int *pktchange);
};

#endif
