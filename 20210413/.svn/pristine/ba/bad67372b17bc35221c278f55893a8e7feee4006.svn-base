/*******************************************************************************************
*文件:  FC4BytesSingle.h
*描述:  4bytes模块
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#ifndef __FC_4BYTES_SINGLE_H__
#define __FC_4BYTES_SINGLE_H__

#include "FCSingle.h"

class C4BYTESSINGLE : public CSINGLE
{
public:
    C4BYTESSINGLE();
    ~C4BYTESSINGLE();
    bool DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc);
protected:
    bool DoSrcMsg(unsigned char *sdata, int slen, char *cherror);
    bool DoDstMsg(unsigned char *sdata, int slen, char *cherror);
};

#endif
