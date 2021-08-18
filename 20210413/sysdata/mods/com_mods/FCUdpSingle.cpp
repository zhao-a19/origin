/*******************************************************************************************
*文件:  FCUdpSingle.cpp
*描述:  UDP单向模块
*作者:  王君雷
*日期:  2016-03
*修改:
*******************************************************************************************/
#include "FCUdpSingle.h"

CUDPSINGLE::CUDPSINGLE()
{
}

CUDPSINGLE::~CUDPSINGLE()
{
}

bool CUDPSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}

bool CUDPSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    return true;
}

bool CUDPSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    int datalen = slen - hdlen;

    if (datalen <= 0) {
        return true;
    }

    //字节数>0的不允许通过
    RecordCallLog(sdata, "", "", UDPSINGLE_TRY_PASS, false);
    return false;
}
