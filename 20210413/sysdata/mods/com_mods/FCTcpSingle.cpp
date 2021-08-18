/*******************************************************************************************
*文件:  FCTcpSingle.cpp
*描述:  TCP单向模块
*作者:  王君雷
*日期:  2016-03
*修改:
*       可以记录SYN和FIN日志                                  ------> 2019-12-16
*******************************************************************************************/
#include "FCTcpSingle.h"

CTCPSINGLE::CTCPSINGLE()
{
}

CTCPSINGLE::~CTCPSINGLE()
{
}

bool CTCPSINGLE::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc) {
        return DoSrcMsg(sdata, slen, cherror);
    } else {
        return DoDstMsg(sdata, slen, cherror);
    }
}

bool CTCPSINGLE::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    if (IsSYN(sdata)) {
        RecordCallLog(sdata, "", "", "SYN", true);
    } else if (IsFIN(sdata)) {
        RecordCallLog(sdata, "", "", "FIN", true);
    }
    return true;
}

bool CTCPSINGLE::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdlen = GetHeadLen(sdata);
    int datalen = slen - hdlen;

    if (datalen <= 0) {
        if (IsFIN(sdata)) {
            RecordCallLog(sdata, "", "", "FIN", true);
        }
        return true;
    }

    //字节数>0的不允许通过
    RecordCallLog(sdata, "", "", TCPSINGLE_TRY_PASS, false);
    return false;
}
