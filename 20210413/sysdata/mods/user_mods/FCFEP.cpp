#include "FCFEP.h"

CFEP::CFEP()
{
}

CFEP::~CFEP()
{
}

bool CFEP::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
{
    if (bFromSrc == 1)
    {
        return DoSrcMsg(sdata, slen, cherror);
    }
    else
    {
        return DoDstMsg(sdata, slen, cherror);
    }
}

bool CFEP::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0)
    {
        return true;
    }

    //01 请求包
    //02 请求应答包
    //03 结束确认包
    //04 数据包
    if (sdata[hdflag]==0x01 || sdata[hdflag]==0x04)
    {
        return true;
    }
    else
    {
        printf("DoSrcMsg sdata[hdflag] = %d, return false\n", sdata[hdflag]);
    }

    return false;
}

bool CFEP::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0)
    {
        return true;
    }

    //01 请求包
    //02 请求应答包
    //03 结束确认包
    //04 数据包
    if (sdata[hdflag]==0x02 || sdata[hdflag]==0x03)
    {
        return true;
    }
    else
    {
        printf("DoDstMsg sdata[hdflag] = %d, return false\n", sdata[hdflag]);
    }

    return false;
}
