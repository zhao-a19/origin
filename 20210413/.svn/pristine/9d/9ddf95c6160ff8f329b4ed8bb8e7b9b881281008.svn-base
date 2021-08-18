#include "FCRTP.h"

CRTP::CRTP()
{
}

CRTP::~CRTP()
{
}

bool CRTP::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
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

bool CRTP::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0)
    {
        return true;
    }

    //RTP头部为16字节
    if (slen - hdflag < 16)
    {
        printf("packet too short[%d], it should be more than 16\n", slen - hdflag);
        return false;
    }

    return ((sdata[hdflag] & 1<<7) && (!(sdata[hdflag] & 1<<6)));
}

bool CRTP::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0)
    {
        return true;
    }

    //RTP头部为16字节
    if (slen - hdflag < 16)
    {
        printf("packet too short[%d], it should be more than 16\n", slen - hdflag);
        return false;
    }

    return ((sdata[hdflag] & 1<<7) && (!(sdata[hdflag] & 1<<6)));
}
