#include "FCPDXP_UDP.h"

CPDXP_UDP::CPDXP_UDP()
{
}

CPDXP_UDP::~CPDXP_UDP()
{
}

bool CPDXP_UDP::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
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

bool CPDXP_UDP::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0)
    {
        return true;
    }

    //头部为32字节
    if (slen - hdflag < 32)
    {
        printf("pack too short [%d],it should be more than header length[32]\n", slen - hdflag);
        return false;
    }

    char ver = sdata[hdflag];
    if ((ver & 1<<7) && (!(ver & 1<<6)))
    {
        if ((sdata[hdflag+20] == 0) && (sdata[hdflag+21] == 0) && (sdata[hdflag+22] == 0) && (sdata[hdflag+23] == 0))
        {
            return true;
        }
        else
        {
            printf("PDXP_UDP协议保留字段不为0\n");
        }
    }

    return false;
}

bool CPDXP_UDP::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0)
    {
        return true;
    }

    //头部为32字节
    if (slen - hdflag < 32)
    {
        printf("pack too short [%d],it should be more than header length[32]\n", slen - hdflag);
        return false;
    }

    char ver = sdata[hdflag];
    if ((ver & 1<<7) && (!(ver & 1<<6)))
    {
        if ((sdata[hdflag+20] == 0) && (sdata[hdflag+21] == 0) && (sdata[hdflag+22] == 0) && (sdata[hdflag+23] == 0))
        {
            return true;
        }
        else
        {
            printf("PDXP_UDP协议保留字段不为0\n");
        }
    }

    return false;
}
