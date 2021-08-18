#include "FCRECP.h"

CRECP::CRECP()
{
}

CRECP::~CRECP()
{
}

bool CRECP::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
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

bool CRECP::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0)
    {
        return true;
    }

    //RECP头部为73字节
    if (slen - hdflag < 73)
    {
        printf("pack too short [%d],it should be more than RECP header length[73]\n", slen - hdflag);
        return false;
    }

    return ((sdata[hdflag] == 0x01) || (sdata[hdflag] == 0x02) || (sdata[hdflag] == 0x04) || (sdata[hdflag] == 0x08));
}

bool CRECP::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0)
    {
        return true;
    }

    //RECP头部为73字节
    if (slen - hdflag < 73)
    {
        printf("pack too short [%d],it should be more than RECP header length[73]\n", slen - hdflag);
        return false;
    }

    return ((sdata[hdflag] == 0x01) || (sdata[hdflag] == 0x02) || (sdata[hdflag] == 0x04) || (sdata[hdflag] == 0x08));
}
