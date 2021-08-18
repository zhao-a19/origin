#include "FCPDXP_TCP.h"

CPDXP_TCP::CPDXP_TCP()
{
}

CPDXP_TCP::~CPDXP_TCP()
{
}

bool CPDXP_TCP::DoMsg(unsigned char *sdata, int slen, char *cherror, int *pktchange, int bFromSrc)
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

bool CPDXP_TCP::DoSrcMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0)
    {
        return true;
    }

    return (sdata[hdflag] == 0x7E);
}

bool CPDXP_TCP::DoDstMsg(unsigned char *sdata, int slen, char *cherror)
{
    int hdflag = GetHeadLen(sdata);
    if (slen - hdflag <= 0)
    {
        return true;
    }

    return (sdata[hdflag] == 0x7E);
}
